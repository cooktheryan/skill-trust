"""Nono-compatible trust policy and file attestation commands."""

from __future__ import annotations

import sys
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
import click
from rich.console import Console
from rich.table import Table

from skill_trust.cli import cli
from skill_trust.keyed import (
    encode_public_key,
    generate_key_pair,
    key_id,
    load_public_key,
    verify_policy_signature,
    write_policy_signature,
)
from skill_trust.policy import TrustPolicy
from skill_trust.scan import ScanReport, scan_project
from skill_trust.signer import SkillSigner
from skill_trust.verifier import SkillVerifier

console = Console()
DEFAULT_KEY = Path.home() / ".config" / "skill-trust" / "default.pem"


@cli.group()
def trust() -> None:
    """Manage signed trust policies and file attestations."""


@trust.command("keygen")
@click.option("--key", type=click.Path(path_type=Path), default=DEFAULT_KEY)
@click.option("--force", is_flag=True)
def keygen(key: Path, force: bool) -> None:
    """Generate an ECDSA P-256 key pair."""
    if key.exists() and not force:
        raise click.ClickException(f"Key already exists: {key}")
    private_path, public_path = generate_key_pair(key)
    console.print(f"[green]✓[/green] Private key: {private_path}")
    console.print(f"[green]✓[/green] Public key:  {public_path}")


@trust.command("init")
@click.option("--include", "includes", multiple=True, required=True)
@click.option("--key", type=click.Path(exists=True, path_type=Path), default=DEFAULT_KEY)
@click.option("--publisher-name", default=None)
@click.option("--oidc-issuer", default=None)
@click.option("--identity", default=None)
@click.option("--repository", default=None)
@click.option("--workflow", default=None)
@click.option("--ref-pattern", default=None)
@click.option("--force", is_flag=True)
def init(
    includes: tuple[str, ...],
    key: Path,
    publisher_name: str,
    oidc_issuer: str | None,
    identity: str | None,
    repository: str | None,
    workflow: str | None,
    ref_pattern: str | None,
    force: bool,
) -> None:
    """Create a policy rooted at a keyed or OIDC publisher."""
    policy_path = Path("trust-policy.json")
    if policy_path.exists() and not force:
        raise click.ClickException(f"Policy already exists: {policy_path}")

    if oidc_issuer:
        publisher = {
            "name": publisher_name or "rhtas-publisher",
            "issuer": oidc_issuer,
        }
        for field, value in (
            ("identity", identity),
            ("repository", repository),
            ("workflow", workflow),
            ("ref_pattern", ref_pattern),
        ):
            if value is not None:
                publisher[field] = value
    else:
        oidc_fields = (identity, repository, workflow, ref_pattern)
        if any(field is not None for field in oidc_fields):
            raise click.ClickException(
                "OIDC publisher constraints require --oidc-issuer"
            )
        public_key = load_public_key(key.with_name(f"{key.name}.pub"))
        publisher = {
            "name": publisher_name or "local-dev",
            "key_id": key_id(public_key),
            "public_key": encode_public_key(public_key),
        }

    policy = TrustPolicy.from_dict({
        "includes": list(includes),
        "publishers": [publisher],
        "enforcement": "deny",
    })
    policy_path.write_text(json.dumps(policy.to_dict(), indent=2) + "\n")
    console.print(f"[green]✓[/green] Created {policy_path}")
    console.print("Next: skill-trust trust sign-policy --key <private-key>")


@trust.command("sign-policy")
@click.option("--policy", type=click.Path(exists=True, path_type=Path), default=Path("trust-policy.json"))
@click.option("--key", type=click.Path(exists=True, path_type=Path), default=DEFAULT_KEY)
@click.option("--output", type=click.Path(path_type=Path), default=None)
def sign_policy(policy: Path, key: Path, output: Path | None) -> None:
    """Sign a trust policy with a keyed publisher."""
    output = write_policy_signature(policy, key, output)
    console.print(f"[green]✓[/green] Signed policy: {output}")


@trust.command("sign")
@click.argument("paths", type=click.Path(path_type=Path), nargs=-1)
@click.option("--all", "sign_all", is_flag=True)
@click.option("--key", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--identity-token", type=str, default=None)
@click.option("--policy", type=click.Path(exists=True, path_type=Path), default=Path("trust-policy.json"))
@click.option("--staging", is_flag=True)
@click.option("--tuf-url", type=str, default=None)
@click.option("--tuf-root", type=click.Path(exists=True, path_type=Path), default=None)
def sign(
    paths: tuple[Path, ...],
    sign_all: bool,
    key: Path | None,
    identity_token: str | None,
    policy: Path,
    staging: bool,
    tuf_url: str | None,
    tuf_root: Path | None,
) -> None:
    """Sign files explicitly or all files matching a policy."""
    if sign_all:
        trust_policy = TrustPolicy.from_file(policy)
        targets = _policy_files(Path("."), trust_policy)
    else:
        targets = [Path(path) for path in paths]
    if not targets:
        raise click.ClickException("No files matched the policy")

    signer = SkillSigner(
        identity_token=identity_token,
        staging=staging,
        tuf_url=tuf_url,
        tuf_root=tuf_root,
        private_key=key,
    )
    for target in targets:
        bundle = signer.sign_file(target)
        console.print(f"[green]✓[/green] {target} -> {bundle.name}")


@trust.command("verify")
@click.argument("paths", type=click.Path(path_type=Path), nargs=-1)
@click.option("--all", "verify_all", is_flag=True)
@click.option("--policy", type=click.Path(exists=True, path_type=Path), default=Path("trust-policy.json"))
@click.option("--user-policy", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--trust-anchor", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--staging", is_flag=True)
@click.option("--tuf-url", type=str, default=None)
@click.option("--tuf-root", type=click.Path(exists=True, path_type=Path), default=None)
def verify(
    paths: tuple[Path, ...],
    verify_all: bool,
    policy: Path,
    user_policy: Path | None,
    trust_anchor: Path | None,
    staging: bool,
    tuf_url: str | None,
    tuf_root: Path | None,
) -> None:
    """Verify files against a signed, anchored trust policy."""
    effective_policy, trusted_keys = _load_verified_policy(policy, user_policy, trust_anchor)
    verifier = SkillVerifier(staging=staging, tuf_url=tuf_url, tuf_root=tuf_root)
    root = Path(".").resolve()
    if verify_all:
        report = scan_project(root, effective_policy, verifier)
        _print_report(report)
        if not report.allowed:
            sys.exit(1)
        return

    if not paths:
        raise click.ClickException("Provide files or --all")
    selected = set(paths)
    report = scan_project(root, effective_policy, verifier)
    selected_report = ScanReport(
        root=report.root,
        results=tuple(result for result in report.results if result.path in selected),
        warnings=report.warnings,
        enforcement=report.enforcement,
    )
    _print_report(selected_report)
    if not selected_report.allowed:
        sys.exit(1)


@trust.command("list")
@click.option("--policy", type=click.Path(exists=True, path_type=Path), default=Path("trust-policy.json"))
@click.option("--user-policy", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--trust-anchor", type=click.Path(exists=True, path_type=Path), default=None)
def list_files(policy: Path, user_policy: Path | None, trust_anchor: Path | None) -> None:
    """List policy-covered files and their trust status."""
    effective_policy, _ = _load_verified_policy(policy, user_policy, trust_anchor)
    verifier = SkillVerifier()
    report = scan_project(Path(".").resolve(), effective_policy, verifier)
    _print_report(report)


@trust.command("export-key")
@click.option("--key", type=click.Path(exists=True, path_type=Path), default=DEFAULT_KEY)
@click.option("--pem", is_flag=True)
def export_key(key: Path, pem: bool) -> None:
    """Export a public key as base64 DER or PEM."""
    public_key = load_public_key(key.with_name(f"{key.name}.pub"))
    if pem:
        click.echo(
            public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    else:
        click.echo(encode_public_key(public_key))


def _policy_files(root: Path, policy: TrustPolicy) -> list[Path]:
    from skill_trust.scan import _is_skipped

    files = []
    for path in sorted(root.resolve().rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root.resolve()).as_posix()
        if _is_skipped(relative):
            continue
        if policy.matches_path(relative):
            files.append(path)
    return files


def _load_verified_policy(
    policy_path: Path,
    user_policy_path: Path | None,
    trust_anchor: Path | None,
) -> tuple[TrustPolicy, list[str]]:
    signature_path = policy_path.with_name(f"{policy_path.name}.keyed.json")
    if not signature_path.exists():
        raise click.ClickException(f"Signed policy not found: {signature_path}")

    project_policy = TrustPolicy.from_file(policy_path)
    user_policy = TrustPolicy.from_file(user_policy_path) if user_policy_path else None
    trusted_keys: list[str] = []
    if trust_anchor:
        trusted_keys.append(encode_public_key(load_public_key(trust_anchor)))
    if user_policy:
        trusted_keys.extend(
            publisher.public_key
            for publisher in user_policy.publishers
            if publisher.public_key
        )
    if not trusted_keys:
        raise click.ClickException(
            "A signed project policy requires --trust-anchor or --user-policy"
        )

    valid, reason = verify_policy_signature(
        policy_path, signature_path, trusted_public_keys=trusted_keys
    )
    if not valid:
        raise click.ClickException(reason or "Policy signature is invalid")
    if user_policy:
        return user_policy.compose(project_policy), trusted_keys
    return project_policy, trusted_keys


def _print_report(report) -> None:
    table = Table(title="Trust Scan")
    table.add_column("File")
    table.add_column("Status")
    table.add_column("Digest")
    table.add_column("Reason")
    for result in report.results:
        table.add_row(
            result.relative_path,
            result.status,
            result.digest[:12],
            result.reason or "",
        )
    console.print(table)
    for warning in report.warnings:
        console.print(f"[yellow]![/yellow] {warning}")
