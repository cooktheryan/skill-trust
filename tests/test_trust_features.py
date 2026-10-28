"""Tests for Nono-compatible trust policy and keyed attestation features."""

import json
from pathlib import Path

from click.testing import CliRunner
import pytest

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
from skill_trust.scan import scan_project
from skill_trust.signer import SkillSigner
from skill_trust.verifier import SkillVerifier


def _make_key(tmp_path: Path) -> tuple[Path, Path]:
    return generate_key_pair(tmp_path / "signing-key.pem")


def test_keyed_skill_round_trip(tmp_skill: Path, tmp_path: Path) -> None:
    private_key, public_key = _make_key(tmp_path)
    signer = SkillSigner(private_key=private_key)
    signed = signer.sign_skill(tmp_skill)

    result = SkillVerifier().verify_skill(tmp_skill, signed.bundle_path)
    trusted_key_id = key_id(load_public_key(public_key))

    assert result.verified
    assert result.identity == f"key:{trusted_key_id}"
    assert result.claims["key_id"] == trusted_key_id
    assert result.public_key == encode_public_key(load_public_key(public_key))


def test_keyed_signer_rejects_identity_token(tmp_path: Path) -> None:
    private_key, _ = _make_key(tmp_path)

    with pytest.raises(ValueError, match="cannot use an OIDC identity token"):
        SkillSigner(private_key=private_key, identity_token="oidc-token")


def test_keyed_file_round_trip(tmp_path: Path) -> None:
    private_key, public_key = _make_key(tmp_path)
    target = tmp_path / "instructions.txt"
    target.write_text("trusted content\n")

    bundle_path = SkillSigner(private_key=private_key).sign_file(target)
    result = SkillVerifier().verify_file(target, bundle_path)

    assert result.verified
    assert result.claims["key_id"] == key_id(load_public_key(public_key))
    assert result.public_key == encode_public_key(load_public_key(public_key))


def test_keyed_file_tamper_fails(tmp_path: Path) -> None:
    private_key, _ = _make_key(tmp_path)
    target = tmp_path / "instructions.txt"
    target.write_text("trusted content\n")
    bundle_path = SkillSigner(private_key=private_key).sign_file(target)

    target.write_text("tampered content\n")
    result = SkillVerifier().verify_file(target, bundle_path)
    assert not result.verified
    assert result.error == "File signature verification failed"


def test_signed_policy_requires_trusted_anchor(tmp_path: Path) -> None:
    private_key, public_key = _make_key(tmp_path)
    other_private, other_public = _make_key(tmp_path.with_name("other-key.pem"))
    policy_path = tmp_path / "trust-policy.json"
    policy_path.write_text(json.dumps({"includes": ["*.txt"], "publishers": []}))

    signature_path = write_policy_signature(policy_path, private_key)
    valid, key_identifier = verify_policy_signature(
        policy_path,
        signature_path,
        trusted_public_keys=[encode_public_key(load_public_key(public_key))],
    )
    assert valid
    assert key_identifier == key_id(load_public_key(public_key))

    untrusted, reason = verify_policy_signature(
        policy_path,
        signature_path,
        trusted_public_keys=[encode_public_key(load_public_key(other_public))],
    )
    assert not untrusted
    assert reason == "Policy signer is not a trusted anchor"

    policy_path.write_text(json.dumps({"includes": ["*.py"], "publishers": []}))
    tampered, reason = verify_policy_signature(
        policy_path,
        signature_path,
        trusted_public_keys=[encode_public_key(load_public_key(public_key))],
    )
    assert not tampered
    assert reason == "Policy signature is invalid"
    assert other_private.exists()


def test_github_publisher_claim_matching() -> None:
    policy = TrustPolicy.from_dict({
        "publishers": [{
            "issuer": "https://token.actions.githubusercontent.com",
            "repository": "cooktheryan/*",
            "workflow": ".github/workflows/sign.yml",
            "ref_pattern": "refs/heads/main",
        }]
    })
    claims = {
        "github_workflow_repository": "cooktheryan/skill-trust",
        "github_workflow_name": ".github/workflows/sign.yml",
        "github_workflow_ref": "refs/heads/main",
    }
    assert policy.is_publisher_trusted(
        identity="cooktheryan",
        issuer="https://token.actions.githubusercontent.com",
        claims=claims,
    )
    claims["github_workflow_ref"] = "refs/heads/evil"
    assert not policy.is_publisher_trusted(
        identity="cooktheryan",
        issuer="https://token.actions.githubusercontent.com",
        claims=claims,
    )


def test_scan_blocks_digest_even_in_warn_mode(tmp_path: Path) -> None:
    import hashlib

    target = tmp_path / "instructions.txt"
    target.write_text("malicious content\n")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    policy = TrustPolicy.from_dict({
        "includes": ["*.txt"],
        "publishers": [],
        "blocklist": {"digests": [{"sha256": digest}]},
        "enforcement": "warn",
    })
    report = scan_project(tmp_path, policy, SkillVerifier())
    assert not report.allowed
    assert report.results[0].status == "blocked"


def test_scan_blocks_publisher_even_in_warn_mode(tmp_path: Path) -> None:
    private_key, public_key = _make_key(tmp_path)
    target = tmp_path / "instructions.txt"
    target.write_text("signed by blocked publisher\n")
    bundle_path = SkillSigner(private_key=private_key).sign_file(target)
    encoded_public_key = encode_public_key(load_public_key(public_key))
    policy = TrustPolicy.from_dict({
        "includes": ["*.txt"],
        "publishers": [
            {
                "key_id": key_id(load_public_key(public_key)),
                "public_key": encoded_public_key,
            }
        ],
        "blocklist": {
            "publishers": [{"key_id": key_id(load_public_key(public_key))}]
        },
        "enforcement": "warn",
    })

    report = scan_project(tmp_path, policy, SkillVerifier())
    assert report.results[0].verification.verified
    assert report.results[0].status == "blocked"
    assert not report.allowed
    assert bundle_path.exists()


def test_scan_warn_allows_unsigned_with_warning(tmp_path: Path) -> None:
    (tmp_path / "instructions.txt").write_text("unsigned\n")
    policy = TrustPolicy.from_dict({
        "includes": ["*.txt"],
        "publishers": [],
        "enforcement": "warn",
    })
    report = scan_project(tmp_path, policy, SkillVerifier())
    assert report.allowed
    assert report.results[0].status == "unsigned"
    assert report.warnings


def test_policy_composition_is_strictest_wins() -> None:
    user = TrustPolicy.from_dict({
        "includes": ["user.txt"],
        "publishers": [{"identity": "user@example.com"}],
        "enforcement": "deny",
    })
    project = TrustPolicy.from_dict({
        "includes": ["project.txt"],
        "publishers": [{"identity": "project@example.com"}],
        "enforcement": "audit",
    })
    composed = user.compose(project)
    assert composed.enforcement == "deny"
    assert composed.includes == ["user.txt", "project.txt"]
    assert composed.is_identity_trusted("user@example.com")
    assert composed.is_identity_trusted("project@example.com")


def test_cli_keyed_trust_workflow(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as workspace:
        result = runner.invoke(cli, ["trust", "keygen", "--key", "key.pem"])
        assert result.exit_code == 0, result.output

        Path(workspace, "instructions.txt").write_text("trusted content\n")
        result = runner.invoke(
            cli,
            ["trust", "init", "--include", "*.txt", "--key", "key.pem"],
        )
        assert result.exit_code == 0, result.output

        result = runner.invoke(
            cli,
            ["trust", "sign-policy", "--policy", "trust-policy.json", "--key", "key.pem"],
        )
        assert result.exit_code == 0, result.output

        result = runner.invoke(
            cli,
            ["trust", "sign", "--all", "--policy", "trust-policy.json", "--key", "key.pem"],
        )
        assert result.exit_code == 0, result.output

        result = runner.invoke(
            cli,
            [
                "trust", "verify", "--all",
                "--policy", "trust-policy.json",
                "--trust-anchor", "key.pem.pub",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "verified" in result.output

        result = runner.invoke(cli, ["trust", "export-key", "--key", "key.pem"])
        assert result.exit_code == 0, result.output
        assert result.output.strip() == encode_public_key(
            load_public_key(Path(workspace, "key.pem.pub"))
        )


def test_cli_init_creates_rhtas_oidc_policy(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as workspace:
        result = runner.invoke(
            cli,
            ["trust", "keygen", "--key", "policy-key.pem"],
        )
        assert result.exit_code == 0, result.output

        result = runner.invoke(
            cli,
            [
                "trust", "init",
                "--include", "SKILL.md",
                "--include", "src/**/*.py",
                "--key", "policy-key.pem",
                "--publisher-name", "rhtas-keycloak",
                "--oidc-issuer", "https://oidc.example.com/realms/rhtas",
                "--identity", "jdoe@example.com",
                "--repository", "cooktheryan/skill-trust",
                "--workflow", ".github/workflows/sign.yml",
                "--ref-pattern", "refs/heads/main",
            ],
        )
        assert result.exit_code == 0, result.output

        policy = json.loads(Path(workspace, "trust-policy.json").read_text())
        assert policy["publishers"] == [{
            "name": "rhtas-keycloak",
            "issuer": "https://oidc.example.com/realms/rhtas",
            "identity": "jdoe@example.com",
            "repository": "cooktheryan/skill-trust",
            "workflow": ".github/workflows/sign.yml",
            "ref_pattern": "refs/heads/main",
        }]


def test_cli_init_requires_issuer_for_oidc_constraints(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        runner.invoke(cli, ["trust", "keygen", "--key", "policy-key.pem"])
        result = runner.invoke(
            cli,
            [
                "trust", "init",
                "--include", "*.txt",
                "--key", "policy-key.pem",
                "--identity", "jdoe@example.com",
            ],
        )
        assert result.exit_code != 0
        assert "OIDC publisher constraints require --oidc-issuer" in result.output
