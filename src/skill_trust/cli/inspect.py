"""skill-trust inspect command."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from skill_trust.cli import cli

console = Console()


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def inspect(ctx: click.Context, path: Path) -> None:
    """Inspect signing metadata for a skill or plugin."""
    if (path / "skills").is_dir():
        # Plugin root
        bundles_dir = path / ".skill-trust" / "skills"
        if not bundles_dir.is_dir():
            console.print("[yellow]No .skill-trust/ directory found.[/yellow]")
            return

        for bundle_file in sorted(bundles_dir.glob("*.sigstore.json")):
            _inspect_bundle(bundle_file)
            console.print()
    else:
        # Single skill
        bundle_dir = path.parent.parent / ".skill-trust" / "skills"
        bundle_path = bundle_dir / f"{path.name}.sigstore.json"

        if not bundle_path.exists():
            console.print(f"[yellow]No signature found for {path.name}[/yellow]")
            return

        _inspect_bundle(bundle_path)


def _inspect_bundle(bundle_path: Path) -> None:
    """Display metadata for a single sigstore bundle."""
    from sigstore.models import Bundle

    from skill_trust._identity import extract_identity

    try:
        bundle = Bundle.from_json(bundle_path.read_text())
    except (OSError, UnicodeError, ValueError, TypeError) as e:
        console.print(f"[red]Error:[/red] Invalid bundle format in {bundle_path.name}: {e}")
        return

    cert = bundle.signing_certificate
    if cert is None:
        console.print(f"[red]Error:[/red] No signing certificate in {bundle_path.name}")
        return

    try:
        identity_info = extract_identity(cert)
    except (ValueError, TypeError, UnicodeError) as e:
        console.print(f"[red]Error:[/red] Invalid signing certificate in {bundle_path.name}: {e}")
        return

    skill_name = bundle_path.stem.replace(".sigstore", "")

    table = Table(title=f"Signature: {skill_name}", show_header=False, pad_edge=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")

    table.add_row("Bundle", str(bundle_path.name))
    table.add_row("Identity", Text(identity_info.get("identity") or "unknown"))
    table.add_row("Issuer", Text(identity_info.get("issuer") or "unknown"))
    table.add_row("Not Before", str(cert.not_valid_before_utc))
    table.add_row("Not After", str(cert.not_valid_after_utc))

    if identity_info.get("github_workflow_repository"):
        table.add_row("Repository", Text(identity_info["github_workflow_repository"]))
    if identity_info.get("github_workflow_name"):
        table.add_row("Workflow", Text(identity_info["github_workflow_name"]))
    if identity_info.get("github_workflow_ref"):
        table.add_row("Ref", Text(identity_info["github_workflow_ref"]))

    log_entry = bundle.log_entry
    if log_entry:
        table.add_row("Rekor Log Index", str(log_entry.log_index))

    console.print(table)
