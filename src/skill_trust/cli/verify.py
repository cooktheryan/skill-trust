"""skill-trust verify command."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from skill_trust.cli import cli

console = Console()


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--identity",
    type=str,
    default=None,
    help="Expected signer identity (email or URI).",
)
@click.option(
    "--issuer",
    type=str,
    default=None,
    help="Expected OIDC issuer URL.",
)
@click.option(
    "--staging",
    is_flag=True,
    help="Use Sigstore staging infrastructure.",
)
@click.pass_context
def verify(
    ctx: click.Context,
    path: Path,
    identity: str | None,
    issuer: str | None,
    staging: bool,
) -> None:
    """Verify a signed skill directory or all skills in a plugin."""
    from skill_trust.models import IdentityConstraints
    from skill_trust.verifier import SkillVerifier

    constraints = None
    if identity or issuer:
        constraints = IdentityConstraints(identity=identity, issuer=issuer)

    verifier = SkillVerifier(identity_constraints=constraints, staging=staging)

    if (path / "skills").is_dir():
        # Plugin root — verify all skills
        console.print(f"[bold]Verifying all skills in plugin:[/bold] {path}")
        results = verifier.verify_plugin(path)

        all_ok = True
        for name, result in results.items():
            if result.verified:
                console.print(
                    f"  [green]\u2713[/green] {name} "
                    f"(signed by {result.identity or 'unknown'})"
                )
            else:
                all_ok = False
                console.print(f"  [red]\u2717[/red] {name}: {result.error}")
                for d in result.discrepancies:
                    console.print(f"    [yellow]\u2022[/yellow] {d}")

        if all_ok:
            console.print(f"\n[bold green]All {len(results)} skills verified.[/bold green]")
        else:
            console.print("\n[bold red]Verification failed.[/bold red]")
            sys.exit(1)
    else:
        # Single skill directory
        bundle_dir = path.parent.parent / ".skill-trust" / "skills"
        bundle_path = bundle_dir / f"{path.name}.sigstore.json"

        if not bundle_path.exists():
            console.print(f"[red]\u2717[/red] No signature found for {path.name}")
            console.print(f"  Expected: {bundle_path}")
            sys.exit(1)

        result = verifier.verify_skill(path, bundle_path)

        if result.verified:
            console.print(f"[green]\u2713[/green] {path.name} verified")
            console.print(f"  Signer: {result.identity or 'unknown'}")
            console.print(f"  Issuer: {result.issuer or 'unknown'}")
        else:
            console.print(f"[red]\u2717[/red] {path.name}: {result.error}")
            for d in result.discrepancies:
                console.print(f"  [yellow]\u2022[/yellow] {d}")
            sys.exit(1)
