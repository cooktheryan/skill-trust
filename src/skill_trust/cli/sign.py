"""skill-trust sign command."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from skill_trust.cli import cli

console = Console()


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Output directory for .sigstore.json bundles.",
)
@click.option(
    "--staging",
    is_flag=True,
    help="Use Sigstore staging infrastructure (for testing).",
)
@click.option(
    "--tuf-url",
    type=str,
    default=None,
    help="TUF repository URL for a private Sigstore-compatible service (for example, RHTAS).",
)
@click.option(
    "--tuf-root",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Pinned TUF bootstrap root for a custom trust configuration.",
)
@click.option(
    "--identity-token",
    type=str,
    default=None,
    help="Pre-obtained OIDC identity token.",
)
@click.pass_context
def sign(
    ctx: click.Context,
    path: Path,
    output: Path | None,
    staging: bool,
    identity_token: str | None,
    tuf_url: str | None,
    tuf_root: Path | None,
) -> None:
    """Sign a skill directory or all skills in a plugin."""
    from skill_trust.signer import SkillSigner

    signer = SkillSigner(
        identity_token=identity_token,
        staging=staging,
        tuf_url=tuf_url,
        tuf_root=tuf_root,
    )

    if (path / "skills").is_dir():
        # Plugin root — sign all skills
        console.print(f"[bold]Signing all skills in plugin:[/bold] {path}")
        results = signer.sign_plugin(path)
        for result in results:
            console.print(
                f"  [green]\u2713[/green] {result.manifest.skill_name} "
                f"({len(result.manifest.files)} files) -> {result.bundle_path.name}"
            )
        console.print(f"\n[bold green]Signed {len(results)} skills.[/bold green]")
    else:
        # Single skill directory
        console.print(f"[bold]Signing skill:[/bold] {path.name}")
        result = signer.sign_skill(path, output_dir=output)
        console.print(
            f"  [green]\u2713[/green] {result.manifest.skill_name} "
            f"({len(result.manifest.files)} files)"
        )
        console.print(f"  Bundle: {result.bundle_path}")
