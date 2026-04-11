"""skill-trust CLI."""

import click

from skill_trust import __version__


@click.group()
@click.version_option(version=__version__, prog_name="skill-trust")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Keyless signing and verification for AI agent skills using Sigstore."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
