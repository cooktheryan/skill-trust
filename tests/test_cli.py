"""Tests for the skill-trust command-line interface."""

from click.testing import CliRunner

from skill_trust.cli import cli


def test_cli_registers_commands() -> None:
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "inspect" in result.output
    assert "sign" in result.output
    assert "verify" in result.output
