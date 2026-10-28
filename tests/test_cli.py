"""Tests for the skill-trust command-line interface."""

from click.testing import CliRunner

from skill_trust.cli import cli


def test_cli_registers_commands() -> None:
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "inspect" in result.output
    assert "sign" in result.output
    assert "verify" in result.output


def test_trust_sign_accepts_rhtas_identity_token() -> None:
    result = CliRunner().invoke(cli, ["trust", "sign", "--help"])

    assert result.exit_code == 0
    assert "--identity-token" in result.output
