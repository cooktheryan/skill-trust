"""Tests for custom Sigstore-compatible trust configurations."""

from pathlib import Path
from types import SimpleNamespace

import pytest

import skill_trust.signer as signer_module
import skill_trust.verifier as verifier_module
from skill_trust.signer import SkillSigner
from skill_trust.verifier import SkillVerifier


def test_signer_uses_custom_tuf_repository(monkeypatch, tmp_path: Path) -> None:
    calls = {}
    trust_root = object()
    trust_config = SimpleNamespace(trusted_root=trust_root)

    def from_tuf(url, offline=False, bootstrap_root=None):
        calls["url"] = url
        calls["offline"] = offline
        calls["bootstrap_root"] = bootstrap_root
        return trust_config

    monkeypatch.setattr(
        signer_module.ClientTrustConfig,
        "from_tuf",
        classmethod(lambda cls, *args, **kwargs: from_tuf(*args, **kwargs)),
    )
    monkeypatch.setattr(
        signer_module.SigningContext,
        "from_trust_config",
        classmethod(lambda cls, config: object()),
    )

    bootstrap_root = tmp_path / "trusted_root.json"
    bootstrap_root.write_text("{}")
    SkillSigner(
        tuf_url="https://rhtas.example.com/tuf",
        tuf_root=bootstrap_root,
    )

    assert calls == {
        "url": "https://rhtas.example.com/tuf",
        "offline": False,
        "bootstrap_root": bootstrap_root,
    }


def test_verifier_uses_custom_tuf_repository(monkeypatch, tmp_path: Path) -> None:
    calls = {}
    trust_root = object()
    trust_config = SimpleNamespace(trusted_root=trust_root)

    def from_tuf(url, offline=False, bootstrap_root=None):
        calls["url"] = url
        calls["bootstrap_root"] = bootstrap_root
        return trust_config

    def verifier(trusted_root):
        calls["trusted_root"] = trusted_root
        return object()

    monkeypatch.setattr(
        verifier_module.ClientTrustConfig,
        "from_tuf",
        classmethod(lambda cls, *args, **kwargs: from_tuf(*args, **kwargs)),
    )
    monkeypatch.setattr(verifier_module, "Verifier", verifier)

    bootstrap_root = tmp_path / "trusted_root.json"
    bootstrap_root.write_text("{}")
    SkillVerifier(
        tuf_url="https://rhtas.example.com/tuf",
        tuf_root=bootstrap_root,
    )

    assert calls == {
        "url": "https://rhtas.example.com/tuf",
        "bootstrap_root": bootstrap_root,
        "trusted_root": trust_root,
    }


@pytest.mark.parametrize("cls", [SkillSigner, SkillVerifier])
def test_custom_trust_options_are_mutually_exclusive(cls) -> None:
    with pytest.raises(ValueError, match="cannot be combined"):
        cls(staging=True, tuf_url="https://rhtas.example.com/tuf")


@pytest.mark.parametrize("cls", [SkillSigner, SkillVerifier])
def test_bootstrap_root_requires_tuf_url(cls, tmp_path: Path) -> None:
    bootstrap_root = tmp_path / "trusted_root.json"
    bootstrap_root.write_text("{}")

    with pytest.raises(ValueError, match="requires a TUF URL"):
        cls(tuf_root=bootstrap_root)
