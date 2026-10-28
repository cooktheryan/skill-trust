"""Tests for the verification gate and trust policy."""

import json
from pathlib import Path

import pytest

from skill_trust.gate import GateResult, verify_before_load
from skill_trust.policy import TrustPolicy


class TestTrustPolicy:
    def test_default_has_no_trusted_publishers(self) -> None:
        policy = TrustPolicy()
        assert not policy.is_publisher_trusted(
            identity="anyone@example.com",
            issuer="https://any.issuer.com",
        )

    def test_identity_constraint(self) -> None:
        policy = TrustPolicy.from_dict(
            {"publishers": [{"identity": "alice@example.com"}]}
        )
        assert policy.is_identity_trusted("alice@example.com")
        assert not policy.is_identity_trusted("bob@example.com")
        assert not policy.is_identity_trusted(None)

    def test_issuer_constraint(self) -> None:
        policy = TrustPolicy.from_dict(
            {"publishers": [{"issuer": "https://accounts.google.com"}]}
        )
        assert policy.is_issuer_trusted("https://accounts.google.com")
        assert not policy.is_issuer_trusted("https://evil.com")

    def test_from_file(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(json.dumps({
            "require_signature": True,
            "trusted_identities": ["dev@example.com"],
            "trusted_issuers": ["https://accounts.google.com"],
            "mode": "warn",
        }))

        policy = TrustPolicy.from_file(policy_file)
        assert policy.require_signature is True
        assert policy.is_identity_trusted("dev@example.com")
        assert policy.enforcement == "warn"

    def test_from_file_invalid_mode_raises(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "bad.json"
        policy_file.write_text(json.dumps({"mode": "yolo"}))

        with pytest.raises(ValueError, match="Invalid enforcement mode"):
            TrustPolicy.from_file(policy_file)

    def test_from_file_invalid_identities_type_raises(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "bad.json"
        policy_file.write_text(json.dumps({"trusted_identities": "not-a-list"}))

        with pytest.raises(ValueError, match="must be a list"):
            TrustPolicy.from_file(policy_file)

    def test_from_file_invalid_json_raises(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "bad.json"
        policy_file.write_text("{not valid json}")

        with pytest.raises(ValueError, match="Invalid JSON"):
            TrustPolicy.from_file(policy_file)

    def test_to_dict_round_trip(self) -> None:
        policy = TrustPolicy.from_dict({
            "require_signature": True,
            "trusted_identities": ["dev@example.com"],
            "mode": "enforce",
        })
        d = policy.to_dict()
        assert policy.is_identity_trusted("dev@example.com")
        assert d["enforcement"] == "deny"

    def test_require_signature_round_trips(self) -> None:
        policy = TrustPolicy(require_signature=False)
        assert TrustPolicy.from_dict(policy.to_dict()).require_signature is False

    def test_keyed_publisher_requires_public_key(self) -> None:
        policy = TrustPolicy.from_dict({"publishers": [{"key_id": "trusted-id"}]})
        assert not policy.is_publisher_trusted(
            identity=None,
            issuer=None,
            claims={"key_id": "trusted-id"},
            public_key="any-key",
        )

    def test_recursive_glob_includes_direct_and_nested_files(self) -> None:
        policy = TrustPolicy.from_dict({"includes": ["src/**/*.py"]})
        assert policy.matches_path("src/main.py")
        assert policy.matches_path("src/package/main.py")
        assert not policy.matches_path("tests/main.py")

    def test_recursive_glob_includes_root_files(self) -> None:
        policy = TrustPolicy.from_dict({"includes": ["**/*.py"]})
        assert policy.matches_path("main.py")
        assert policy.matches_path("package/main.py")


class TestGate:
    def test_no_signature_required_allows(self, tmp_skill: Path) -> None:
        policy = TrustPolicy(require_signature=False)
        plugin_root = tmp_skill.parent

        result = verify_before_load(tmp_skill, plugin_root, policy)
        assert result.allowed
        assert "not required" in result.reason

    def test_no_signature_enforced_blocks(self, tmp_skill: Path) -> None:
        policy = TrustPolicy(require_signature=True, enforcement="deny")
        plugin_root = tmp_skill.parent

        result = verify_before_load(tmp_skill, plugin_root, policy)
        assert result.blocked
        assert "No signature found" in result.reason

    def test_no_signature_warn_allows_with_warning(self, tmp_skill: Path) -> None:
        policy = TrustPolicy(require_signature=True, enforcement="warn")
        plugin_root = tmp_skill.parent

        result = verify_before_load(tmp_skill, plugin_root, policy)
        assert result.allowed
        assert "No signature found" in result.reason
        assert len(result.warnings) > 0
        assert "UNTRUSTED" in result.warnings[0]

    def test_gate_result_properties(self) -> None:
        r = GateResult(allowed=True, skill_name="test", reason="ok")
        assert not r.blocked

        r = GateResult(allowed=False, skill_name="test", reason="bad")
        assert r.blocked

    def test_gate_result_warnings_default_empty(self) -> None:
        r = GateResult(allowed=True, skill_name="test", reason="ok")
        assert r.warnings == []


class TestManifestSecurity:
    def test_rejects_path_traversal_in_manifest(self) -> None:
        from skill_trust.models import Manifest

        with pytest.raises(ValueError, match="traversal"):
            Manifest.from_dict({
                "version": "1.0",
                "skill_name": "evil",
                "root": "evil",
                "files": [{"path": "../../../etc/passwd", "sha256": "abc"}],
                "root_digest": "abc",
                "hash_algorithm": "sha256",
                "created_at": "2026-01-01T00:00:00Z",
            })

    def test_rejects_invalid_skill_name(self) -> None:
        from skill_trust.manifest import _validate_skill_name

        with pytest.raises(ValueError, match="Invalid skill name"):
            _validate_skill_name("../../evil")

        with pytest.raises(ValueError, match="Invalid skill name"):
            _validate_skill_name("")

    def test_accepts_valid_skill_names(self) -> None:
        from skill_trust.manifest import _validate_skill_name

        _validate_skill_name("my-skill")
        _validate_skill_name("test_skill")
        _validate_skill_name("skill123")
        _validate_skill_name("My.Skill.v2")

    def test_symlink_to_directory_does_not_escape(self, tmp_path: Path) -> None:
        """Ensure files inside symlinked directories are not included."""
        from skill_trust.manifest import build_manifest

        skill_dir = tmp_path / "skill-with-dir-symlink"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("---\nname: test\n---\n# Test\n")

        target = tmp_path / "external"
        target.mkdir()
        (target / "secret.txt").write_text("sensitive data")

        link = skill_dir / "refs"
        link.symlink_to(target)

        manifest = build_manifest(skill_dir)
        paths = [f.path for f in manifest.files]
        assert "SKILL.md" in paths
        assert "refs/secret.txt" not in paths
