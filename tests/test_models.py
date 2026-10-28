"""Tests for data models."""

import pytest

from skill_trust.models import FileEntry, IdentityConstraints, Manifest, VerificationResult

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
ROOT_DIGEST = "e" * 64


class TestFileEntry:
    def test_round_trip(self) -> None:
        entry = FileEntry(path="SKILL.md", sha256=DIGEST_A)
        d = entry.to_dict()
        restored = FileEntry.from_dict(d)
        assert restored == entry

    def test_immutable(self) -> None:
        entry = FileEntry(path="SKILL.md", sha256="abc123")
        with pytest.raises(AttributeError):
            entry.path = "other.md"  # type: ignore[misc]


class TestManifest:
    def _make_manifest(self, **overrides) -> Manifest:
        defaults = {
            "version": "1.0",
            "skill_name": "test",
            "root": "test",
            "files": (
                FileEntry(path="SKILL.md", sha256=DIGEST_A),
                FileEntry(path="helper.sh", sha256=DIGEST_B),
            ),
            "root_digest": ROOT_DIGEST,
            "hash_algorithm": "sha256",
            "created_at": "2026-04-11T00:00:00+00:00",
        }
        defaults.update(overrides)
        return Manifest(**defaults)

    def test_to_dict_and_back(self) -> None:
        m = self._make_manifest()
        d = m.to_dict()
        m2 = Manifest.from_dict(d)
        assert m.version == m2.version
        assert m.skill_name == m2.skill_name
        assert m.files == m2.files
        assert m.root_digest == m2.root_digest
        assert m.hash_algorithm == m2.hash_algorithm

    def test_rejects_invalid_digest(self) -> None:
        manifest = self._make_manifest().to_dict()
        manifest["files"][0]["sha256"] = "not-a-digest"

        with pytest.raises(ValueError, match="Invalid SHA-256 digest"):
            Manifest.from_dict(manifest)

    def test_diff_identical(self) -> None:
        m = self._make_manifest()
        assert m.diff(m) == []

    def test_diff_modified(self) -> None:
        m1 = self._make_manifest()
        m2 = self._make_manifest(
            files=(
                FileEntry(path="SKILL.md", sha256=DIGEST_C),
                FileEntry(path="helper.sh", sha256=DIGEST_B),
            )
        )
        diff = m1.diff(m2)
        assert diff == ["modified: SKILL.md"]

    def test_diff_added(self) -> None:
        m1 = self._make_manifest()
        m2 = self._make_manifest(
            files=(
                FileEntry(path="SKILL.md", sha256=DIGEST_A),
                FileEntry(path="extra.md", sha256=DIGEST_C),
                FileEntry(path="helper.sh", sha256=DIGEST_B),
            )
        )
        diff = m1.diff(m2)
        assert diff == ["added: extra.md"]

    def test_diff_removed(self) -> None:
        m1 = self._make_manifest()
        m2 = self._make_manifest(
            files=(FileEntry(path="SKILL.md", sha256=DIGEST_A),)
        )
        diff = m1.diff(m2)
        assert diff == ["removed: helper.sh"]

    def test_diff_skill_name_mismatch(self) -> None:
        m1 = self._make_manifest(skill_name="alpha")
        m2 = self._make_manifest(skill_name="beta")
        diff = m1.diff(m2)
        assert any("skill_name mismatch" in d for d in diff)

    def test_diff_multiple_changes(self) -> None:
        m1 = self._make_manifest()
        m2 = self._make_manifest(
            files=(
                FileEntry(path="SKILL.md", sha256=DIGEST_C),
                FileEntry(path="new.md", sha256=DIGEST_D),
            )
        )
        diff = m1.diff(m2)
        assert len(diff) == 3

    def test_rejects_path_traversal(self) -> None:
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

    def test_rejects_absolute_windows_and_duplicate_paths(self) -> None:
        base = {
            "version": "1.0",
            "skill_name": "evil",
            "root": "evil",
            "root_digest": "abc",
            "hash_algorithm": "sha256",
            "created_at": "2026-01-01T00:00:00Z",
        }
        for path in ("/etc/passwd", "..\\secret", "a/../b"):
            with pytest.raises(ValueError, match="path"):
                Manifest.from_dict({
                    **base,
                    "files": [{"path": path, "sha256": "abc"}],
                })

        with pytest.raises(ValueError, match="duplicate"):
            Manifest.from_dict({
                **base,
                "files": [
                    {"path": "a.txt", "sha256": DIGEST_A},
                    {"path": "a.txt", "sha256": DIGEST_B},
                ],
            })


class TestVerificationResult:
    def test_defaults(self) -> None:
        r = VerificationResult(verified=True)
        assert r.identity is None
        assert r.issuer is None
        assert r.discrepancies == []
        assert r.error is None

    def test_with_discrepancies(self) -> None:
        r = VerificationResult(
            verified=False,
            discrepancies=["modified: SKILL.md"],
            error="Files have been tampered with",
        )
        assert not r.verified
        assert len(r.discrepancies) == 1


class TestIdentityConstraints:
    def test_defaults(self) -> None:
        c = IdentityConstraints()
        assert c.identity is None
        assert c.issuer is None
        assert c.repository is None

    def test_with_values(self) -> None:
        c = IdentityConstraints(
            identity="user@example.com",
            issuer="https://accounts.google.com",
        )
        assert c.identity == "user@example.com"
