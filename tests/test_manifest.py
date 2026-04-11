"""Tests for manifest generation."""

import os
from pathlib import Path

import pytest

from skill_trust.manifest import build_manifest, compute_root_digest
from skill_trust.models import FileEntry


class TestBuildManifest:
    def test_produces_manifest_from_fixture(self, sample_skill_path: Path) -> None:
        manifest = build_manifest(sample_skill_path)

        assert manifest.version == "1.0"
        assert manifest.skill_name == "sample-skill"
        assert manifest.root == "sample-skill"
        assert manifest.hash_algorithm == "sha256"
        assert len(manifest.files) == 2
        assert manifest.root_digest  # non-empty

        paths = [f.path for f in manifest.files]
        assert "SKILL.md" in paths
        assert "helper.sh" in paths

    def test_deterministic_output(self, sample_skill_path: Path) -> None:
        m1 = build_manifest(sample_skill_path)
        m2 = build_manifest(sample_skill_path)

        assert m1.files == m2.files
        assert m1.root_digest == m2.root_digest
        assert m1.skill_name == m2.skill_name

    def test_files_sorted_lexicographically(self, sample_skill_path: Path) -> None:
        manifest = build_manifest(sample_skill_path)
        paths = [f.path for f in manifest.files]
        assert paths == sorted(paths)

    def test_posix_paths(self, sample_skill_path: Path) -> None:
        manifest = build_manifest(sample_skill_path)
        for entry in manifest.files:
            assert "\\" not in entry.path

    def test_sha256_hex_format(self, sample_skill_path: Path) -> None:
        manifest = build_manifest(sample_skill_path)
        for entry in manifest.files:
            assert len(entry.sha256) == 64
            int(entry.sha256, 16)  # should not raise

    def test_skips_symlinks(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "skill-with-symlink"
        skill_dir.mkdir()
        real_file = skill_dir / "SKILL.md"
        real_file.write_text("---\nname: test\n---\n# Test\n")
        link = skill_dir / "link.md"
        link.symlink_to(real_file)

        manifest = build_manifest(skill_dir)
        paths = [f.path for f in manifest.files]
        assert "SKILL.md" in paths
        assert "link.md" not in paths

    def test_includes_binary_files(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "binary-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("---\nname: bin\n---\n# Bin\n")
        (skill_dir / "data.bin").write_bytes(b"\x00\x01\x02\xff")

        manifest = build_manifest(skill_dir)
        paths = [f.path for f in manifest.files]
        assert "data.bin" in paths

    def test_handles_subdirectories(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "nested-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("---\nname: nested\n---\n# Nested\n")
        sub = skill_dir / "refs"
        sub.mkdir()
        (sub / "tools.md").write_text("# Tools\n")

        manifest = build_manifest(skill_dir)
        paths = [f.path for f in manifest.files]
        assert "refs/tools.md" in paths

    def test_nonexistent_path_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            build_manifest(Path("/nonexistent/skill"))

    def test_file_path_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "not-a-dir.txt"
        f.write_text("hello")
        with pytest.raises(NotADirectoryError):
            build_manifest(f)

    def test_empty_dir_raises(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty-skill"
        empty.mkdir()
        with pytest.raises(ValueError, match="No files found"):
            build_manifest(empty)

    def test_invalid_skill_name_raises(self, tmp_path: Path) -> None:
        bad_dir = tmp_path / "..evil"
        bad_dir.mkdir()
        (bad_dir / "SKILL.md").write_text("test")
        with pytest.raises(ValueError, match="Invalid skill name"):
            build_manifest(bad_dir)

    def test_parallel_hashing(self, tmp_path: Path) -> None:
        """Parallel hashing produces same result as single-threaded."""
        skill_dir = tmp_path / "parallel-skill"
        skill_dir.mkdir()
        for i in range(10):
            (skill_dir / f"file{i:02d}.md").write_text(f"Content {i}\n")

        m_single = build_manifest(skill_dir, max_workers=1)
        m_parallel = build_manifest(skill_dir, max_workers=4)

        assert m_single.files == m_parallel.files
        assert m_single.root_digest == m_parallel.root_digest


class TestManifestDiff:
    def test_identical_manifests_no_diff(self, sample_skill_path: Path) -> None:
        m1 = build_manifest(sample_skill_path)
        m2 = build_manifest(sample_skill_path)
        assert m1.diff(m2) == []

    def test_detects_modified_file(self, tmp_skill: Path) -> None:
        m1 = build_manifest(tmp_skill)
        (tmp_skill / "SKILL.md").write_text("---\nname: changed\n---\n# Changed\n")
        m2 = build_manifest(tmp_skill)

        diff = m1.diff(m2)
        assert any("modified: SKILL.md" in d for d in diff)

    def test_detects_added_file(self, tmp_skill: Path) -> None:
        m1 = build_manifest(tmp_skill)
        (tmp_skill / "extra.md").write_text("# Extra\n")
        m2 = build_manifest(tmp_skill)

        diff = m1.diff(m2)
        assert any("added: extra.md" in d for d in diff)

    def test_detects_removed_file(self, tmp_skill: Path) -> None:
        m1 = build_manifest(tmp_skill)
        os.remove(tmp_skill / "helper.sh")
        m2 = build_manifest(tmp_skill)

        diff = m1.diff(m2)
        assert any("removed: helper.sh" in d for d in diff)

    def test_detects_multiple_changes(self, tmp_skill: Path) -> None:
        m1 = build_manifest(tmp_skill)
        (tmp_skill / "SKILL.md").write_text("changed")
        (tmp_skill / "new.md").write_text("new")
        os.remove(tmp_skill / "helper.sh")
        m2 = build_manifest(tmp_skill)

        diff = m1.diff(m2)
        assert len(diff) == 3


class TestRootDigest:
    def test_deterministic(self) -> None:
        files = (
            FileEntry(path="SKILL.md", sha256="aaa"),
            FileEntry(path="helper.sh", sha256="bbb"),
        )
        assert compute_root_digest(files) == compute_root_digest(files)

    def test_different_for_different_files(self) -> None:
        f1 = (FileEntry(path="a.md", sha256="aaa"),)
        f2 = (FileEntry(path="a.md", sha256="bbb"),)
        assert compute_root_digest(f1) != compute_root_digest(f2)

    def test_order_matters(self) -> None:
        f1 = (
            FileEntry(path="a.md", sha256="aaa"),
            FileEntry(path="b.md", sha256="bbb"),
        )
        f2 = (
            FileEntry(path="b.md", sha256="bbb"),
            FileEntry(path="a.md", sha256="aaa"),
        )
        assert compute_root_digest(f1) != compute_root_digest(f2)

    def test_hex_format(self) -> None:
        files = (FileEntry(path="a.md", sha256="aaa"),)
        digest = compute_root_digest(files)
        assert len(digest) == 64
        int(digest, 16)  # should not raise


class TestManifestSerialization:
    def test_round_trip(self, sample_skill_path: Path) -> None:
        from skill_trust.models import Manifest

        m = build_manifest(sample_skill_path)
        d = m.to_dict()
        m2 = Manifest.from_dict(d)

        assert m.version == m2.version
        assert m.skill_name == m2.skill_name
        assert m.files == m2.files
        assert m.root_digest == m2.root_digest
        assert m.hash_algorithm == m2.hash_algorithm
