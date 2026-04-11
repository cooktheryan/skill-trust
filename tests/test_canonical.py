"""Tests for JSON canonicalization."""

import json

from skill_trust._canonical import canonicalize
from skill_trust.models import FileEntry, Manifest


class TestCanonicalize:
    def _make_manifest(self) -> Manifest:
        return Manifest(
            version="1.0",
            skill_name="test",
            root="test",
            files=(
                FileEntry(path="SKILL.md", sha256="aaa"),
                FileEntry(path="helper.sh", sha256="bbb"),
            ),
            root_digest="rootdigest123",
            hash_algorithm="sha256",
            created_at="2026-04-11T00:00:00+00:00",
        )

    def test_produces_bytes(self) -> None:
        result = canonicalize(self._make_manifest())
        assert isinstance(result, bytes)

    def test_deterministic(self) -> None:
        m = self._make_manifest()
        assert canonicalize(m) == canonicalize(m)

    def test_sorted_keys(self) -> None:
        result = canonicalize(self._make_manifest())
        text = result.decode("utf-8")
        data = json.loads(text)
        expected = json.dumps(data, sort_keys=True, separators=(",", ":"))
        assert text == expected

    def test_compact_format(self) -> None:
        result = canonicalize(self._make_manifest())
        text = result.decode("utf-8")
        assert ": " not in text
        assert ", " not in text

    def test_valid_json(self) -> None:
        result = canonicalize(self._make_manifest())
        data = json.loads(result)
        assert data["version"] == "1.0"
        assert data["skill_name"] == "test"
        assert data["root_digest"] == "rootdigest123"
        assert data["hash_algorithm"] == "sha256"
        assert len(data["files"]) == 2
