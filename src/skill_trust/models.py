"""Data models for skill-trust."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import re

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class FileEntry:
    """A single file in a skill manifest."""

    path: str
    sha256: str

    def to_dict(self) -> dict:
        return {"path": self.path, "sha256": self.sha256}

    @classmethod
    def from_dict(cls, data: dict) -> FileEntry:
        if not isinstance(data, dict):
            raise ValueError("Manifest file entry must be an object")
        path = data["path"]
        if not isinstance(path, str) or not path:
            raise ValueError("Manifest file path must be a non-empty string")
        _validate_manifest_path(path)
        sha256 = data["sha256"]
        if not isinstance(sha256, str) or not _SHA256_PATTERN.fullmatch(sha256):
            raise ValueError(f"Invalid SHA-256 digest for manifest path: {path!r}")
        return cls(path=path, sha256=sha256)


@dataclass(frozen=True)
class Manifest:
    """Deterministic manifest of all files in a skill directory.

    Following model-transparency patterns:
    - root_digest: single hash computed from all file digests (used as DSSE subject)
    - hash_algorithm: recorded for reproducibility
    """

    version: str
    skill_name: str
    root: str
    files: tuple[FileEntry, ...]
    root_digest: str
    hash_algorithm: str
    created_at: str

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "skill_name": self.skill_name,
            "root": self.root,
            "files": [f.to_dict() for f in self.files],
            "root_digest": self.root_digest,
            "hash_algorithm": self.hash_algorithm,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Manifest:
        if not isinstance(data, dict):
            raise ValueError("Manifest must be an object")
        raw_files = data.get("files")
        if not isinstance(raw_files, list):
            raise ValueError("Manifest files must be a list")
        files = tuple(FileEntry.from_dict(f) for f in raw_files)
        paths = [entry.path for entry in files]
        if len(paths) != len(set(paths)):
            raise ValueError("Manifest contains duplicate file paths")
        for field_name in ("version", "skill_name", "root", "root_digest"):
            if not isinstance(data.get(field_name), str) or not data[field_name]:
                raise ValueError(f"Manifest {field_name} must be a non-empty string")
        hash_algorithm = data.get("hash_algorithm", "sha256")
        if hash_algorithm != "sha256":
            raise ValueError(f"Unsupported manifest hash algorithm: {hash_algorithm}")
        if not isinstance(data.get("created_at"), str) or not data["created_at"]:
            raise ValueError("Manifest created_at must be a non-empty string")
        root_digest = data["root_digest"]
        if not isinstance(root_digest, str) or not _SHA256_PATTERN.fullmatch(root_digest):
            raise ValueError("Invalid manifest root digest")
        return cls(
            version=data["version"],
            skill_name=data["skill_name"],
            root=data["root"],
            files=files,
            root_digest=data["root_digest"],
            hash_algorithm=data.get("hash_algorithm", "sha256"),
            created_at=data["created_at"],
        )

    def diff(self, other: Manifest) -> list[str]:
        """Compare this manifest against another, returning discrepancies.

        Compares skill_name and file entries. Returns a list of human-readable
        strings describing differences. An empty list means the manifests match.
        """
        discrepancies: list[str] = []

        for field_name in ("version", "skill_name", "root", "root_digest", "hash_algorithm"):
            expected = getattr(self, field_name)
            actual = getattr(other, field_name)
            if expected != actual:
                discrepancies.append(
                    f"{field_name} mismatch: expected '{expected}', got '{actual}'"
                )

        self_files = {f.path: f.sha256 for f in self.files}
        other_files = {f.path: f.sha256 for f in other.files}

        for path in sorted(self_files.keys() - other_files.keys()):
            discrepancies.append(f"removed: {path}")

        for path in sorted(other_files.keys() - self_files.keys()):
            discrepancies.append(f"added: {path}")

        for path in sorted(self_files.keys() & other_files.keys()):
            if self_files[path] != other_files[path]:
                discrepancies.append(f"modified: {path}")

        return discrepancies


def _validate_manifest_path(path: str) -> None:
    if "\\" in path or "\x00" in path:
        raise ValueError(f"Manifest path contains an invalid character: {path!r}")
    parts = path.split("/")
    if path.startswith("/") or any(part in ("", ".", "..") for part in parts):
        raise ValueError(
            f"Manifest path contains a traversal component or is not canonical: {path!r}"
        )


@dataclass(frozen=True)
class SignedSkill:
    """A skill manifest paired with its sigstore bundle path."""

    manifest: Manifest
    bundle_path: Path


@dataclass(frozen=True)
class VerificationResult:
    """Result of verifying a signed skill."""

    verified: bool
    identity: str | None = None
    issuer: str | None = None
    timestamp: datetime | None = None
    discrepancies: list[str] = field(default_factory=list)
    error: str | None = None
    claims: dict[str, str | None] = field(default_factory=dict)
    public_key: str | None = None


@dataclass(frozen=True)
class IdentityConstraints:
    """Constraints for verifying signer identity."""

    identity: str | None = None
    issuer: str | None = None
    repository: str | None = None
