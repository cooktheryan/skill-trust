"""Data models for skill-trust."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class FileEntry:
    """A single file in a skill manifest."""

    path: str
    sha256: str

    def to_dict(self) -> dict:
        return {"path": self.path, "sha256": self.sha256}

    @classmethod
    def from_dict(cls, data: dict) -> FileEntry:
        return cls(path=data["path"], sha256=data["sha256"])


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
        files = tuple(FileEntry.from_dict(f) for f in data["files"])
        for f in files:
            if ".." in f.path.split("/"):
                raise ValueError(f"File path contains traversal component: {f.path}")
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

        if self.skill_name != other.skill_name:
            discrepancies.append(
                f"skill_name mismatch: expected '{self.skill_name}', got '{other.skill_name}'"
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


@dataclass(frozen=True)
class IdentityConstraints:
    """Constraints for verifying signer identity."""

    identity: str | None = None
    issuer: str | None = None
    repository: str | None = None
