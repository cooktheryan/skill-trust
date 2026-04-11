"""Deterministic manifest generation for skill directories.

Follows patterns from sigstore/model-transparency:
- Parallel file hashing with ThreadPoolExecutor
- Root digest computed from sorted file digests
- Serialization metadata recorded for reproducibility
"""

from __future__ import annotations

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from skill_trust.models import FileEntry, Manifest

MANIFEST_VERSION = "1.0"
HASH_ALGORITHM = "sha256"

_SAFE_SKILL_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


def _validate_skill_name(name: str) -> None:
    """Validate that a skill name contains only safe characters."""
    if not _SAFE_SKILL_NAME.match(name):
        raise ValueError(
            f"Invalid skill name: {name!r}. "
            "Must contain only alphanumeric characters, hyphens, underscores, and dots."
        )


def _hash_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file's raw bytes.

    Uses chunked reads (8KB) to handle large files without loading into memory.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_root_digest(file_entries: tuple[FileEntry, ...]) -> str:
    """Compute a single root digest from all file digests.

    Following model-transparency's pattern: SHA-256 over all individual file
    digests concatenated in sorted order. This single hash is what gets signed
    as the DSSE subject.
    """
    h = hashlib.sha256()
    for entry in file_entries:
        h.update(f"{entry.path}:{entry.sha256}\n".encode("utf-8"))
    return h.hexdigest()


def _collect_file_paths(skill_path: Path) -> list[tuple[str, Path]]:
    """Walk a skill directory and collect (posix_relative_path, resolved_path) pairs.

    Skips symlinks for security. Verifies all files resolve within the skill
    directory to prevent path traversal.
    """
    skill_path = skill_path.resolve()
    paths: list[tuple[str, Path]] = []

    for item in sorted(skill_path.rglob("*")):
        if item.is_symlink():
            continue
        if not item.is_file():
            continue

        resolved = item.resolve()
        if not resolved.is_relative_to(skill_path):
            raise ValueError(f"Path escapes skill directory: {item}")

        rel = item.relative_to(skill_path)
        posix_path = rel.as_posix()

        if ".." in posix_path.split("/"):
            raise ValueError(f"Path contains traversal component: {posix_path}")

        paths.append((posix_path, resolved))

    return paths


def _hash_files_parallel(
    paths: list[tuple[str, Path]],
    max_workers: int | None = None,
) -> list[tuple[str, str]]:
    """Hash multiple files in parallel using ThreadPoolExecutor.

    Following model-transparency's pattern for parallel file hashing.
    """
    if len(paths) <= 1:
        return [(p, _hash_file(resolved)) for p, resolved in paths]

    results: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_hash_file, resolved): posix_path
            for posix_path, resolved in paths
        }
        for future in futures:
            posix_path = futures[future]
            digest = future.result()
            results.append((posix_path, digest))

    # Re-sort since ThreadPoolExecutor doesn't preserve order
    results.sort(key=lambda x: x[0])
    return results


def build_manifest(skill_path: Path, *, max_workers: int | None = None) -> Manifest:
    """Build a deterministic manifest for a skill directory.

    Args:
        skill_path: Path to the skill directory to manifest.
        max_workers: Max threads for parallel file hashing (None = auto).

    Returns:
        A Manifest with sorted file entries, SHA-256 digests, and root digest.

    Raises:
        FileNotFoundError: If skill_path does not exist.
        NotADirectoryError: If skill_path is not a directory.
        ValueError: If the directory is empty or the skill name is invalid.
    """
    skill_path = skill_path.resolve()

    if not skill_path.exists():
        raise FileNotFoundError(f"Skill directory not found: {skill_path}")
    if not skill_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {skill_path}")

    skill_name = skill_path.name
    _validate_skill_name(skill_name)

    paths = _collect_file_paths(skill_path)
    if not paths:
        raise ValueError(f"No files found in skill directory: {skill_path}")

    entries = _hash_files_parallel(paths, max_workers=max_workers)

    file_entries = tuple(
        FileEntry(path=path, sha256=digest) for path, digest in entries
    )

    root_digest = compute_root_digest(file_entries)

    return Manifest(
        version=MANIFEST_VERSION,
        skill_name=skill_name,
        root=skill_name,
        files=file_entries,
        root_digest=root_digest,
        hash_algorithm=HASH_ALGORITHM,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
