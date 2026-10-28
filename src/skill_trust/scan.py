"""Policy-driven pre-execution trust scanning."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from skill_trust.models import VerificationResult
from skill_trust.policy import TrustPolicy
from skill_trust.verifier import SkillVerifier

_SKIP_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
}
_POLICY_FILES = {"trust-policy.json", "trust-policy.json.keyed.json"}


@dataclass(frozen=True)
class FileTrustResult:
    path: Path
    relative_path: str
    digest: str
    status: str
    reason: str | None = None
    verification: VerificationResult | None = None

    @property
    def verified(self) -> bool:
        return self.status == "verified"


@dataclass(frozen=True)
class ScanReport:
    root: Path
    results: tuple[FileTrustResult, ...]
    warnings: tuple[str, ...] = field(default_factory=tuple)
    enforcement: str = "deny"

    @property
    def failures(self) -> tuple[FileTrustResult, ...]:
        return tuple(result for result in self.results if result.status != "verified")

    @property
    def allowed(self) -> bool:
        if any(result.status == "blocked" for result in self.results):
            return False
        if self.enforcement in ("warn", "audit"):
            return True
        return not self.failures


def scan_project(
    root: Path,
    policy: TrustPolicy,
    verifier: SkillVerifier,
) -> ScanReport:
    """Scan files matching policy includes without respecting .gitignore."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Scan root not found or not a directory: {root}")
    results: list[FileTrustResult] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if _is_skipped(relative):
            continue
        if not policy.matches_path(relative):
            continue

        try:
            data = _read_regular_file_no_follow(path)
        except OSError as error:
            results.append(
                FileTrustResult(
                    path=path,
                    relative_path=relative,
                    digest="",
                    status="blocked",
                    reason=f"Unable to read file: {error}",
                )
            )
            continue
        digest = hashlib.sha256(data).hexdigest()
        if policy.is_digest_blocked(digest):
            results.append(
                FileTrustResult(
                    path=path,
                    relative_path=relative,
                    digest=digest,
                    status="blocked",
                    reason="Digest is blocklisted",
                )
            )
            continue

        bundle_path = path.with_name(f"{path.name}.bundle")
        if not bundle_path.exists():
            if not policy.require_signature:
                results.append(
                    FileTrustResult(
                        path=path,
                        relative_path=relative,
                        digest=digest,
                        status="verified",
                        reason="Signatures not required",
                    )
                )
                continue
            results.append(
                FileTrustResult(
                    path=path,
                    relative_path=relative,
                    digest=digest,
                    status="unsigned",
                    reason=f"No bundle found: {bundle_path.name}",
                )
            )
            continue

        try:
            bundle_bytes = _read_regular_file_no_follow(bundle_path)
        except FileNotFoundError:
            results.append(
                FileTrustResult(
                    path=path,
                    relative_path=relative,
                    digest=digest,
                    status="unsigned",
                    reason=f"No bundle found: {bundle_path.name}",
                )
            )
            continue
        except (OSError, ValueError) as error:
            results.append(
                FileTrustResult(
                    path=path,
                    relative_path=relative,
                    digest=digest,
                    status="blocked",
                    reason=f"Signature bundle must be a regular, non-symlink file: {error}",
                )
            )
            continue

        try:
            verification = verifier.verify_file(
                path,
                bundle_path,
                data=data,
                bundle_bytes=bundle_bytes,
            )
        except (OSError, ValueError, TypeError) as error:
            results.append(
                FileTrustResult(
                    path=path,
                    relative_path=relative,
                    digest=digest,
                    status="blocked",
                    reason=f"Verification scan failed: {error}",
                )
            )
            continue
        publisher_blocked = policy.is_publisher_blocked(
            identity=verification.identity,
            issuer=verification.issuer,
            claims=verification.claims,
            public_key=verification.public_key,
        )
        publisher_trusted = verification.verified and policy.is_publisher_trusted(
            identity=verification.identity,
            issuer=verification.issuer,
            claims=verification.claims,
            public_key=verification.public_key,
        )
        if publisher_blocked:
            status = "blocked"
            reason = "Publisher is blocklisted"
        elif not verification.verified:
            status = "invalid"
            reason = verification.error or "Signature verification failed"
        elif not publisher_trusted:
            status = "untrusted"
            reason = "Signer is not a trusted publisher"
        else:
            status = "verified"
            reason = None

        results.append(
            FileTrustResult(
                path=path,
                relative_path=relative,
                digest=digest,
                status=status,
                reason=reason,
                verification=verification,
            )
        )

    failures = [result for result in results if result.status != "verified"]
    warnings: list[str] = []
    if failures and policy.enforcement in ("warn", "audit"):
        warnings.extend(
            f"{result.relative_path}: {result.status} — {result.reason}"
            for result in failures
        )
    return ScanReport(
        root=root,
        results=tuple(results),
        warnings=tuple(warnings),
        enforcement=policy.enforcement,
    )


def preexec_verify(
    root: Path,
    policy: TrustPolicy,
    verifier: SkillVerifier,
) -> ScanReport:
    """Return a pre-execution decision for files covered by policy."""
    return scan_project(root, policy, verifier)


def _is_skipped(relative_path: str) -> bool:
    parts = Path(relative_path).parts
    if any(part in _SKIP_DIRECTORIES for part in parts[:-1]):
        return True
    return relative_path in _POLICY_FILES


def _read_regular_file_no_follow(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Not a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 8192)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)
