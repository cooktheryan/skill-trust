"""Trust policy configuration for skill verification."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class TrustPolicy:
    """Configuration for what skills are trusted.

    Separates "can I verify this cryptographically?" from "do I trust this signer?"
    """

    require_signature: bool = True
    trusted_identities: list[str] = field(default_factory=list)
    trusted_issuers: list[str] = field(default_factory=list)
    mode: Literal["enforce", "warn"] = "enforce"

    def is_identity_trusted(self, identity: str | None) -> bool:
        """Check if a signer identity is trusted by this policy."""
        if not self.trusted_identities:
            return True  # no constraints = trust all
        return identity is not None and identity in self.trusted_identities

    def is_issuer_trusted(self, issuer: str | None) -> bool:
        """Check if an OIDC issuer is trusted by this policy."""
        if not self.trusted_issuers:
            return True  # no constraints = trust all
        return issuer is not None and issuer in self.trusted_issuers

    @classmethod
    def from_file(cls, path: Path) -> TrustPolicy:
        """Load a trust policy from a JSON file.

        Raises:
            ValueError: If the policy file contains invalid values.
        """
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in policy file {path}: {e}") from e

        mode = data.get("mode", "enforce")
        if mode not in ("enforce", "warn"):
            raise ValueError(
                f"Invalid mode '{mode}' in {path}. Must be 'enforce' or 'warn'."
            )

        identities = data.get("trusted_identities", [])
        if not isinstance(identities, list):
            raise ValueError(
                f"trusted_identities must be a list in {path}, got {type(identities).__name__}"
            )

        issuers = data.get("trusted_issuers", [])
        if not isinstance(issuers, list):
            raise ValueError(
                f"trusted_issuers must be a list in {path}, got {type(issuers).__name__}"
            )

        return cls(
            require_signature=bool(data.get("require_signature", True)),
            trusted_identities=identities,
            trusted_issuers=issuers,
            mode=mode,
        )

    def to_dict(self) -> dict:
        return {
            "require_signature": self.require_signature,
            "trusted_identities": list(self.trusted_identities),
            "trusted_issuers": list(self.trusted_issuers),
            "mode": self.mode,
        }
