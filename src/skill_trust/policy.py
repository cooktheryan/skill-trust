"""Trust policy configuration and signed-policy composition."""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

POLICY_PREDICATE = "https://skill-trust.dev/policy/v1"
Enforcement = Literal["deny", "warn", "audit"]


@dataclass(frozen=True)
class Publisher:
    """A trusted keyed or keyless signer."""

    name: str = "publisher"
    identity: str | None = None
    issuer: str | None = None
    repository: str | None = None
    workflow: str | None = None
    ref_pattern: str | None = None
    key_id: str | None = None
    public_key: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> Publisher:
        return cls(
            name=str(data.get("name", "publisher")),
            identity=data.get("identity"),
            issuer=data.get("issuer"),
            repository=data.get("repository"),
            workflow=data.get("workflow"),
            ref_pattern=data.get("ref_pattern"),
            key_id=data.get("key_id"),
            public_key=data.get("public_key"),
        )

    def to_dict(self) -> dict:
        result = {"name": self.name}
        for key in (
            "identity",
            "issuer",
            "repository",
            "workflow",
            "ref_pattern",
            "key_id",
            "public_key",
        ):
            value = getattr(self, key)
            if value is not None:
                result[key] = value
        return result

    def matches(self, *, identity: str | None, issuer: str | None, claims: dict | None, public_key: str | None) -> bool:
        claims = claims or {}
        if self.key_id is not None:
            if self.public_key is None:
                return False
            signer_key_id = claims.get("key_id")
            if self.key_id != signer_key_id:
                return False
            if self.public_key is not None and self.public_key != public_key:
                return False
            return True

        if self.identity is not None and self.identity != identity:
            return False
        if self.issuer is not None and self.issuer != issuer:
            return False
        if self.repository is not None and not fnmatch.fnmatchcase(
            str(claims.get("github_workflow_repository")), self.repository
        ):
            return False
        if self.workflow is not None and not fnmatch.fnmatchcase(
            str(claims.get("github_workflow_name")), self.workflow
        ):
            return False
        if self.ref_pattern is not None and not fnmatch.fnmatchcase(
            str(claims.get("github_workflow_ref")), self.ref_pattern
        ):
            return False
        return True


@dataclass(frozen=True)
class BlockedDigest:
    sha256: str
    description: str | None = None
    added: str | None = None

    @classmethod
    def from_dict(cls, data: dict | str) -> BlockedDigest:
        if isinstance(data, str):
            return cls(sha256=data)
        return cls(
            sha256=data["sha256"],
            description=data.get("description"),
            added=data.get("added"),
        )

    def to_dict(self) -> dict:
        result = {"sha256": self.sha256}
        if self.description is not None:
            result["description"] = self.description
        if self.added is not None:
            result["added"] = self.added
        return result


@dataclass(frozen=True)
class TrustPolicy:
    """Configuration for what is verified and who is trusted."""

    includes: list[str] = field(default_factory=list)
    publishers: list[Publisher] = field(default_factory=list)
    blocked_digests: list[BlockedDigest] = field(default_factory=list)
    blocked_publishers: list[Publisher] = field(default_factory=list)
    enforcement: Enforcement = "deny"
    require_signature: bool = True

    def is_digest_blocked(self, digest: str) -> bool:
        return digest in {entry.sha256 for entry in self.blocked_digests}

    @property
    def mode(self) -> Literal["enforce", "warn"]:
        return "warn" if self.enforcement in ("warn", "audit") else "enforce"

    def is_publisher_trusted(
        self,
        *,
        identity: str | None,
        issuer: str | None,
        claims: dict | None = None,
        public_key: str | None = None,
    ) -> bool:
        if not self.publishers:
            return False
        return any(
            publisher.matches(
                identity=identity,
                issuer=issuer,
                claims=claims,
                public_key=public_key,
            )
            for publisher in self.publishers
        )

    def is_publisher_blocked(
        self,
        *,
        identity: str | None,
        issuer: str | None,
        claims: dict | None = None,
        public_key: str | None = None,
    ) -> bool:
        return any(
            publisher.matches(
                identity=identity,
                issuer=issuer,
                claims=claims,
                public_key=public_key,
            )
            for publisher in self.blocked_publishers
        )
    def matches_path(self, relative_path: str) -> bool:
        return any(
            re.fullmatch(_glob_to_regex(pattern), relative_path)
            for pattern in self.includes
        )

    def is_identity_trusted(self, identity: str | None) -> bool:
        identities = {
            publisher.identity for publisher in self.publishers if publisher.identity
        }
        return bool(identities) and identity in identities

    def is_issuer_trusted(self, issuer: str | None) -> bool:
        issuers = {publisher.issuer for publisher in self.publishers if publisher.issuer}
        return bool(issuers) and issuer in issuers
    @classmethod
    def from_dict(cls, data: dict) -> TrustPolicy:
        enforcement = data.get("enforcement", data.get("mode", "deny"))
        if enforcement not in ("deny", "warn", "audit", "enforce"):
            raise ValueError(f"Invalid enforcement mode: {enforcement}")
        if enforcement == "enforce":
            enforcement = "deny"
        includes = _string_list(data, "includes")
        publishers_data = data.get("publishers", [])
        blocklist = data.get("blocklist", {})
        if not isinstance(blocklist, dict):
            raise ValueError("blocklist must be an object")
        blocked_data = blocklist.get("digests", [])
        blocked_publisher_data = blocklist.get("publishers", [])
        if not isinstance(publishers_data, list):
            raise ValueError("publishers must be a list")
        if not all(isinstance(publisher, dict) for publisher in publishers_data):
            raise ValueError("publishers must contain objects")
        if not isinstance(blocked_data, list):
            raise ValueError("blocklist.digests must be a list")
        if not all(isinstance(digest, (dict, str)) for digest in blocked_data):
            raise ValueError("blocklist.digests must contain objects or strings")
        if not isinstance(blocked_publisher_data, list):
            raise ValueError("blocklist.publishers must be a list")
        if not all(isinstance(publisher, dict) for publisher in blocked_publisher_data):
            raise ValueError("blocklist.publishers must contain objects")

        publishers = [Publisher.from_dict(item) for item in publishers_data]
        legacy_identities = _optional_string_list(data, "trusted_identities")
        legacy_issuers = _optional_string_list(data, "trusted_issuers")
        if not publishers and (legacy_identities or legacy_issuers):
            if legacy_identities and legacy_issuers:
                publishers = [
                    Publisher(identity=identity, issuer=issuer)
                    for identity in legacy_identities
                    for issuer in legacy_issuers
                ]
            elif legacy_identities:
                publishers = [
                    Publisher(identity=identity) for identity in legacy_identities
                ]
            else:
                publishers = [Publisher(issuer=issuer) for issuer in legacy_issuers]

        return cls(
            includes=includes,
            publishers=publishers,
            blocked_digests=[BlockedDigest.from_dict(item) for item in blocked_data],
            blocked_publishers=[
                Publisher.from_dict(item) for item in blocked_publisher_data
            ],
            enforcement=enforcement,
            require_signature=bool(data.get("require_signature", True)),
        )
    @classmethod
    def from_file(cls, path: Path) -> TrustPolicy:
        try:
            data = json.loads(Path(path).read_text())
        except json.JSONDecodeError as error:
            raise ValueError(f"Invalid JSON in policy file {path}: {error}") from error
        return cls.from_dict(data)
    def to_dict(self) -> dict:
        return {
            "predicate": POLICY_PREDICATE,
            "includes": list(self.includes),
            "publishers": [publisher.to_dict() for publisher in self.publishers],
            "blocklist": {
                "digests": [entry.to_dict() for entry in self.blocked_digests],
                "publishers": [
                    publisher.to_dict() for publisher in self.blocked_publishers
                ],
            },
            "enforcement": self.enforcement,
            "require_signature": self.require_signature,
        }
    def compose(self, other: TrustPolicy) -> TrustPolicy:
        """Compose policies; neither side can weaken the result."""
        enforcement_rank = {"audit": 0, "warn": 1, "deny": 2}
        enforcement = max(self.enforcement, other.enforcement, key=lambda mode: enforcement_rank[mode])
        return TrustPolicy(
            includes=list(dict.fromkeys(self.includes + other.includes)),
            publishers=list(dict.fromkeys(self.publishers + other.publishers)),
            blocked_digests=list(dict.fromkeys(self.blocked_digests + other.blocked_digests)),
            blocked_publishers=list(
                dict.fromkeys(self.blocked_publishers + other.blocked_publishers)
            ),
            enforcement=enforcement,
            require_signature=self.require_signature or other.require_signature,
        )
def _string_list(data: dict, key: str) -> list[str]:
    values = data.get(key, [])
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError(f"{key} must be a list of strings")
    return values


def _glob_to_regex(pattern: str) -> str:
    parts = pattern.split("/")
    expression = ""
    for index, part in enumerate(parts):
        is_last = index == len(parts) - 1
        if part == "**":
            expression += "[^/]+(?:/[^/]+)*" if is_last else "(?:[^/]+/)*"
            continue
        segment = fnmatch.translate(part)
        if segment.endswith("\\Z"):
            segment = segment[:-2]
        expression += segment
        if not is_last:
            expression += "/"
    return expression


def _optional_string_list(data: dict, key: str) -> list[str]:
    values = data.get(key, [])
    if not isinstance(values, list) or not all(
        isinstance(value, str) for value in values
    ):
        raise ValueError(f"{key} must be a list")
    return values
