"""Load-time verification gate for plugin loaders."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from skill_trust.models import IdentityConstraints
from skill_trust.policy import TrustPolicy
from skill_trust.verifier import SkillVerifier

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GateResult:
    """Result of the load-time verification gate."""

    allowed: bool
    skill_name: str
    reason: str
    identity: str | None = None
    issuer: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return not self.allowed


def _make_result(
    allowed: bool,
    skill_name: str,
    reason: str,
    policy: TrustPolicy,
    *,
    identity: str | None = None,
    issuer: str | None = None,
) -> GateResult:
    """Build a GateResult, applying warn mode if configured."""
    if not allowed and policy.mode == "warn":
        logger.warning("UNTRUSTED SKILL LOADED: %s — %s", skill_name, reason)
        return GateResult(
            allowed=True,
            skill_name=skill_name,
            reason=reason,
            identity=identity,
            issuer=issuer,
            warnings=[f"UNTRUSTED SKILL LOADED: {reason}"],
        )
    return GateResult(
        allowed=allowed,
        skill_name=skill_name,
        reason=reason,
        identity=identity,
        issuer=issuer,
    )


def verify_before_load(
    skill_path: Path,
    plugin_root: Path,
    policy: TrustPolicy,
    *,
    staging: bool = False,
    tuf_url: str | None = None,
    tuf_root: Path | None = None,
) -> GateResult:
    """Verify a skill before loading it into LLM context.

    This is the primary integration point for plugin loaders. Call this
    before injecting skill content into an agent conversation.

    Args:
        skill_path: Path to the skill directory.
        plugin_root: Path to the plugin root (parent of skills/).
        policy: Trust policy defining what's required.
        staging: Use Sigstore staging infrastructure.
        tuf_url: TUF repository URL for a private Sigstore-compatible service.
        tuf_root: Optional pinned TUF bootstrap root.

    Returns:
        GateResult indicating whether the skill should be loaded.
        In "warn" mode, allowed=True but warnings list is populated.
    """
    skill_path = Path(skill_path).resolve()
    plugin_root = Path(plugin_root).resolve()
    skill_name = skill_path.name

    # Check for signature bundle
    bundle_path = plugin_root / ".skill-trust" / "skills" / f"{skill_name}.sigstore.json"

    if not bundle_path.exists():
        if not policy.require_signature:
            return GateResult(
                allowed=True,
                skill_name=skill_name,
                reason="No signature found, but signatures not required by policy",
            )
        return _make_result(
            False, skill_name,
            f"No signature found for skill '{skill_name}'",
            policy,
        )

    # Build identity constraints from ALL trusted identities/issuers
    trusted_list: list[IdentityConstraints] = []
    if policy.trusted_identities and policy.trusted_issuers:
        # Cross-product: each identity with each issuer
        for ident in policy.trusted_identities:
            for iss in policy.trusted_issuers:
                trusted_list.append(IdentityConstraints(identity=ident, issuer=iss))
    elif policy.trusted_identities:
        for ident in policy.trusted_identities:
            trusted_list.append(IdentityConstraints(identity=ident))
    elif policy.trusted_issuers:
        for iss in policy.trusted_issuers:
            trusted_list.append(IdentityConstraints(issuer=iss))

    verifier = SkillVerifier(
        trusted_identities=trusted_list if trusted_list else None,
        staging=staging,
        tuf_url=tuf_url,
        tuf_root=tuf_root,
    )
    result = verifier.verify_skill(skill_path, bundle_path)

    if not result.verified:
        return _make_result(
            False, skill_name,
            f"Verification failed: {result.error}",
            policy,
            identity=result.identity,
            issuer=result.issuer,
        )

    # Check trust policy (post-hoc check on full lists)
    if not policy.is_identity_trusted(result.identity):
        return _make_result(
            False, skill_name,
            f"Signer '{result.identity}' is not in trusted identities list",
            policy,
            identity=result.identity,
            issuer=result.issuer,
        )

    if not policy.is_issuer_trusted(result.issuer):
        return _make_result(
            False, skill_name,
            f"Issuer '{result.issuer}' is not in trusted issuers list",
            policy,
            identity=result.identity,
            issuer=result.issuer,
        )

    return GateResult(
        allowed=True,
        skill_name=skill_name,
        reason="Verified and trusted",
        identity=result.identity,
        issuer=result.issuer,
    )
