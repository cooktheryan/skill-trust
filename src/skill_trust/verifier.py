"""Skill verification using Sigstore."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from sigstore.models import Bundle
from sigstore.verify import Verifier
from sigstore.verify.policy import AnyOf, Identity, UnsafeNoOp

from skill_trust._identity import extract_identity
from skill_trust.manifest import build_manifest
from skill_trust.models import IdentityConstraints, Manifest, VerificationResult

logger = logging.getLogger(__name__)


class SkillVerifier:
    """Verifies signed AI agent skills using Sigstore.

    Two-step verification:
    1. Cryptographic: DSSE signature verification via sigstore (Fulcio cert + Rekor log)
    2. Content: Compare signed manifest against current files on disk
    """

    def __init__(
        self,
        *,
        identity_constraints: IdentityConstraints | None = None,
        trusted_identities: list[IdentityConstraints] | None = None,
        staging: bool = False,
    ) -> None:
        self._constraints = identity_constraints
        self._trusted_identities = trusted_identities or []
        self._verifier = Verifier.staging() if staging else Verifier.production()

    def _build_policy(self):
        """Build a sigstore verification policy from identity constraints.

        Raises ValueError if no identity constraints are provided, to prevent
        accidentally accepting signatures from any signer.
        """
        # If multiple trusted identities are configured, use AnyOf
        if self._trusted_identities:
            policies = []
            for c in self._trusted_identities:
                if c.identity and c.issuer:
                    policies.append(Identity(identity=c.identity, issuer=c.issuer))
                elif c.identity:
                    policies.append(Identity(identity=c.identity))
                elif c.issuer:
                    policies.append(Identity(issuer=c.issuer))
            if policies:
                return AnyOf(policies) if len(policies) > 1 else policies[0]

        # Single constraint
        if self._constraints is not None:
            if self._constraints.identity and self._constraints.issuer:
                return Identity(
                    identity=self._constraints.identity,
                    issuer=self._constraints.issuer,
                )
            elif self._constraints.identity:
                return Identity(identity=self._constraints.identity)
            elif self._constraints.issuer:
                return Identity(issuer=self._constraints.issuer)

        # No constraints — refuse to proceed silently
        logger.warning(
            "No identity constraints provided. Signature will be verified "
            "cryptographically but the signer identity will NOT be checked. "
            "Any valid Sigstore signer will be accepted."
        )
        return UnsafeNoOp()

    def verify_skill(
        self,
        skill_path: Path,
        bundle_path: Path,
    ) -> VerificationResult:
        """Verify a signed skill.

        Args:
            skill_path: Path to the skill directory on disk.
            bundle_path: Path to the .sigstore.json bundle.

        Returns:
            VerificationResult with verification status and identity info.
        """
        skill_path = Path(skill_path).resolve()
        bundle_path = Path(bundle_path).resolve()

        # Load the sigstore bundle
        try:
            bundle_text = bundle_path.read_text()
        except FileNotFoundError:
            return VerificationResult(
                verified=False,
                error=f"Bundle not found: {bundle_path}",
            )
        except PermissionError:
            return VerificationResult(
                verified=False,
                error=f"Permission denied reading bundle: {bundle_path}",
            )

        try:
            bundle = Bundle.from_json(bundle_text)
        except (json.JSONDecodeError, ValueError) as e:
            return VerificationResult(
                verified=False,
                error=f"Invalid bundle format: {e}",
            )

        # Step 1: Cryptographic DSSE verification
        policy = self._build_policy()
        try:
            _payload_type, payload_bytes = self._verifier.verify_dsse(bundle, policy)
        except Exception as e:
            # sigstore raises various exception types for verification failures;
            # these are all legitimate "signature is invalid" outcomes
            return VerificationResult(
                verified=False,
                error=f"Signature verification failed: {e}",
            )

        # Extract identity from the signing certificate
        cert = bundle.signing_certificate
        identity_info = extract_identity(cert)

        # Parse the authenticated manifest from the DSSE payload
        try:
            statement_data = json.loads(payload_bytes)
            signed_manifest = Manifest.from_dict(statement_data["predicate"])
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            return VerificationResult(
                verified=False,
                identity=identity_info.get("identity"),
                issuer=identity_info.get("issuer"),
                error=f"Failed to parse signed manifest: {e}",
            )

        # Step 2: Check skill name matches
        disk_skill_name = skill_path.name
        if signed_manifest.skill_name != disk_skill_name:
            return VerificationResult(
                verified=False,
                identity=identity_info.get("identity"),
                issuer=identity_info.get("issuer"),
                error=(
                    f"Skill name mismatch: bundle signed for '{signed_manifest.skill_name}' "
                    f"but verifying '{disk_skill_name}'"
                ),
            )

        # Step 3: Compare signed manifest against current disk state
        try:
            disk_manifest = build_manifest(skill_path)
        except (FileNotFoundError, NotADirectoryError, ValueError) as e:
            return VerificationResult(
                verified=False,
                identity=identity_info.get("identity"),
                issuer=identity_info.get("issuer"),
                error=f"Failed to build disk manifest: {e}",
            )

        discrepancies = signed_manifest.diff(disk_manifest)

        return VerificationResult(
            verified=len(discrepancies) == 0,
            identity=identity_info.get("identity"),
            issuer=identity_info.get("issuer"),
            discrepancies=discrepancies,
            error="Files have been tampered with" if discrepancies else None,
        )

    def verify_plugin(
        self,
        plugin_root: Path,
    ) -> dict[str, VerificationResult]:
        """Verify all signed skills in a plugin.

        Returns a dict mapping skill name to VerificationResult.

        Raises:
            FileNotFoundError: If the skills/ directory does not exist.
        """
        plugin_root = Path(plugin_root).resolve()
        skills_dir = plugin_root / "skills"
        bundles_dir = plugin_root / ".skill-trust" / "skills"

        if not skills_dir.is_dir():
            raise FileNotFoundError(f"No skills/ directory found in {plugin_root}")

        results: dict[str, VerificationResult] = {}

        for skill_dir in sorted(skills_dir.iterdir()):
            if not skill_dir.is_dir():
                continue

            bundle_path = bundles_dir / f"{skill_dir.name}.sigstore.json"

            if not bundle_path.exists():
                results[skill_dir.name] = VerificationResult(
                    verified=False,
                    error="No signature bundle found",
                )
                continue

            results[skill_dir.name] = self.verify_skill(skill_dir, bundle_path)

        return results
