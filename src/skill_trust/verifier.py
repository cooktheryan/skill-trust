"""Skill and file verification using Sigstore or keyed ECDSA."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from sigstore.dsse import Envelope
from sigstore.dsse import _verify as verify_dsse_envelope
from sigstore.models import Bundle, ClientTrustConfig
from sigstore.verify import Verifier
from sigstore.verify.policy import AnyOf, Identity, UnsafeNoOp

from skill_trust._identity import extract_identity
from skill_trust.keyed import KEYED_BUNDLE_MEDIA_TYPE, decode_public_key, key_id, verify_bytes
from skill_trust.manifest import build_manifest
from skill_trust.models import IdentityConstraints, Manifest, VerificationResult

logger = logging.getLogger(__name__)
_IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
_IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_SKILL_PREDICATE_TYPE = "https://skill-trust.dev/skill/v1"


class SkillVerifier:
    """Verifies signed skills and files using Sigstore or keyed ECDSA."""

    def __init__(
        self,
        *,
        identity_constraints: IdentityConstraints | None = None,
        trusted_identities: list[IdentityConstraints] | None = None,
        staging: bool = False,
        tuf_url: str | None = None,
        tuf_root: Path | None = None,
        allow_unconstrained_identity: bool = False,
    ) -> None:
        if staging and tuf_url:
            raise ValueError("--staging and a custom TUF URL cannot be combined")
        if tuf_root and not tuf_url:
            raise ValueError("A custom TUF bootstrap root requires a TUF URL")

        self._constraints = identity_constraints
        self._trusted_identities = trusted_identities or []
        self._staging = staging
        self._tuf_url = tuf_url
        self._tuf_root = tuf_root
        self._allow_unconstrained_identity = allow_unconstrained_identity
        self._verifier: Verifier | None = None

    def _keyless_verifier(self) -> Verifier:
        if self._verifier is None:
            if self._tuf_url:
                trust_config = ClientTrustConfig.from_tuf(
                    self._tuf_url,
                    bootstrap_root=self._tuf_root,
                )
                self._verifier = Verifier(trusted_root=trust_config.trusted_root)
            else:
                self._verifier = (
                    Verifier.staging() if self._staging else Verifier.production()
                )
        return self._verifier

    def _build_policy(self):
        if self._trusted_identities:
            policies = []
            for constraint in self._trusted_identities:
                if constraint.identity and constraint.issuer:
                    policies.append(Identity(identity=constraint.identity, issuer=constraint.issuer))
                elif constraint.identity:
                    policies.append(Identity(identity=constraint.identity))
                elif constraint.issuer:
                    policies.append(Identity(issuer=constraint.issuer))
            if policies:
                return AnyOf(policies) if len(policies) > 1 else policies[0]

        if self._constraints is not None:
            if self._constraints.identity and self._constraints.issuer:
                return Identity(identity=self._constraints.identity, issuer=self._constraints.issuer)
            if self._constraints.identity:
                return Identity(identity=self._constraints.identity)
            if self._constraints.issuer:
                return Identity(issuer=self._constraints.issuer)

        logger.warning(
            "No cryptographic identity constraints provided. The caller must apply "
            "publisher policy after verification."
        )
        if not self._allow_unconstrained_identity:
            raise ValueError(
                "Keyless verification requires identity constraints or explicit "
                "allow_unconstrained_identity=True"
            )
        return UnsafeNoOp()

    def verify_skill(self, skill_path: Path, bundle_path: Path) -> VerificationResult:
        skill_path = Path(skill_path).resolve()
        bundle_path = Path(bundle_path).resolve()
        try:
            bundle_text = bundle_path.read_text()
        except FileNotFoundError:
            return VerificationResult(verified=False, error=f"Bundle not found: {bundle_path}")
        except PermissionError:
            return VerificationResult(verified=False, error=f"Permission denied reading bundle: {bundle_path}")

        try:
            bundle_data = json.loads(bundle_text)
        except json.JSONDecodeError as error:
            return VerificationResult(verified=False, error=f"Invalid bundle format: {error}")

        if bundle_data.get("mediaType") == KEYED_BUNDLE_MEDIA_TYPE:
            return self._verify_keyed_skill(skill_path, bundle_data)
        return self._verify_keyless_skill(skill_path, bundle_text)

    def verify_file(
        self,
        file_path: Path,
        bundle_path: Path,
        *,
        data: bytes | None = None,
        bundle_bytes: bytes | None = None,
    ) -> VerificationResult:
        file_path = Path(file_path).resolve()
        bundle_path = Path(bundle_path).resolve()
        try:
            data = file_path.read_bytes() if data is None else data
            bundle_text = (
                bundle_bytes.decode("utf-8")
                if bundle_bytes is not None
                else bundle_path.read_text()
            )
        except FileNotFoundError as error:
            return VerificationResult(verified=False, error=f"File or bundle not found: {error}")
        except PermissionError as error:
            return VerificationResult(verified=False, error=f"Permission denied: {error}")
        except UnicodeError as error:
            return VerificationResult(verified=False, error=f"Invalid bundle encoding: {error}")

        try:
            bundle_data = json.loads(bundle_text)
        except json.JSONDecodeError as error:
            return VerificationResult(verified=False, error=f"Invalid bundle format: {error}")

        digest = hashlib.sha256(data).hexdigest()
        if bundle_data.get("mediaType") == KEYED_BUNDLE_MEDIA_TYPE:
            try:
                public_key = decode_public_key(bundle_data["publicKey"])
            except (KeyError, TypeError, ValueError) as error:
                return VerificationResult(verified=False, error=f"Invalid keyed bundle: {error}")
            valid = (
                bundle_data.get("sha256") == digest
                and verify_bytes(public_key, data, bundle_data.get("signature", ""))
            )
            encoded_key = bundle_data.get("publicKey")
            claims = {"key_id": key_id(public_key)}
            return VerificationResult(
                verified=valid,
                identity=f"key:{claims['key_id']}" if valid else None,
                claims=claims,
                public_key=encoded_key,
                error=None if valid else "File signature verification failed",
            )

        try:
            bundle = Bundle.from_json(bundle_text)
            self._keyless_verifier().verify_artifact(data, bundle, self._build_policy())
            identity_info = extract_identity(bundle.signing_certificate)
        except Exception as error:
            return VerificationResult(verified=False, error=f"Signature verification failed: {error}")

        return VerificationResult(
            verified=True,
            identity=identity_info.get("identity"),
            issuer=identity_info.get("issuer"),
            claims=identity_info,
        )

    def _verify_keyed_skill(self, skill_path: Path, bundle_data: dict) -> VerificationResult:
        try:
            public_key = decode_public_key(bundle_data["publicKey"])
            envelope = Envelope._from_json(json.dumps(bundle_data["envelope"]))
            payload = verify_dsse_envelope(public_key, envelope)
            statement_data = json.loads(payload)
            if envelope._inner.payload_type != _IN_TOTO_PAYLOAD_TYPE:
                raise ValueError("unexpected DSSE payload type")
            _validate_skill_statement(statement_data)
            signed_manifest = Manifest.from_dict(statement_data["predicate"])
        except Exception as error:
            return VerificationResult(verified=False, error=f"Signature verification failed: {error}")

        claims = {"key_id": key_id(public_key)}
        return self._finish_skill_verification(
            skill_path,
            signed_manifest,
            identity=f"key:{claims['key_id']}",
            issuer=None,
            claims=claims,
            public_key=bundle_data.get("publicKey"),
        )

    def _verify_keyless_skill(self, skill_path: Path, bundle_text: str) -> VerificationResult:
        try:
            bundle = Bundle.from_json(bundle_text)
            _payload_type, payload = self._keyless_verifier().verify_dsse(
                bundle, self._build_policy()
            )
            if _payload_type != _IN_TOTO_PAYLOAD_TYPE:
                raise ValueError("unexpected DSSE payload type")
            statement_data = json.loads(payload)
            _validate_skill_statement(statement_data)
            signed_manifest = Manifest.from_dict(statement_data["predicate"])
        except Exception as error:
            return VerificationResult(verified=False, error=f"Signature verification failed: {error}")

        identity_info = extract_identity(bundle.signing_certificate)
        return self._finish_skill_verification(
            skill_path,
            signed_manifest,
            identity=identity_info.get("identity"),
            issuer=identity_info.get("issuer"),
            claims=identity_info,
        )

    def _finish_skill_verification(
        self,
        skill_path: Path,
        signed_manifest: Manifest,
        *,
        identity: str | None,
        issuer: str | None,
        claims: dict,
        public_key: str | None = None,
    ) -> VerificationResult:
        common = {
            "identity": identity,
            "issuer": issuer,
            "claims": claims,
            "public_key": public_key,
        }
        if signed_manifest.skill_name != skill_path.name:
            return VerificationResult(
                verified=False,
                error=(
                    f"Skill name mismatch: bundle signed for '{signed_manifest.skill_name}' "
                    f"but verifying '{skill_path.name}'"
                ),
                **common,
            )

        try:
            disk_manifest = build_manifest(skill_path)
        except (FileNotFoundError, NotADirectoryError, ValueError) as error:
            return VerificationResult(
                verified=False,
                error=f"Failed to build disk manifest: {error}",
                **common,
            )

        discrepancies = signed_manifest.diff(disk_manifest)
        return VerificationResult(
            verified=not discrepancies,
            discrepancies=discrepancies,
            error="Files have been tampered with" if discrepancies else None,
            **common,
        )

    def verify_plugin(self, plugin_root: Path) -> dict[str, VerificationResult]:
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


def _validate_skill_statement(statement_data: dict) -> None:
    if statement_data.get("_type") != _IN_TOTO_STATEMENT_TYPE:
        raise ValueError("unexpected in-toto statement type")
    if statement_data.get("predicateType") != _SKILL_PREDICATE_TYPE:
        raise ValueError("unexpected skill predicate type")
    subjects = statement_data.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise ValueError("skill statement must contain exactly one subject")
    subject = subjects[0]
    if not isinstance(subject, dict):
        raise ValueError("invalid skill statement subject")
    digest = subject.get("digest")
    if not isinstance(digest, dict):
        raise ValueError("invalid skill statement subject digest")
    manifest = statement_data.get("predicate")
    if not isinstance(manifest, dict):
        raise ValueError("invalid skill manifest predicate")
    subject_digest = digest.get("sha256")
    if subject_digest != manifest.get("root_digest"):
        raise ValueError("skill subject digest does not match manifest")
    if subject.get("name") != manifest.get("skill_name"):
        raise ValueError("skill subject name does not match manifest")
