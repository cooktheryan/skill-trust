"""Skill signing using Sigstore (keyless) or EC keys (for testing).

Following model-transparency patterns:
- Root digest from file hashes used as DSSE subject (not canonical JSON hash)
- Serialization metadata included in predicate for reproducibility
- EC key signing supported for offline/test use
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from sigstore.dsse import DigestSet, StatementBuilder, Subject
from sigstore.models import Bundle, ClientTrustConfig
from sigstore.oidc import IdentityToken, Issuer, detect_credential
from sigstore.sign import SigningContext

from skill_trust.manifest import build_manifest
from skill_trust.models import Manifest, SignedSkill

PREDICATE_TYPE = "https://skill-trust.dev/skill/v1"


class SkillSigner:
    """Signs AI agent skill directories using Sigstore's keyless flow.

    Uses OIDC identity -> Fulcio short-lived certificate -> Rekor transparency log.
    Produces standard sigstore bundles containing DSSE-signed in-toto attestations.
    """

    def __init__(
        self,
        *,
        identity_token: str | None = None,
        staging: bool = False,
        use_ambient_credentials: bool = True,
    ) -> None:
        self._raw_token = identity_token
        self._staging = staging
        self._use_ambient_credentials = use_ambient_credentials

        trust_config = (
            ClientTrustConfig.staging() if staging else ClientTrustConfig.production()
        )
        self._signing_ctx = SigningContext.from_trust_config(trust_config)
        self._trust_config = trust_config

    def _get_identity_token(self) -> IdentityToken:
        """Acquire an OIDC identity token.

        Priority: explicit token > ambient credentials > interactive browser flow.
        """
        if self._raw_token:
            return IdentityToken(self._raw_token)

        if self._use_ambient_credentials:
            ambient = detect_credential()
            if ambient:
                return IdentityToken(ambient)

        oidc_url = self._trust_config.signing_config.get_oidc_url()
        issuer = Issuer(oidc_url)
        return issuer.identity_token()

    def sign_skill(
        self,
        skill_path: Path,
        output_dir: Path | None = None,
    ) -> SignedSkill:
        """Sign a skill directory.

        Args:
            skill_path: Path to the skill directory.
            output_dir: Where to write the .sigstore.json bundle.
                        Defaults to .skill-trust/skills/ relative to skill_path's parent.

        Returns:
            SignedSkill with the manifest and bundle path.
        """
        skill_path = Path(skill_path).resolve()
        manifest = build_manifest(skill_path)

        statement = _build_statement(manifest).build()
        identity = self._get_identity_token()

        with self._signing_ctx.signer(identity, cache=True) as signer:
            bundle = signer.sign_dsse(statement)

        bundle_path = _write_bundle(bundle, manifest.skill_name, skill_path, output_dir)

        return SignedSkill(manifest=manifest, bundle_path=bundle_path)

    def sign_plugin(self, plugin_root: Path) -> list[SignedSkill]:
        """Sign all skill directories in a plugin.

        Looks for subdirectories under plugin_root/skills/ that contain a SKILL.md.
        """
        plugin_root = Path(plugin_root).resolve()
        skills_dir = plugin_root / "skills"

        if not skills_dir.is_dir():
            raise FileNotFoundError(f"No skills/ directory found in {plugin_root}")

        results: list[SignedSkill] = []
        for skill_dir in sorted(skills_dir.iterdir()):
            if skill_dir.is_dir() and (skill_dir / "SKILL.md").exists():
                result = self.sign_skill(
                    skill_dir,
                    output_dir=plugin_root / ".skill-trust" / "skills",
                )
                results.append(result)

        return results


def generate_ec_test_key(output_path: Path) -> Path:
    """Generate an EC P-256 private key for testing.

    Following model-transparency's pattern of using EC key signing
    for offline tests without requiring Sigstore infrastructure.

    Args:
        output_path: Where to write the PEM-encoded private key.

    Returns:
        The output path.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    output_path.write_bytes(pem)
    return output_path


def _build_statement(manifest: Manifest) -> StatementBuilder:
    """Build an in-toto DSSE Statement from a skill manifest.

    Uses root_digest (computed from sorted file hashes) as the DSSE subject,
    following model-transparency's pattern.
    """
    subject = Subject(
        name=manifest.skill_name,
        digest=DigestSet(root={"sha256": manifest.root_digest}),
    )

    return (
        StatementBuilder()
        .subjects([subject])
        .predicate_type(PREDICATE_TYPE)
        .predicate(manifest.to_dict())
    )


def _write_bundle(
    bundle: Bundle,
    skill_name: str,
    skill_path: Path,
    output_dir: Path | None,
) -> Path:
    """Write a sigstore bundle to disk."""
    if output_dir is None:
        output_dir = skill_path.parent.parent / ".skill-trust" / "skills"

    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = output_dir / f"{skill_name}.sigstore.json"
    bundle_path.write_text(bundle.to_json())

    return bundle_path
