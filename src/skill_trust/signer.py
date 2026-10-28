"""Skill signing using Sigstore (keyless) or EC keys (for testing).

Following model-transparency patterns:
- Root digest from file hashes used as DSSE subject (not canonical JSON hash)
- Serialization metadata included in predicate for reproducibility
- EC key signing supported for offline/test use
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from sigstore.dsse import DigestSet, StatementBuilder, Subject
from sigstore.dsse import _sign as sign_dsse_envelope
from sigstore.models import Bundle, ClientTrustConfig
from sigstore.oidc import IdentityToken, Issuer, detect_credential
from sigstore.sign import SigningContext

from skill_trust.manifest import build_manifest
from skill_trust.keyed import (
    KEYED_BUNDLE_MEDIA_TYPE,
    encode_public_key,
    key_id,
    load_private_key,
    sign_bytes,
)
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
        tuf_url: str | None = None,
        tuf_root: Path | None = None,
        private_key: Path | None = None,
    ) -> None:
        if private_key and (staging or tuf_url):
            raise ValueError("Keyed signing cannot use Sigstore keyless infrastructure")
        if private_key and identity_token:
            raise ValueError("Keyed signing cannot use an OIDC identity token")

        self._private_key = load_private_key(private_key) if private_key else None
        self._keyless = private_key is None
        if staging and tuf_url:
            raise ValueError("--staging and a custom TUF URL cannot be combined")
        if tuf_root and not tuf_url:
            raise ValueError("A custom TUF bootstrap root requires a TUF URL")

        self._raw_token = identity_token
        self._use_ambient_credentials = use_ambient_credentials
        self._tuf_root = tuf_root

        if not self._keyless:
            self._signing_ctx = None
            self._trust_config = None
        elif tuf_url:
            trust_config = ClientTrustConfig.from_tuf(
                tuf_url,
                bootstrap_root=tuf_root,
            )
        else:
            trust_config = (
                ClientTrustConfig.staging()
                if staging
                else ClientTrustConfig.production()
            )

        if self._keyless:
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

        if self._private_key is not None:
            statement = _build_statement(manifest).build()
            envelope = sign_dsse_envelope(self._private_key, statement)
            bundle_data = {
                "mediaType": KEYED_BUNDLE_MEDIA_TYPE,
                "envelope": json.loads(envelope.to_json()),
                "publicKey": encode_public_key(self._private_key.public_key()),
                "keyId": key_id(self._private_key.public_key()),
            }
            bundle_path = _write_bundle(
                bundle_data, manifest.skill_name, skill_path, output_dir
            )
        else:
            statement = _build_statement(manifest).build()
            identity = self._get_identity_token()
            with self._signing_ctx.signer(identity, cache=True) as signer:
                bundle = signer.sign_dsse(statement)
            bundle_path = _write_bundle(bundle, manifest.skill_name, skill_path, output_dir)

        return SignedSkill(manifest=manifest, bundle_path=bundle_path)

    def sign_file(self, file_path: Path, output_path: Path | None = None) -> Path:
        """Sign an arbitrary file with keyed ECDSA or keyless Sigstore."""
        file_path = Path(file_path).resolve()
        data = file_path.read_bytes()
        output_path = output_path or file_path.with_name(f"{file_path.name}.bundle")

        if self._private_key is not None:
            bundle_data = {
                "mediaType": KEYED_BUNDLE_MEDIA_TYPE,
                "sha256": hashlib.sha256(data).hexdigest(),
                "signature": sign_bytes(self._private_key, data),
                "publicKey": encode_public_key(self._private_key.public_key()),
                "keyId": key_id(self._private_key.public_key()),
            }
            output_path.write_text(json.dumps(bundle_data, indent=2) + "\n")
            return output_path

        identity = self._get_identity_token()
        with self._signing_ctx.signer(identity, cache=True) as signer:
            bundle = signer.sign_artifact(data)
        output_path.write_text(bundle.to_json())
        return output_path

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
    bundle: Bundle | dict,
    skill_name: str,
    skill_path: Path,
    output_dir: Path | None,
) -> Path:
    """Write a sigstore bundle to disk."""
    if output_dir is None:
        output_dir = skill_path.parent.parent / ".skill-trust" / "skills"

    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = output_dir / f"{skill_name}.sigstore.json"
    bundle_text = (
        bundle.to_json() if isinstance(bundle, Bundle) else json.dumps(bundle, indent=2) + "\n"
    )
    bundle_path.write_text(bundle_text)

    return bundle_path
