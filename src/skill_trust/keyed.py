"""Keyed ECDSA P-256 signing helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

KEYED_BUNDLE_MEDIA_TYPE = "application/vnd.skill-trust.keyed-bundle.v1+json"
POLICY_SIGNATURE_MEDIA_TYPE = "application/vnd.skill-trust.policy-signature.v1+json"


def generate_key_pair(private_key_path: Path) -> tuple[Path, Path]:
    """Generate a P-256 key pair with owner-only file permissions."""
    private_key_path = Path(private_key_path)
    public_key_path = private_key_path.with_name(f"{private_key_path.name}.pub")
    private_key = ec.generate_private_key(ec.SECP256R1())

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    _atomic_write_bytes(private_key_path, private_pem, mode=0o600)
    _atomic_write_bytes(public_key_path, public_pem, mode=0o600)
    return private_key_path, public_key_path


def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    key = load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError(f"Expected an EC private key: {path}")
    if key.curve.name != "secp256r1":
        raise ValueError(f"Expected an EC P-256 private key: {path}")
    return key


def load_public_key(path: Path) -> ec.EllipticCurvePublicKey:
    key = load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError(f"Expected an EC public key: {path}")
    if key.curve.name != "secp256r1":
        raise ValueError(f"Expected an EC P-256 public key: {path}")
    return key


def public_key_der(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def encode_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
    return base64.b64encode(public_key_der(public_key)).decode("ascii")


def decode_public_key(encoded: str) -> ec.EllipticCurvePublicKey:
    der = base64.b64decode(encoded, validate=True)
    loaded = serialization.load_der_public_key(der)
    if not isinstance(loaded, ec.EllipticCurvePublicKey):
        raise ValueError("Expected an EC public key")
    if loaded.curve.name != "secp256r1":
        raise ValueError("Expected an EC P-256 public key")
    return loaded


def key_id(public_key: ec.EllipticCurvePublicKey) -> str:
    return hashlib.sha256(public_key_der(public_key)).hexdigest()


def sign_bytes(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    signature = private_key.sign(
        digest,
        ec.ECDSA(Prehashed(hashes.SHA256())),
    )
    return base64.b64encode(signature).decode("ascii")


def verify_bytes(
    public_key: ec.EllipticCurvePublicKey,
    data: bytes,
    encoded_signature: str,
) -> bool:
    digest = hashlib.sha256(data).digest()
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
        public_key.verify(
            signature,
            digest,
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def write_policy_signature(
    policy_path: Path,
    private_key_path: Path,
    output_path: Path | None = None,
) -> Path:
    """Sign a trust policy and write a keyed signature sidecar."""
    policy_path = Path(policy_path)
    private_key = load_private_key(private_key_path)
    output_path = output_path or policy_path.with_name(f"{policy_path.name}.keyed.json")
    payload = policy_path.read_bytes()

    sidecar = {
        "mediaType": POLICY_SIGNATURE_MEDIA_TYPE,
        "algorithm": "ecdsa-p256-sha256",
        "publicKey": encode_public_key(private_key.public_key()),
        "keyId": key_id(private_key.public_key()),
        "signature": sign_bytes(private_key, payload),
    }
    _atomic_write_text(output_path, json.dumps(sidecar, indent=2) + "\n")
    return Path(output_path)


def verify_policy_signature(
    policy_path: Path,
    signature_path: Path,
    trusted_public_keys: list[str] | None = None,
) -> tuple[bool, str | None]:
    """Verify a policy signature, optionally requiring a trusted anchor key."""
    policy_path = Path(policy_path)
    signature_path = Path(signature_path)
    try:
        sidecar = json.loads(signature_path.read_text())
        encoded_key = sidecar["publicKey"]
        signature = sidecar["signature"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        return False, f"Invalid policy signature: {error}"

    if sidecar.get("mediaType") != POLICY_SIGNATURE_MEDIA_TYPE:
        return False, "Unsupported policy signature media type"

    try:
        public_key = decode_public_key(encoded_key)
    except (ValueError, TypeError) as error:
        return False, f"Invalid policy public key: {error}"

    canonical_trusted_keys = None
    if trusted_public_keys is not None:
        canonical_trusted_keys = []
        for trusted_key in trusted_public_keys:
            if not isinstance(trusted_key, str):
                return False, "Trusted policy public keys must be strings"
            try:
                canonical_trusted_keys.append(encode_public_key(decode_public_key(trusted_key)))
            except (ValueError, TypeError) as error:
                return False, f"Invalid trusted policy public key: {error}"
        encoded_key = encode_public_key(public_key)

    if canonical_trusted_keys is not None and encoded_key not in canonical_trusted_keys:
        return False, "Policy signer is not a trusted anchor"

    try:
        policy_bytes = policy_path.read_bytes()
    except OSError as error:
        return False, f"Unable to read policy: {error}"
    if not verify_bytes(public_key, policy_bytes, signature):
        return False, "Policy signature is invalid"
    return True, key_id(public_key)


def _atomic_write_text(path: Path, text: str) -> None:
    _atomic_write_bytes(path, text.encode("utf-8"))


def _atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            dir=path.parent,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as temporary_file:
            descriptor = None
            temporary_file.write(data)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
