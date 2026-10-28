"""X.509 certificate identity extraction for sigstore signing certificates."""

from __future__ import annotations

from cryptography import x509

# Sigstore-specific OIDs for certificate extensions
_SIGSTORE_OIDC_ISSUER = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
_SIGSTORE_GH_WORKFLOW_TRIGGER = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.2")
_SIGSTORE_GH_WORKFLOW_SHA = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.3")
_SIGSTORE_GH_WORKFLOW_NAME = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.4")
_SIGSTORE_GH_WORKFLOW_REPOSITORY = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.5")
_SIGSTORE_GH_WORKFLOW_REF = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.6")


def _get_extension_value(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> str | None:
    """Extract a UTF-8 string value from a certificate extension by OID."""
    try:
        ext = cert.extensions.get_extension_for_oid(oid)
        return ext.value.value.decode("utf-8")
    except (x509.ExtensionNotFound, AttributeError, UnicodeDecodeError):
        return None


def _get_san_identity(cert: x509.Certificate) -> str | None:
    """Extract the Subject Alternative Name (email or URI) from a certificate."""
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = san_ext.value

        emails = san.get_values_for_type(x509.RFC822Name)
        if emails:
            return emails[0]

        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        if uris:
            return uris[0]
    except x509.ExtensionNotFound:
        pass

    return None


def extract_identity(cert: x509.Certificate) -> dict[str, str | None]:
    """Extract signer identity information from a sigstore signing certificate.

    Returns a dict with keys: identity, issuer, and optional GitHub workflow fields.
    """
    return {
        "identity": _get_san_identity(cert),
        "issuer": _get_extension_value(cert, _SIGSTORE_OIDC_ISSUER),
        "github_workflow_trigger": _get_extension_value(cert, _SIGSTORE_GH_WORKFLOW_TRIGGER),
        "github_workflow_sha": _get_extension_value(cert, _SIGSTORE_GH_WORKFLOW_SHA),
        "github_workflow_name": _get_extension_value(cert, _SIGSTORE_GH_WORKFLOW_NAME),
        "github_workflow_repository": _get_extension_value(cert, _SIGSTORE_GH_WORKFLOW_REPOSITORY),
        "github_workflow_ref": _get_extension_value(cert, _SIGSTORE_GH_WORKFLOW_REF),
    }
