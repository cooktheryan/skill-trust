"""JSON canonicalization for deterministic signing."""

from __future__ import annotations

import json

from skill_trust.models import Manifest


def canonicalize(manifest: Manifest) -> bytes:
    """Produce a canonical JSON representation of a manifest.

    Uses sorted keys and compact separators for determinism.
    Returns UTF-8 encoded bytes suitable for hashing and signing.
    """
    return json.dumps(
        manifest.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
