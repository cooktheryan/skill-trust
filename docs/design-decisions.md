# Design Decisions

## Sign a manifest, not individual files

An agent skill is a directory, not a single file. A per-directory manifest provides one
signature for the complete instruction bundle and detects additions, removals, and
modifications without requiring a separate signing flow for every file.

## Use DSSE and in-toto

DSSE provides an envelope for signed statements. in-toto provides a standard statement and
predicate model. This makes the attestation self-describing and leaves room for future
predicate types such as provenance or dependency metadata.

## Use a root digest as the subject

The root digest is a single SHA-256 commitment to the sorted `path:sha256` manifest entries.
It provides a simple subject for the DSSE statement while the full manifest remains in the
authenticated predicate for detailed comparison.

## Support both keyless and keyed signing

Keyless signing is the preferred production flow because it avoids long-lived signing keys
and binds signatures to OIDC identities through Fulcio and Rekor.

Keyed ECDSA P-256 signing supports local development, offline tests, and environments
without an accepted OIDC provider. Keyed publishers must bind a key ID to public-key
material; a signer-supplied key ID alone is not trusted.

## Separate cryptography from policy

Cryptographic verification proves what was signed and who signed it. Policy decides whether
that signer is accepted. This separation allows RHTAS or public Sigstore to provide the
cryptographic trust roots while each project defines its own publisher constraints.

Direct `SkillVerifier` keyless verification fails closed without identity constraints.
Policy scanning can explicitly request unconstrained cryptographic verification because it
applies publisher policy after verification.

## Make policies signed and composable

Project policies are signed by a policy-anchor key. Verification accepts the project policy
only when its signature is anchored by a supplied public key or an approved user policy.

User and project policies compose by:

- Unioning includes, publishers, and blocklists
- Selecting the strictest enforcement mode
- Requiring a signature if either policy requires one

This lets an organization add restrictions without allowing a project to weaken them.

## Enforce before agent startup

`preexec_verify()` and `verify_before_load()` provide practical startup and load-time
enforcement. They intentionally do not claim to be a kernel-level sandbox. This keeps the
tool portable across agent platforms while making the trust boundary explicit.

## Ignore `.gitignore` during scanning

Trust coverage must not depend on developer tool configuration. A hidden or ignored file
can still be read by an agent, so policy includes determine coverage independently of
`.gitignore`.

## Pin custom TUF trust

For RHTAS and other private Sigstore-compatible services, callers provide a TUF URL and
may pin its bootstrap root. Custom trust and public staging trust are mutually exclusive so
verification cannot silently fall back to the wrong trust domain.

## Why not use Cosign directly?

Cosign can sign and verify blobs, but it does not understand skill-directory manifests,
plugin layouts, publisher policies, or agent startup gates. `skill-trust` can interoperate
with the same Sigstore trust services while providing the agent-facing semantics.
