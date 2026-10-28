# Security

## Security goal

`skill-trust` prevents an agent from loading modified or untrusted instruction-layer
content when integrators call the verification APIs immediately before loading or execution
and treat failures as fatal.

## Guarantees

- Skill signatures cover every file in the skill directory.
- Verification detects added, removed, and modified files.
- Skill names and DSSE subjects are bound to the signed manifest.
- Keyless signatures are bound to Fulcio certificates and Rekor transparency records.
- Keyed signatures use ECDSA P-256 and SHA-256.
- Policy decisions can require issuer, identity, repository, workflow, ref, or public-key
  constraints.
- Digest and publisher blocklists apply even in `warn` and `audit` modes.
- Project policies must be signed by an anchored public key.
- Scanning ignores `.gitignore` and rejects symlinked covered files and bundles.

## Threat model

| Threat | Mitigation |
|---------|------------|
| Malicious skill injection | Require a valid signature and trusted publisher |
| Skill content tampering | Compare signed and current manifests |
| File addition or removal | Detect manifest membership changes |
| Wrong signer | Apply identity, issuer, and publisher constraints |
| Bundle transplant | Verify skill name and DSSE subject |
| Old bundle with changed files | Manifest comparison fails |
| Malicious digest | Digest blocklist |
| Compromised publisher | Publisher blocklist and key rotation |
| Path traversal | Validate skill names and manifest paths |
| Symlink substitution | Skip symlinked files and use no-follow bundle reads |

## Known limitations

### Time-of-check to time-of-use

Files can change after verification and before loading. Integrators should verify
immediately before loading and keep the trusted process in control of the filesystem. The
current implementation does not provide syscall-level `openat()` interception.

### Warn and audit modes

`warn` and `audit` allow non-blocklisted failures while recording warnings or results.
Use `deny` for production release gates and agent startup.

### Runtime enforcement

`preexec_verify()` is a startup gate, not a sandbox. It does not constrain network access,
process execution, or file access after the agent starts.

### Key management

Keyless signing avoids long-lived signing keys, but keyed workflows and policy anchors still
require private-key protection. Store private keys in a secret manager, restrict filesystem
permissions, and never commit them.

### Policy anchor compromise

A policy-anchor private key can sign a policy that trusts additional publishers. Protect it
at least as strongly as a code-signing key and rotate it if compromised.

## Operational hardening

- Use `enforcement: deny` for production.
- Verify in CI and again at agent startup.
- Constrain publishers to the smallest practical identity set.
- For GitHub Actions, constrain repository, workflow, and ref.
- Pin the RHTAS or private Sigstore TUF bootstrap root.
- Treat malformed policies and bundles as failures.
- Monitor warnings and audit reports.
- Rotate keys and update blocklists when a publisher or artifact is compromised.

## Reporting

Please report security-sensitive vulnerabilities privately to the repository maintainer
rather than opening a public issue.
