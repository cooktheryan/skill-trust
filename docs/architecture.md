# Architecture

`skill-trust` separates artifact representation, cryptographic verification, policy
evaluation, and agent integration.

## Components

```text
src/skill_trust/
├── models.py       # Manifest, verification results, identity constraints
├── manifest.py     # Deterministic directory manifests and root digests
├── signer.py       # Keyless and keyed signing for skills and files
├── verifier.py     # DSSE, certificate, artifact, and manifest verification
├── gate.py         # Plugin-loader integration
├── policy.py       # Publisher, include, blocklist, and enforcement policy
├── keyed.py        # ECDSA P-256 key and policy-signature helpers
├── scan.py         # Policy-driven pre-execution file scanning
├── _canonical.py   # Deterministic JSON serialization helpers
├── _identity.py    # X.509 identity and GitHub claim extraction
└── cli/            # sign, verify, inspect, and trust commands
```

## Skill signing flow

```text
Skill directory
     │
     ▼
Deterministic manifest
     │
     ▼
DSSE in-toto statement
     │
     ├── Keyed: ECDSA P-256 signature
     └── Keyless: Fulcio certificate + Rekor transparency log
     │
     ▼
.skill-trust/skills/<skill-name>.sigstore.json
```

1. Walk the skill directory and reject symlinked files.
2. Hash each file with SHA-256.
3. Sort file entries by path.
4. Compute a root digest over `path:sha256` entries.
5. Build an in-toto DSSE statement whose subject is the root digest and whose predicate is
   the complete manifest.
6. Sign with a P-256 key or a Sigstore keyless identity.
7. Write the bundle beside the plugin's skills.

## Skill verification flow

```text
Skill bundle
     │
     ▼
Cryptographic verification
     │
     ▼
Signed manifest extraction
     │
     ▼
Current directory manifest
     │
     ▼
Manifest comparison
     │
     ▼
Publisher policy decision
```

Verification rejects:

- Invalid signatures and certificates
- Unsupported statement or predicate types
- Subject and manifest mismatches
- Skill-name substitution
- Added, removed, or modified files
- Untrusted publishers
- Blocklisted digests or publishers

## File trust flow

Arbitrary files use signed policies and sidecar bundles:

```text
trust-policy.json
     │
     ├── Policy signature anchored by a public key
     ▼
Policy-covered files
     │
     ├── <filename>.bundle
     ▼
scan_project()
     │
     ▼
Allow, warn, audit, or deny decision
```

The scanner does not honor `.gitignore`; coverage is determined solely by policy includes.
It reads covered files and bundles through no-follow regular-file descriptors and verifies
the same bytes used for digest policy decisions.

## Bundle layout

```text
my-plugin/
├── .skill-trust/
│   └── skills/
│       ├── my-skill.sigstore.json
│       └── another-skill.sigstore.json
├── skills/
│   ├── my-skill/
│   │   └── SKILL.md
│   └── another-skill/
│       └── SKILL.md
└── package.json
```

For arbitrary files, bundles are stored as `<filename>.bundle` next to the covered file.

## Trust boundaries

### Cryptographic layer

`SkillSigner` and `SkillVerifier` prove that a bundle is internally consistent, that its
signature is valid, and that its signed manifest matches the observed artifact. Direct
keyless verification fails closed unless identity constraints are supplied.

### Policy layer

`TrustPolicy`, `verify_before_load()`, and `scan_project()` decide whether a verified
publisher is trusted. Policy scanning can enable unconstrained cryptographic verification
only because it applies publisher policy afterward.

### Enforcement layer

Callers must treat a denied or blocked result as fatal. `deny` is the required mode for
production release and agent-startup gates. `warn` and `audit` are transitional or
observability modes.

### Trust configuration

Public Sigstore, Sigstore staging, and RHTAS are selected through explicit trust
configuration. A custom TUF URL may include a pinned bootstrap root. `--staging` and
`--tuf-url` are mutually exclusive to prevent accidental fallback to public trust.
