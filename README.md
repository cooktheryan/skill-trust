# skill-trust

Keyless signing and verification for AI agent skills using [Sigstore](https://sigstore.dev).

## The Problem

AI agent "skills" are markdown files that get injected into LLM context to control behavior. A malicious skill doesn't need to exploit a vulnerability — it simply instructs the LLM to run arbitrary commands, exfiltrate data, or modify files. There is no existing tool to verify the integrity and provenance of these instruction-layer artifacts.

## What skill-trust Does

skill-trust signs skill directories using Sigstore's keyless flow and verifies them before they enter an LLM's context:

1. **Sign** — authenticate via OIDC (GitHub, Google, etc.), get a short-lived certificate from Fulcio, sign a manifest of all skill files, record in Rekor's transparency log
2. **Verify** — cryptographically verify the signature, then compare the signed manifest against the current files on disk to detect any tampering
3. **Gate** — plugin loaders call `verify_before_load()` to block unsigned or tampered skills before they reach the LLM

No long-lived keys to manage. The signer's identity (email, GitHub Actions workflow) is bound to the signature via the transparency log.

## Install

```bash
pip install skill-trust
```

Requires Python 3.12+.

## Quick Start

### Sign a skill (Sigstore keyless — opens browser for OIDC)

```bash
# Sign a single skill directory
skill-trust sign path/to/skills/my-skill/

# Sign all skills in a plugin
skill-trust sign path/to/my-plugin/
```

### Verify a skill

```bash
# Verify a single skill
skill-trust verify path/to/skills/my-skill/

# Verify all skills in a plugin
skill-trust verify path/to/my-plugin/

# Verify with identity constraints
skill-trust verify path/to/my-plugin/ \
  --identity developer@example.com \
  --issuer https://accounts.google.com
```

### Inspect signing metadata

```bash
skill-trust inspect path/to/my-plugin/
```

Output:

```
┌─────────────────────────────────────┐
│ Signature: my-skill                 │
│ Bundle    my-skill.sigstore.json    │
│ Identity  developer@example.com     │
│ Issuer    https://accounts.google.com│
│ Not Before 2026-04-11 12:00:00 UTC  │
│ Not After  2026-04-11 12:10:00 UTC  │
│ Rekor Log Index  12345678           │
└─────────────────────────────────────┘
```

## How It Works

### What Gets Signed

skill-trust signs a **manifest** of all files in a skill directory, not individual files. The manifest contains:

```json
{
  "version": "1.0",
  "skill_name": "brainstorming",
  "root": "brainstorming",
  "files": [
    {"path": "SKILL.md", "sha256": "a1b2c3..."},
    {"path": "guidelines.md", "sha256": "d4e5f6..."}
  ],
  "root_digest": "7890ab...",
  "hash_algorithm": "sha256",
  "created_at": "2026-04-11T12:00:00+00:00"
}
```

The `root_digest` is computed from all file hashes and used as the DSSE subject — a single hash that represents the entire skill directory state.

### Signing Flow

```
┌─────────┐    ┌────────┐    ┌───────┐    ┌───────┐
│  Build   │───>│  Sign   │───>│ Fulcio│───>│ Rekor │
│ manifest │    │  DSSE   │    │  cert │    │  log  │
└─────────┘    └────────┘    └───────┘    └───────┘
     │              │              │            │
  SHA-256      in-toto        short-lived   immutable
  all files    statement      OIDC cert     record
```

1. Walk the skill directory, hash every file (SHA-256), build a deterministic manifest
2. Compute root digest from sorted file hashes
3. Create an [in-toto](https://in-toto.io/) DSSE attestation with the manifest as predicate
4. Authenticate via OIDC (Sigstore keyless — no keys to manage)
5. Get a short-lived certificate from [Fulcio](https://docs.sigstore.dev/certificate_authority/overview/) binding your identity to an ephemeral key
6. Sign the DSSE statement and record in [Rekor](https://docs.sigstore.dev/logging/overview/) transparency log
7. Write the `.sigstore.json` bundle to `.skill-trust/skills/`

### Verification Flow

```
┌──────────┐    ┌─────────┐    ┌──────────┐    ┌──────┐
│  Load     │───>│ Verify  │───>│ Re-hash  │───>│ Diff │
│  bundle   │    │  DSSE   │    │  disk    │    │      │
└──────────┘    └─────────┘    └──────────┘    └──────┘
     │               │              │              │
  .sigstore     signature      current         tampering
  .json         + identity     file state      detection
```

1. Load the `.sigstore.json` bundle
2. Verify the DSSE signature cryptographically (Fulcio cert + Rekor timestamp)
3. Extract the signed manifest from the authenticated payload
4. Re-hash all files on disk to build a current manifest
5. Compare signed vs current — any discrepancy = tampering detected

### Bundle Storage

```
my-plugin/
├── .skill-trust/
│   └── skills/
│       ├── brainstorming.sigstore.json
│       └── debugging.sigstore.json
├── skills/
│   ├── brainstorming/
│   │   └── SKILL.md
│   └── debugging/
│       ├── SKILL.md
│       └── find-polluter.sh
└── package.json
```

## Plugin Loader Integration

The verification gate is designed to be called by plugin loaders before injecting skill content into an LLM conversation:

```python
from skill_trust.gate import verify_before_load
from skill_trust.policy import TrustPolicy

policy = TrustPolicy(
    require_signature=True,
    trusted_identities=["developer@example.com"],
    trusted_issuers=["https://accounts.google.com"],
    mode="enforce",  # or "warn"
)

result = verify_before_load(
    skill_path="skills/brainstorming",
    plugin_root="my-plugin/",
    policy=policy,
)

if result.blocked:
    print(f"Skill blocked: {result.reason}")
else:
    # Safe to load the skill into LLM context
    skill_content = (skill_path / "SKILL.md").read_text()
```

### Trust Policy

Policies can be loaded from JSON files:

```json
{
  "require_signature": true,
  "trusted_identities": ["dev@example.com", "ci@github.com"],
  "trusted_issuers": ["https://accounts.google.com", "https://token.actions.githubusercontent.com"],
  "mode": "enforce"
}
```

| Mode | Behavior |
|------|----------|
| `enforce` | Block unsigned/tampered/untrusted skills |
| `warn` | Allow loading but populate `result.warnings` list |

## Signing in CI (GitHub Actions)

```yaml
permissions:
  id-token: write  # Required for Sigstore OIDC

steps:
  - uses: actions/checkout@v4
  - run: pip install skill-trust
  - run: skill-trust sign path/to/plugin/
```

GitHub Actions provides ambient OIDC credentials automatically when `id-token: write` is set. No secrets or keys needed.

## Testing

### Run unit tests (no internet needed)

```bash
pip install -e ".[dev]"
pytest -m "not integration"
```

Unit tests use EC P-256 keys for signing (following [model-transparency](https://github.com/sigstore/model-transparency)'s testing pattern). No Sigstore infrastructure required.

### Run integration tests (Sigstore staging)

```bash
pytest -m integration
```

Integration tests hit Sigstore's staging Fulcio and Rekor. They require internet access and OIDC authentication (interactive or CI ambient).

### Run the demo

```bash
# EC key demo (offline, no Sigstore)
python examples/demo_ec_signing.py

# Sigstore staging demo (opens browser for OIDC)
python examples/demo_sigstore_staging.py

# Plugin loader integration demo
python examples/demo_plugin_loader.py
```

## Architecture

```
src/skill_trust/
├── models.py       # Manifest, FileEntry, VerificationResult, IdentityConstraints
├── manifest.py     # Deterministic directory hashing (parallel ThreadPoolExecutor)
├── signer.py       # SkillSigner (Sigstore keyless) + EC key generation
├── verifier.py     # SkillVerifier (DSSE verify + manifest diff)
├── gate.py         # verify_before_load() — plugin loader integration
├── policy.py       # TrustPolicy (enforce/warn, identity/issuer constraints)
├── _canonical.py   # Deterministic JSON serialization
├── _identity.py    # X.509 certificate identity extraction
└── cli/            # skill-trust sign/verify/inspect commands
```

### Design Decisions

| Decision | Rationale |
|----------|-----------|
| DSSE attestations over raw blob signing | Structured, self-describing payloads with predicate types; extensible (provenance, SBOM) |
| Directory-level manifests | One manifest per skill; avoids N separate OIDC flows; detects any file tampering |
| Root digest as DSSE subject | Single hash from sorted file digests (model-transparency pattern); simple artifact reference |
| Serialization metadata in predicate | Hash algorithm and version recorded for reproducibility (model-transparency pattern) |
| Separate crypto from policy | Verifier proves identity; gate/policy decides trust (same pattern as sigstore-a2a) |
| EC key signing for tests | Offline testing without Sigstore infrastructure (model-transparency pattern) |

## Security

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Malicious skill injection | Signature verification blocks unsigned skills |
| Skill content tampering | Manifest diff detects any file modification, addition, or removal |
| Impersonation (wrong signer) | Identity constraints verify OIDC identity + issuer |
| Replay (old bundle on new files) | Manifest comparison fails if files changed |
| Transplant (bundle from skill A on skill B) | Skill name verified in both DSSE subject and manifest diff |
| Symlink attacks | Symlinks skipped; resolved paths verified within skill directory |
| Path traversal | Skill names validated; `..` components rejected |

### Known Limitations

- **TOCTOU**: Files can change between verification and loading. For maximum security, verify at load time, not just install time.
- **Warn mode**: Allows untrusted skills while populating `warnings`. Monitor warnings in production.
- **UnsafeNoOp fallback**: When no identity constraints are provided, any valid Sigstore signer is accepted. Always configure identity constraints in production.

## Related Projects

| Project | What it signs | How skill-trust differs |
|---------|--------------|------------------------|
| [sigstore-a2a](https://github.com/sigstore/sigstore-a2a) | A2A Agent Cards | Signs agent identity, not instruction content |
| [model-transparency](https://github.com/sigstore/model-transparency) | ML model files | Signs model weights, not prompt-level instructions |
| [cosign](https://docs.sigstore.dev/cosign/overview/) | Container images, blobs | Generic primitive; no skill-aware manifest or policy |

## License

Apache 2.0
