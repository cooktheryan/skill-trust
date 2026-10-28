# skill-trust

`skill-trust` signs and verifies AI agent skills and other instruction-layer files so
agents load only content from trusted publishers. It supports Sigstore keyless signing,
keyed ECDSA P-256 signing, Red Hat Trusted Artifact Signer (RHTAS), signed project
policies, and pre-execution trust gates.

## Why It Exists

Agent skills are instructions injected into an LLM's context. A malicious or modified
skill can therefore change agent behavior without exploiting an application vulnerability.
`skill-trust` establishes provenance and integrity for those instructions:

1. Build a deterministic manifest for a skill directory.
2. Sign the manifest with a Sigstore keyless identity or an ECDSA P-256 key.
3. Verify the signature and compare the signed manifest with the files on disk.
4. Apply a policy that decides which publishers, repositories, workflows, refs, and digests
   are trusted.
5. Block loading or execution when verification fails.

## Installation

```bash
python -m pip install skill-trust
```

Python 3.12 or newer is required.

## Quick Start

Sign all skills in a plugin:

```bash
skill-trust sign path/to/my-plugin/
```

Verify the plugin and constrain the accepted keyless signer:

```bash
skill-trust verify path/to/my-plugin/ \
  --identity developer@example.com \
  --issuer https://accounts.google.com
```

Keyless verification fails closed unless identity constraints or a signed trust policy is
supplied. Keyed bundles carry their public key and can be verified directly.

Inspect a signed plugin:

```bash
skill-trust inspect path/to/my-plugin/
```

## Integration

### Plugin loader gate

Call `verify_before_load()` before injecting a skill into an LLM context:

```python
from pathlib import Path

from skill_trust.gate import verify_before_load
from skill_trust.policy import TrustPolicy

policy = TrustPolicy.from_dict({
    "publishers": [{
        "identity": "developer@example.com",
        "issuer": "https://accounts.google.com",
    }],
    "enforcement": "deny",
})

skill_path = Path("path/to/my-plugin/skills/my-skill")
result = verify_before_load(
    skill_path=skill_path,
    plugin_root=skill_path.parent.parent,
    policy=policy,
)

if result.blocked:
    raise RuntimeError(f"Skill blocked: {result.reason}")

skill_content = (skill_path / "SKILL.md").read_text()
```

### Pre-execution file scan

For arbitrary instruction, configuration, and script files, create a signed policy and scan
all covered files before starting an agent or command:

```python
from pathlib import Path

from skill_trust.policy import TrustPolicy
from skill_trust.scan import preexec_verify
from skill_trust.verifier import SkillVerifier

project_root = Path(".")
policy = TrustPolicy.from_file(project_root / "trust-policy.json")

report = preexec_verify(
    project_root,
    policy,
    SkillVerifier(allow_unconstrained_identity=True),
)
if not report.allowed:
    raise RuntimeError("trust scan failed")
```

The policy scanner explicitly allows unconstrained cryptographic verification because it
applies publisher policy after signature verification. Direct `SkillVerifier` use remains
fail-closed.

### CLI trust workflow

```bash
skill-trust trust keygen --key .skill-trust/policy-key.pem

skill-trust trust init \
  --include "SKILL.md" \
  --include "CLAUDE.md" \
  --include "src/**/*.py" \
  --key .skill-trust/policy-key.pem

skill-trust trust sign-policy \
  --policy trust-policy.json \
  --key .skill-trust/policy-key.pem

skill-trust trust sign --all \
  --policy trust-policy.json \
  --key .skill-trust/policy-key.pem

skill-trust trust verify --all \
  --policy trust-policy.json \
  --trust-anchor .skill-trust/policy-key.pem.pub
```

### Red Hat Trusted Artifact Signer

RHTAS provides Fulcio, Rekor, TUF, an optional TSA, and an OIDC identity provider.
`skill-trust` adds skill manifests, trust policies, publisher constraints, and agent-facing
enforcement. See the [RHTAS runbook](docs/rhtas.md) for endpoint discovery, token
acquisition, signing, policy setup, and verification.

The repository includes a live RHTAS CI workflow at
`.github/workflows/rhtas-ci.yml`.

## Documentation

| Guide | Purpose |
|-------|---------|
| [Testing](docs/testing.md) | Run unit, integration, static, package, and CLI checks |
| [Signing in CI](docs/ci-signing.md) | Sign and verify skills with GitHub Actions and RHTAS |
| [Architecture](docs/architecture.md) | Components, data flows, and trust boundaries |
| [Design decisions](docs/design-decisions.md) | Rationale for manifests, DSSE, policies, and enforcement |
| [Security](docs/security.md) | Threat model, guarantees, limitations, and hardening guidance |
| [RHTAS runbook](docs/rhtas.md) | End-to-end Red Hat Trusted Artifact Signer workflow |

## Related Projects

- [sigstore-a2a](https://github.com/sigstore/sigstore-a2a) signs agent identity cards, not instruction content.
- [model-transparency](https://github.com/sigstore/model-transparency) signs ML model artifacts.
- [Cosign](https://docs.sigstore.dev/cosign/overview/) signs blobs and OCI artifacts, but does not provide skill-aware manifests or policies.

## License

Apache 2.0
