# Signing in CI

This guide shows how to sign and verify agent skills from CI. The examples use GitHub
Actions; the same model works with any CI system that can provide an OIDC identity
accepted by Fulcio or RHTAS.

## GitHub Actions keyless signing

```yaml
name: Sign skills

on:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: python -m pip install skill-trust

      - run: skill-trust sign path/to/my-plugin/
```

`id-token: write` allows GitHub Actions to request the ambient OIDC token used by Sigstore
keyless signing. No private signing key or long-lived token is required.

## Verify in CI

Constrain verification to the signer accepted by your trust policy:

```yaml
- run: |
    skill-trust verify path/to/my-plugin/ \
      --identity "$GITHUB_ACTOR" \
      --issuer https://token.actions.githubusercontent.com
```

For stronger workflow and ref constraints, use a signed trust policy with a GitHub
publisher:

```json
{
  "includes": ["SKILL.md", "src/**/*.py"],
  "publishers": [{
    "name": "github-ci",
    "issuer": "https://token.actions.githubusercontent.com",
    "repository": "cooktheryan/skill-trust",
    "workflow": ".github/workflows/sign.yml",
    "ref_pattern": "refs/heads/main"
  }],
  "enforcement": "deny"
}
```

Then run:

```bash
skill-trust trust verify --all \
  --policy trust-policy.json \
  --trust-anchor .skill-trust/policy-key.pem.pub
```

## Committing bundles

For source repositories, commit:

- Skill directories
- `.skill-trust/skills/*.sigstore.json` skill bundles
- `trust-policy.json`
- `trust-policy.json.keyed.json`
- File bundles for policy-covered files

Do not commit:

- Private policy-anchor keys
- OIDC tokens
- RHTAS credentials

For release artifacts, publish bundles alongside the artifact and verify them in a separate
consumer job or workflow.

## RHTAS in CI

When using RHTAS, supply the deployment's TUF URL and pinned TUF root:

```bash
skill-trust sign path/to/my-plugin/ \
  --tuf-url "$TUF_URL" \
  --tuf-root rhtas-tuf-root.json
```

Use the same trust configuration during verification. See the
[RHTAS runbook](rhtas.md) for endpoint discovery, token acquisition, and policy setup.

This repository also includes a complete RHTAS CI workflow at
`.github/workflows/rhtas-ci.yml`. It signs and verifies a demo skill and a policy-covered
file using GitHub Actions OIDC, the RHTAS TUF root, and a signed project policy.

## CI hardening

- Request the minimum token permissions required by each job.
- Require protected branches and passing verification before merge.
- Pin the TUF bootstrap root for reproducible trust configuration.
- Constrain the repository, workflow, and ref in the trust policy.
- Treat verification failure as fatal; do not use `warn` or `audit` for release gates.
