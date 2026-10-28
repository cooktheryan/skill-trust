# Using skill-trust with Red Hat Trusted Artifact Signer

This runbook deploys RHTAS 1.5 on OpenShift, configures it for GitHub Actions OIDC, pins
its TUF root, and runs `skill-trust` signing and verification in CI.

## What RHTAS provides

RHTAS operates the Sigstore-compatible backend:

- **Fulcio** issues short-lived certificates bound to an OIDC identity.
- **Rekor** and Trillian provide transparency-log storage and inclusion proofs.
- **TUF** publishes the trust root, trusted root, and signing configuration.
- **TSA** provides optional signed timestamps.

RHTAS does not provide AI-skill manifests, project file policies, publisher constraints, or
agent startup enforcement. `skill-trust` supplies those layers.

## 1. Install the RHTAS operator

Install Red Hat Trusted Artifact Signer 1.5 from Red Hat OperatorHub using the `stable`
channel. The operator normally lives in `openshift-rhtas-operator`.

If installing with the OpenShift CLI, create a subscription equivalent to:

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: rhtas-operator
  namespace: openshift-rhtas-operator
spec:
  channel: stable
  installPlanApproval: Automatic
  name: rhtas-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
  startingCSV: rhtas-operator.v1.5.0
```

Wait for the operator deployment:

```bash
oc -n openshift-rhtas-operator wait \
  --for=condition=Available \
  deployment/rhtas-operator-controller-manager \
  --timeout=10m
```

Confirm the installed version:

```bash
oc -n openshift-rhtas-operator get csv \
  -l operators.coreos.com/rhtas-operator.openshift-rhtas-operator=""
```

## 2. Create a RHTAS instance for GitHub Actions

Create a dedicated namespace:

```bash
oc create namespace skill-trust-rhtas
```

Apply the example `Securesign` resource:

```bash
oc apply -n skill-trust-rhtas \
  -f examples/rhtas-securesign-github-actions.yaml
```

The manifest configures Fulcio to accept GitHub Actions OIDC:

```yaml
oidcIssuers:
  - issuer: https://token.actions.githubusercontent.com
    issuerURL: https://token.actions.githubusercontent.com
    clientID: sigstore
    type: github-workflow
```

Wait for all RHTAS components:

```bash
oc wait -n skill-trust-rhtas securesign/skill-trust \
  --for=condition=Ready \
  --timeout=10m
```

Inspect the resulting endpoints:

```bash
oc -n skill-trust-rhtas get securesign skill-trust -o wide
```

The status provides URLs for Fulcio, Rekor, TSA, and TUF.

## 3. Pin the TUF bootstrap root

Set the TUF URL from the `Securesign` status:

```bash
export TUF_URL="$(oc -n skill-trust-rhtas get securesign skill-trust \
  -o jsonpath='{.status.tuf.url}')"
```

Download and pin the bootstrap root:

```bash
curl -fsSL "$TUF_URL/root.json" \
  -o trust/rhtas/root.json
```

In RHTAS 1.5, `root.json` is available at that direct path. The trusted-root and
signing-config targets are content-addressed below `/targets/`; do not try to download them
by their logical filenames. The Sigstore TUF client resolves those targets from signed TUF
metadata automatically.

Validate that the pinned root resolves the RHTAS services:

```python
import os
from pathlib import Path

from sigstore.models import ClientTrustConfig

config = ClientTrustConfig.from_tuf(
    os.environ["TUF_URL"],
    bootstrap_root=Path("trust/rhtas/root.json"),
)
assert config.signing_config.get_oidc_url() == "https://token.actions.githubusercontent.com"
```

The resolved configuration also contains the RHTAS Fulcio, Rekor, and TSA URLs.

## 4. Create the CI trust policy

The repository contains a signed policy for a small demo skill:

- `trust-policy.json`
- `trust-policy.json.keyed.json`
- `trust/rhtas/policy-key.pub`

The policy trusts GitHub Actions signatures only when the certificate claims match:

- Issuer: `https://token.actions.githubusercontent.com`
- Repository: `cooktheryan/skill-trust`
- Workflow: `.github/workflows/rhtas-ci.yml`
- Ref: `refs/heads/main`

The public anchor key is committed. The corresponding private key is not committed and
must be stored securely. To rotate the anchor, generate a new key, update the policy, sign
it with the new key, and replace the public anchor.

## 5. Run RHTAS CI validation

The repository includes `.github/workflows/rhtas-ci.yml`. It:

1. Installs `skill-trust`.
2. Signs `examples/rhtas-demo-plugin` with RHTAS keyless signing.
3. Verifies the skill through `verify_before_load()` and the RHTAS TUF root.
4. Signs the policy-covered `SKILL.md` file.
5. Verifies the policy-covered file through `trust verify`.

The order matters: adding a `<filename>.bundle` sidecar inside a skill directory after the
skill manifest is signed changes the skill's file set. Verify the skill before generating
file sidecars, or keep policy-covered files outside signed skill directories.

Configure the repository variable:

```bash
gh variable set RHTAS_TUF_URL \
  --repo cooktheryan/skill-trust \
  --body "$TUF_URL"
```

Run the validation manually:

```bash
gh workflow run rhtas-ci.yml \
  --repo cooktheryan/skill-trust \
  --ref main
```

Watch the result:

```bash
gh run watch \
  --repo cooktheryan/skill-trust \
  $(gh run list --repo cooktheryan/skill-trust \
    --workflow rhtas-ci.yml \
    --limit 1 \
    --json databaseId \
    --jq '.[0].databaseId')
```

## 6. Use RHTAS for your own files

Create or edit a policy with a GitHub publisher:

```bash
skill-trust trust init \
  --include 'SKILL.md' \
  --include 'src/**/*.py' \
  --key .skill-trust/policy-key.pem \
  --publisher-name rhtas-github-actions \
  --oidc-issuer https://token.actions.githubusercontent.com \
  --repository cooktheryan/skill-trust \
  --workflow .github/workflows/sign.yml \
  --ref-pattern refs/heads/main
```

Sign and verify policy-covered files from CI:

```bash
skill-trust trust sign --all \
  --policy trust-policy.json \
  --tuf-url "$TUF_URL" \
  --tuf-root trust/rhtas/root.json

skill-trust trust verify --all \
  --policy trust-policy.json \
  --trust-anchor trust/rhtas/policy-key.pub \
  --tuf-url "$TUF_URL" \
  --tuf-root trust/rhtas/root.json
```

GitHub Actions supplies the OIDC token automatically when the job has:

```yaml
permissions:
  contents: read
  id-token: write
```

## 7. Use a human OIDC issuer

The example deployment accepts GitHub Actions only. To sign interactively as a person,
configure Fulcio with an email issuer such as Keycloak or your corporate identity provider,
then pass the token explicitly:

```bash
skill-trust sign path/to/plugin \
  --tuf-url "$TUF_URL" \
  --tuf-root trust/rhtas/root.json \
  --identity-token "$OIDC_TOKEN"
```

Use the same TUF URL and root for verification, and constrain the accepted identity and
issuer in the trust policy.

## Troubleshooting

### Operator is installed but no endpoints exist

The operator is only the controller. Create a `Securesign` instance and wait for its
`Ready` condition.

### `trusted_root.json` returns 404

This is expected on RHTAS 1.5 when requesting the logical filename directly. The target is
published with a content-addressed filename below `/targets/`. Let the Sigstore TUF client
resolve it.

### GitHub OIDC is rejected

Confirm that Fulcio contains both the GitHub `issuer` and matching `issuerURL`, the
workflow has `id-token: write`, and the trust policy matches the exact repository,
workflow path, and ref.

### Verification cannot reach RHTAS

Confirm network and TLS trust from the runner to the RHTAS routes. For private routes,
configure runner network access or expose the services through an approved ingress.

### Older RHTAS deployments

Older deployments may not publish a signing configuration compatible with current Python
Sigstore clients. Upgrade RHTAS or publish the required TUF targets with supported RHTAS
tooling.
