# Using skill-trust with Red Hat Trusted Artifact Signer

This runbook shows how to use RHTAS as the keyless signing and verification backend for
AI skills and other project files protected by `skill-trust`.

## What RHTAS provides out of the box

RHTAS deploys and operates the Sigstore-compatible backend:

- **Fulcio** — short-lived signing certificates bound to an OIDC identity.
- **Rekor** and Trillian — transparency-log storage and inclusion proofs.
- **TUF** — pinned trust metadata, including the TUF root, trusted root, and signing configuration.
- **TSA** — optional signed timestamps.
- **Keycloak** in the simple quickstart, or your corporate identity provider in production.

RHTAS does **not** know about AI skills, skill manifests, project file policies, or agent
startup enforcement. `skill-trust` supplies those pieces:

- Deterministic skill-directory manifests.
- Per-file and per-skill bundles.
- Signed project trust policies.
- Publisher, issuer, repository, workflow, and ref constraints.
- Pre-execution scanning and deny/warn/audit decisions.

## Prerequisites

- An OpenShift cluster with the RHTAS operator installed and an RHTAS instance ready.
- Permission to read RHTAS custom resources and routes.
- Python 3.12 or newer.
- Network and TLS trust from your workstation or CI runner to the RHTAS routes.
- An OIDC identity accepted by your RHTAS Fulcio configuration.

For an evaluation deployment, the upstream `securesign/quickstarts` simple scenario can
create RHTAS components and a Keycloak realm:

```bash
git clone https://github.com/securesign/quickstarts.git
cd quickstarts/openshift/simple
make deploy-all
```

The quickstart repository is intended for evaluation and may change between RHTAS releases.
For production, install RHTAS through your supported Red Hat installation path and connect
Fulcio to your approved identity provider.

## 1. Discover the RHTAS endpoints

Set the namespace used by your RHTAS instance. The simple quickstart uses `rhtas-simple`:

```bash
export RHTAS_NAMESPACE=rhtas-simple
export TUF_URL="$(oc -n "$RHTAS_NAMESPACE" get tuf -o jsonpath='{.items[0].status.url}')"
export FULCIO_URL="$(oc -n "$RHTAS_NAMESPACE" get fulcio -o jsonpath='{.items[0].status.url}')"
export REKOR_URL="$(oc -n "$RHTAS_NAMESPACE" get rekor -o jsonpath='{.items[0].status.url}')"
export TSA_URL="$(oc -n "$RHTAS_NAMESPACE" get timestampauthorities -o jsonpath='{.items[0].status.url}')"
```

The simple quickstart's Keycloak issuer is:

```bash
export OIDC_ISSUER="https://keycloak-keycloak-system.$(oc get ingress.config.openshift.io cluster -o jsonpath='{.spec.domain}')/auth/realms/trusted-artifact-signer"
```

Use the OIDC issuer configured in your own Fulcio resource for a production deployment.

## 2. Install skill-trust and pin the RHTAS TUF root

From this repository:

```bash
python -m pip install -e .
skill-trust --version
curl -fsSL "$TUF_URL/root.json" -o rhtas-tuf-root.json
```

Treat `rhtas-tuf-root.json` as trust material. Store it in a secure, reproducible location and
do not regenerate it casually. The RHTAS TUF repository must publish the metadata expected by
the Sigstore client, including `trusted_root.json` and `signing_config.v0.2.json`. Current
RHTAS TUF repositories provide this; older deployments may need an upgrade or migration.

## 3. Obtain an OIDC token

For the simple quickstart's Keycloak realm, the example user is `jdoe` with password
`secure`:

```bash
export OIDC_TOKEN="$(curl -fsSL -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=jdoe' \
  -d 'password=secure' \
  -d 'grant_type=password' \
  -d 'scope=openid' \
  -d 'client_id=trusted-artifact-signer' \
  "$OIDC_ISSUER/protocol/openid-connect/token" |
  python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
```

In production, use your approved OIDC client and authentication flow. Never put a user's
OIDC token in source control.

## 4. Smoke-test a skill plugin

Create a small plugin:

```bash
mkdir -p demo-plugin/skills/greeting
cat > demo-plugin/skills/greeting/SKILL.md <<'EOF'
---
name: greeting
description: Greet the user.
---

Greet the user by name.
EOF
```

Sign every skill in the plugin with RHTAS:

```bash
skill-trust sign demo-plugin \
  --tuf-url "$TUF_URL" \
  --tuf-root rhtas-tuf-root.json \
  --identity-token "$OIDC_TOKEN"
```

Verify the plugin and constrain the signer:

```bash
skill-trust verify demo-plugin \
  --identity jdoe@redhat.com \
  --issuer "$OIDC_ISSUER" \
  --tuf-url "$TUF_URL" \
  --tuf-root rhtas-tuf-root.json
```

The bundle is written under `demo-plugin/.skill-trust/skills/`. Commit it with the plugin if
you want consumers to verify the skill before loading it.

## 5. Create a signed project policy for arbitrary files

The project policy declares which files are covered and which RHTAS OIDC publishers are
trusted. The policy itself is signed with a local anchor key; this is separate from the
RHTAS keyless signing key.

Generate a policy anchor key:

```bash
skill-trust trust keygen --key .skill-trust/policy-key.pem
```

Create a starting policy:

```bash
skill-trust trust init \
  --include 'CLAUDE.md' \
  --include 'SKILL.md' \
  --include 'src/**/*.py' \
  --key .skill-trust/policy-key.pem \
  --publisher-name rhtas-keycloak \
  --oidc-issuer "$OIDC_ISSUER" \
  --identity jdoe@redhat.com
```

Replace `--identity jdoe@redhat.com` with the identity accepted by your RHTAS Fulcio
configuration. Omit it when the issuer alone should define the trusted publisher.

For GitHub Actions, constrain the exact repository, workflow, and ref that may sign:

```bash
skill-trust trust init \
  --include 'CLAUDE.md' \
  --include 'SKILL.md' \
  --include 'src/**/*.py' \
  --key .skill-trust/policy-key.pem \
  --publisher-name rhtas-github-actions \
  --oidc-issuer https://token.actions.githubusercontent.com \
  --repository cooktheryan/skill-trust \
  --workflow .github/workflows/sign.yml \
  --ref-pattern refs/heads/main
```

Sign the policy with the local anchor key:

```bash
skill-trust trust sign-policy \
  --policy trust-policy.json \
  --key .skill-trust/policy-key.pem
```

## 6. Sign policy-covered files with RHTAS

Sign every file selected by the policy:

```bash
skill-trust trust sign --all \
  --policy trust-policy.json \
  --tuf-url "$TUF_URL" \
  --tuf-root rhtas-tuf-root.json \
  --identity-token "$OIDC_TOKEN"
```

Each file receives a `<filename>.bundle` sidecar. Commit the signed files, their bundles,
`trust-policy.json`, and `trust-policy.json.keyed.json`. Do not commit the private policy key.

## 7. Verify before an agent starts

Verify every policy-covered file against the signed policy and RHTAS trust root:

```bash
skill-trust trust verify --all \
  --policy trust-policy.json \
  --trust-anchor .skill-trust/policy-key.pem.pub \
  --tuf-url "$TUF_URL" \
  --tuf-root rhtas-tuf-root.json
```

Use the same command as the pre-execution gate in your agent wrapper, CI job, or launcher.
A non-zero exit code means the trust scan failed and the agent should not start.

To list covered files and their current status:

```bash
skill-trust trust list \
  --policy trust-policy.json \
  --trust-anchor .skill-trust/policy-key.pem.pub
```

## 8. Use RHTAS from CI

A CI runner can use ambient OIDC credentials only if your RHTAS Fulcio configuration accepts
that CI issuer and claim format. With ambient credentials configured, omit `--identity-token`:

```bash
skill-trust trust sign --all \
  --policy trust-policy.json \
  --tuf-url "$TUF_URL" \
  --tuf-root rhtas-tuf-root.json
```

For GitHub Actions, request the OIDC token with:

```yaml
permissions:
  id-token: write
  contents: read
```

Then constrain the policy publisher to the exact repository, workflow, and ref that should be
allowed to sign.

## Troubleshooting

- **`No valid Rekor transparency log found in signing config`** — the RHTAS TUF repository
  does not publish `signing_config.v0.2.json`. Upgrade RHTAS or publish the signing
  configuration with its supported tooling.
- **TLS failure** — import the cluster CA into the runner's trust store or use certificates
  issued by a CA already trusted by the runner.
- **Identity verification failure** — compare the bundle identity and issuer with
  `skill-trust inspect`. The policy must use the exact identity and issuer encoded in the
  Fulcio certificate.
- **`--staging` and `--tuf-url` conflict** — custom RHTAS trust and public Sigstore staging
  are intentionally mutually exclusive.
- **Missing bundle** — every file matching `includes` must have a `<filename>.bundle`. The
  scanner intentionally ignores `.gitignore`, so ignored files cannot bypass the policy.
