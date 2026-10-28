# Testing

This guide describes the local and CI validation used by `skill-trust`.

## Unit tests

Unit tests are offline and use ECDSA P-256 keys for signing and verification. They do not
contact Fulcio, Rekor, or an OIDC provider.

```bash
python -m pip install -e ".[dev]"
python -m pytest -m "not integration"
```

The suite covers:

- Deterministic skill manifests and root digests
- Keyed and keyless bundle parsing
- Signature and manifest tamper detection
- Trust-policy parsing, composition, and publisher matching
- Pre-execution scanning and deny behavior
- CLI signing, verification, listing, and inspection
- Plugin-loader gate behavior

## Sigstore staging integration tests

Integration tests exercise real Fulcio and Rekor staging services. They require network
access and an OIDC credential. GitHub Actions supplies ambient OIDC credentials; local runs
may open a browser.

```bash
python -m pytest -m integration
```

## Static analysis

The project uses read-only Ruff checks for undefined names and similar errors:

```bash
ruff check --select F src tests
```

Do not run the obsolete locally installed Ruff formatter; old preview builds can corrupt
Python source files.

## Package and CLI smoke tests

Build a wheel and verify that the package and CLI entry point are present:

```bash
python -m pip wheel . --no-deps -w /tmp/skill-trust-wheel
skill-trust --version
skill-trust trust --help
```

## CI validation

GitHub Actions runs:

- Unit tests on Python 3.12 and 3.13
- Sigstore staging integration tests on Python 3.12
- RHTAS integration tests against the deployment documented in [rhtas.md](rhtas.md)

Both workflows must pass before a change on `main` is considered validated.

## Test principles

- Unit tests must not require internet access or interactive authentication.
- Integration tests must be explicitly marked `integration` so they can be deselected.
- Security changes require negative tests for tampering, path traversal, untrusted
  publishers, malformed input, and policy bypass attempts.
- CLI changes require command-level tests through Click's test runner.
