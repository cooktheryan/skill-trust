"""Integration tests using Sigstore staging infrastructure.

These tests require:
- Internet access (connects to Sigstore staging Fulcio + Rekor)
- Either ambient CI credentials (GitHub Actions OIDC) or interactive browser auth

Run with: pytest -m integration
Skip with: pytest -m "not integration"
"""

import pytest

from skill_trust.manifest import build_manifest
from skill_trust.models import IdentityConstraints
from skill_trust.signer import SkillSigner
from skill_trust.verifier import SkillVerifier


@pytest.mark.integration
class TestSigstoreStagingSignVerify:
    """Full sign/verify round-trip using Sigstore staging infrastructure."""

    def test_sign_and_verify_skill(self, tmp_skill):
        """Sign a skill with Sigstore staging, then verify it."""
        # Sign
        signer = SkillSigner(staging=True)
        result = signer.sign_skill(tmp_skill)

        assert result.bundle_path.exists()
        assert result.manifest.skill_name == "test-skill"
        assert len(result.manifest.files) == 2

        # Verify (no identity constraints — accepts any signer)
        verifier = SkillVerifier(staging=True)
        verify_result = verifier.verify_skill(tmp_skill, result.bundle_path)

        assert verify_result.verified
        assert verify_result.identity is not None
        assert verify_result.error is None

    def test_tampered_skill_fails_verification(self, tmp_skill):
        """Sign a skill, tamper with it, verify that verification fails."""
        signer = SkillSigner(staging=True)
        result = signer.sign_skill(tmp_skill)

        # Tamper
        (tmp_skill / "SKILL.md").write_text("TAMPERED CONTENT")

        # Verify should fail
        verifier = SkillVerifier(staging=True)
        verify_result = verifier.verify_skill(tmp_skill, result.bundle_path)

        assert not verify_result.verified
        assert verify_result.discrepancies
        assert any("modified" in d for d in verify_result.discrepancies)

    def test_sign_plugin_and_verify(self, tmp_path):
        """Sign all skills in a plugin, then verify them."""
        # Create a mini plugin
        plugin_root = tmp_path / "test-plugin"
        skills_dir = plugin_root / "skills"

        for name in ["alpha", "beta"]:
            skill_dir = skills_dir / name
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                f"---\nname: {name}\ndescription: Test.\n---\n\n# {name}\n"
            )

        # Sign all
        signer = SkillSigner(staging=True)
        results = signer.sign_plugin(plugin_root)
        assert len(results) == 2

        # Verify all
        verifier = SkillVerifier(staging=True)
        verify_results = verifier.verify_plugin(plugin_root)

        assert len(verify_results) == 2
        for name, result in verify_results.items():
            assert result.verified, f"{name} failed: {result.error}"

    def test_inspect_bundle_after_signing(self, tmp_skill):
        """Verify that inspect can read signing metadata from a bundle."""
        from sigstore.models import Bundle

        from skill_trust._identity import extract_identity

        signer = SkillSigner(staging=True)
        result = signer.sign_skill(tmp_skill)

        # Load and inspect the bundle
        bundle = Bundle.from_json(result.bundle_path.read_text())
        cert = bundle.signing_certificate
        assert cert is not None

        identity_info = extract_identity(cert)
        assert identity_info["identity"] is not None
        assert identity_info["issuer"] is not None
