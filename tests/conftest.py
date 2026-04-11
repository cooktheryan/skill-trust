"""Shared test fixtures for skill-trust."""

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_skill_path() -> Path:
    return FIXTURES_DIR / "sample-skill"


@pytest.fixture
def tmp_skill(tmp_path: Path) -> Path:
    """Create a temporary copy of the sample skill for mutation tests."""
    skill_dir = tmp_path / "test-skill"
    skill_dir.mkdir()

    (skill_dir / "SKILL.md").write_text(
        "---\nname: test-skill\ndescription: A test skill.\n---\n\n# Test Skill\n\nContent here.\n"
    )
    (skill_dir / "helper.sh").write_bytes(b"#!/bin/bash\necho hello\n")

    return skill_dir


@pytest.fixture
def ec_test_key(tmp_path: Path) -> Path:
    """Generate an EC P-256 private key for testing (no Sigstore needed)."""
    from skill_trust.signer import generate_ec_test_key

    key_path = tmp_path / "test-key.pem"
    return generate_ec_test_key(key_path)
