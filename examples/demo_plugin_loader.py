#!/usr/bin/env python3
"""Demo: Integrating skill-trust into a plugin loader.

This shows how a plugin framework (like Claude Code's superpowers plugin)
would use skill-trust's verification gate to check skills before loading
them into an LLM's context.

Usage:
    python examples/demo_plugin_loader.py
"""

import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from skill_trust.gate import verify_before_load
from skill_trust.manifest import build_manifest
from skill_trust.policy import TrustPolicy
from skill_trust.signer import generate_ec_test_key


def simulate_plugin_loader(plugin_root: Path, policy: TrustPolicy) -> None:
    """Simulate a plugin loader that verifies skills before injection."""
    skills_dir = plugin_root / "skills"

    print(f"\nPlugin loader scanning: {plugin_root.name}")
    print(f"Policy: require_signature={policy.require_signature}, mode={policy.mode}")
    print("-" * 50)

    for skill_dir in sorted(skills_dir.iterdir()):
        if not skill_dir.is_dir():
            continue

        result = verify_before_load(skill_dir, plugin_root, policy)

        if result.allowed:
            if result.warnings:
                print(f"  WARN  {result.skill_name}: {result.warnings[0]}")
            else:
                print(f"  LOAD  {result.skill_name}: {result.reason}")

            # In a real loader, you'd now read and inject the skill:
            # skill_content = (skill_dir / "SKILL.md").read_text()
            # inject_into_context(skill_content)
        else:
            print(f"  BLOCK {result.skill_name}: {result.reason}")


def main() -> None:
    print("=" * 60)
    print("skill-trust Demo: Plugin Loader Integration")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        # ── Create a plugin with signed and unsigned skills ───────
        plugin_root = tmp_path / "my-plugin"
        skills_dir = plugin_root / "skills"

        # Signed skill
        signed_skill = skills_dir / "signed-skill"
        signed_skill.mkdir(parents=True)
        (signed_skill / "SKILL.md").write_text(
            "---\nname: signed-skill\ndescription: A properly signed skill.\n---\n\n"
            "# Signed Skill\n\nThis skill is signed and verified.\n"
        )

        # Unsigned skill
        unsigned_skill = skills_dir / "unsigned-skill"
        unsigned_skill.mkdir(parents=True)
        (unsigned_skill / "SKILL.md").write_text(
            "---\nname: unsigned-skill\ndescription: An unsigned skill.\n---\n\n"
            "# Unsigned Skill\n\nThis skill has no signature.\n"
        )

        # Sign only the first skill (using EC key for demo)
        key_path = tmp_path / "key.pem"
        generate_ec_test_key(key_path)
        private_key = load_pem_private_key(key_path.read_bytes(), password=None)

        manifest = build_manifest(signed_skill)
        canonical = json.dumps(manifest.to_dict(), sort_keys=True, separators=(",", ":")).encode()
        signature = private_key.sign(canonical, ec.ECDSA(SHA256()))

        sig_dir = plugin_root / ".skill-trust" / "skills"
        sig_dir.mkdir(parents=True)
        (sig_dir / "signed-skill.manifest.json").write_text(
            json.dumps(manifest.to_dict(), indent=2)
        )

        print("\nCreated plugin with 2 skills (1 signed, 1 unsigned)")

        # ── Scenario 1: Enforce mode ──────────────────────────────
        print("\n--- Scenario 1: Enforce mode (strict) ---")
        policy = TrustPolicy(require_signature=True, mode="enforce")
        simulate_plugin_loader(plugin_root, policy)

        # ── Scenario 2: Warn mode ────────────────────────────────
        print("\n--- Scenario 2: Warn mode (permissive) ---")
        policy = TrustPolicy(require_signature=True, mode="warn")
        simulate_plugin_loader(plugin_root, policy)

        # ── Scenario 3: Signatures not required ──────────────────
        print("\n--- Scenario 3: No signatures required ---")
        policy = TrustPolicy(require_signature=False)
        simulate_plugin_loader(plugin_root, policy)

        # ── Scenario 4: Policy from file ─────────────────────────
        print("\n--- Scenario 4: Policy loaded from JSON file ---")
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(json.dumps({
            "require_signature": True,
            "trusted_identities": ["developer@example.com"],
            "trusted_issuers": ["https://accounts.google.com"],
            "mode": "enforce",
        }, indent=2))
        print(f"  Policy file: {policy_file.name}")
        print(f"  Contents: {policy_file.read_text()}")
        policy = TrustPolicy.from_file(policy_file)
        simulate_plugin_loader(plugin_root, policy)

        print("\n" + "=" * 60)
        print("Demo complete. Shows enforce/warn/disabled policy modes.")
        print("=" * 60)


if __name__ == "__main__":
    main()
