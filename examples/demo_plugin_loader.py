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

from skill_trust.gate import verify_before_load
from skill_trust.policy import TrustPolicy


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

        # ── Create a plugin without Sigstore bundles ──────────────
        plugin_root = tmp_path / "my-plugin"
        skills_dir = plugin_root / "skills"

        for skill_name in ["drafting", "research"]:
            skill_dir = skills_dir / skill_name
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                f"---\nname: {skill_name}\ndescription: Demo skill.\n---\n\n"
                f"# {skill_name.title()}\n\nThis skill has no Sigstore bundle.\n"
            )

        print("\nCreated plugin with 2 skills and no Sigstore bundles")

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
