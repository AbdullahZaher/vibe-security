"""Minimal stdlib-only checks of portable Agent Skills conventions."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TestSkillContract(unittest.TestCase):
    def test_name_and_description(self):
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(skill.startswith("---\n"))
        header = skill.split("---", 2)[1]
        self.assertRegex(header, r"(?m)^name: prelaunch-security-audit$")
        self.assertRegex(header, r"(?m)^description: >-$")
        self.assertIn("Review and harden", header)
        self.assertEqual(ROOT.name, "prelaunch-security-audit")

    def test_required_references_exist(self):
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        for ref in re.findall(r"\]\((references/[^)]+)\)", skill):
            self.assertTrue((ROOT / ref).is_file(), ref)
        self.assertTrue((ROOT / "assets/findings.schema.json").is_file())

    def test_mcp_adapter_does_not_shadow_sdk(self):
        self.assertFalse((ROOT / "mcp" / "server.py").exists())
        self.assertTrue((ROOT / "mcp_adapter" / "server.py").exists())

    def test_adaptive_guidance_and_offline_migration_helper(self):
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        controls = (ROOT / "references/security-controls.md").read_text(encoding="utf-8")
        playbooks = (ROOT / "references/stack-playbooks.md").read_text(encoding="utf-8")
        self.assertIn("Adaptive attack-surface discovery", skill)
        self.assertIn("Authorized next", skill)
        self.assertIn("0.0.0.0", controls)
        self.assertIn("script-src-elem", controls)
        self.assertIn("migration_parity.py", playbooks)
        self.assertTrue((ROOT / "scripts/migration_parity.py").is_file())

    def test_27_controls_are_sequential(self):
        text = (ROOT / "references/security-controls.md").read_text(encoding="utf-8")
        control_ids = re.findall(r"(?m)^## (\d\d) —", text)
        self.assertEqual(control_ids, [f"{x:02d}" for x in range(1, 28)])


if __name__ == "__main__":
    unittest.main()
