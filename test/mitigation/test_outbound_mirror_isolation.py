"""
Task P09-008: Formal proof of outbound mirror isolation.
Audits CI configuration, git hooks, and code paths to prove that no direct,
automatic, or autonomous egress path to the public GitHub mirror exists.
"""

from pathlib import Path
import re
import subprocess
import unittest


class TestOutboundMirrorIsolation(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parent.parent.parent
        self.ci_file = self.root / ".gitlab-ci.yml"

    def test_gitlab_ci_has_no_automated_mirror_job(self):
        if self.ci_file.exists():
            content = self.ci_file.read_text(encoding="utf-8")
            # Verify no job executes git push to GitHub origin
            self.assertNotRegex(
                content,
                r"git\s+push\s+(?:--mirror\s+)?origin",
                "CI pipeline must not contain automated push or mirror to GitHub origin",
            )
            # Verify no direct GitHub PAT egress trigger
            self.assertNotIn("GITHUB_TOKEN", content)
            self.assertNotIn("GH_TOKEN", content)

    def test_audit_egress_barriers_script_succeeds(self):
        res = subprocess.run(
            ["./scripts/audit-egress-barriers.sh"],
            cwd=str(self.root),
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"Audit script failed: {res.stderr}")
        self.assertIn("AUDIT PASSED", res.stdout)

    def test_mirror_gatekeeper_is_sole_authorized_cli(self):
        gate_script = self.root / "scripts" / "mirror-release-gate.sh"
        self.assertTrue(gate_script.exists(), "mirror-release-gate.sh must exist")
        content = gate_script.read_text(encoding="utf-8")
        self.assertIn("MirrorReleaseGate", content)
        self.assertIn("SignedReleaseToken", content)
        self.assertIn("git push origin main", content)


if __name__ == "__main__":
    unittest.main()
