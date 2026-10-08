import unittest
from src.storage.attack_path_graph import (
    AttackPathGraph,
    list_attack_paths,
    plan_remediation,
)


class TestAttackPathGraph(unittest.TestCase):
    def setUp(self):
        self.apg = AttackPathGraph()

    def test_dag_invariant_cycle_rejection(self):
        self.apg.graph.add_node("A")
        self.apg.graph.add_node("B")
        self.apg.graph.add_node("C")

        self.assertTrue(self.apg.add_attack_step("A", "B"))
        self.assertTrue(self.apg.add_attack_step("B", "C"))
        # Adding C -> A would create a cycle; must be rejected
        self.assertFalse(self.apg.add_attack_step("C", "A"))
        self.assertFalse(self.apg.graph.has_edge("C", "A"))

    def test_build_from_findings_and_list_paths(self):
        findings = [
            {
                "id": "FINDING-SLITHER-0001",
                "severity": "CRITICAL",
                "title": "arbitrary-send-erc20",
                "target": "VulnerableVault",
                "dread": {"score": 8.9},
            },
            {
                "id": "FINDING-MYTHRIL-0002",
                "severity": "HIGH",
                "title": "SWC-107",
                "target": "VulnerableVault",
                "dread": {"score": 7.5},
            },
        ]
        self.apg.build_from_findings(findings)
        paths = self.apg.list_attack_paths()

        self.assertGreaterEqual(len(paths), 2)
        for p in paths:
            self.assertEqual(p["entry"], "ENTRY:external_attacker")
            self.assertEqual(p["target"], "TARGET:VulnerableVault")
            self.assertGreater(p["cumulative_weight"], 0)
            self.assertGreater(p["average_dread"], 0)

    def test_plan_remediation_valid_path(self):
        findings = [
            {
                "id": "FINDING-SLITHER-0001",
                "severity": "CRITICAL",
                "title": "arbitrary-send-erc20",
                "target": "VulnerableVault",
                "dread": {"score": 8.9},
            }
        ]
        self.apg.build_from_findings(findings)
        paths = self.apg.list_attack_paths()
        self.assertTrue(len(paths) > 0)

        path_id = paths[0]["path_id"]
        plan = self.apg.plan_remediation(path_id)
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(plan["remediation_count"], 1)
        self.assertIn("VulnerableVault", plan["target"])

    def test_plan_remediation_nonexistent_path(self):
        plan = self.apg.plan_remediation("NONEXISTENT-PATH")
        self.assertEqual(plan["status"], "not_found")
        self.assertEqual(plan["remediations"], [])

    def test_module_level_helpers(self):
        # Verify module-level exports execute safely
        paths = list_attack_paths()
        self.assertIsInstance(paths, list)
        plan = plan_remediation("DUMMY")
        self.assertEqual(plan["status"], "not_found")


if __name__ == "__main__":
    unittest.main()
