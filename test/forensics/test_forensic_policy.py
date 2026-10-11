"""
Task P10B-001: Unit tests for Forensic OPA Policy.
Validates operator authorization, agent least-privilege read boundaries,
universal mutation/deletion rejection, and fail-closed default deny.
"""

from pathlib import Path
import unittest

from src.forensics.policy_evaluator import ForensicPolicyEvaluator


class TestForensicPolicy(unittest.TestCase):
    def setUp(self):
        self.evaluator = ForensicPolicyEvaluator()

    def test_policy_file_exists_and_declares_package(self):
        content = Path("config/opa/forensic_policy.rego").read_text(encoding="utf-8")
        self.assertIn("package soc.forensics", content)
        self.assertIn("default allow = false", content)

    def test_operator_authorized_for_acquisition_and_sealing(self):
        req_acquire = {"principal": "soc-operator", "action": "acquire", "target": "memory_dump"}
        req_seal = {"principal": "soc-operator", "action": "seal", "target": "vault"}
        req_dispatch = {"principal": "soc-operator", "action": "dispatch_working_copy", "target": "working_copy"}

        self.assertTrue(self.evaluator.evaluate(req_acquire).allow)
        self.assertTrue(self.evaluator.evaluate(req_seal).allow)
        self.assertTrue(self.evaluator.evaluate(req_dispatch).allow)

    def test_all_agents_allowed_for_derived_artifacts(self):
        agents = ["agent", "agent_a", "agent_b", "agent_c", "agent_d", "agent_e", "agent_f", "agent_g"]
        for ag in agents:
            req = {
                "principal": ag,
                "action": "read_derived",
                "target": "working_copy",
            }
            decision = self.evaluator.evaluate(req)
            self.assertTrue(decision.allow, f"Agent {ag} should be allowed to read working copy")

    def test_all_agents_denied_for_evidence_acquisition_and_raw_access(self):
        agents = ["agent", "agent_a", "agent_b", "agent_c", "agent_d", "agent_e", "agent_f", "agent_g"]
        for ag in agents:
            req_acq = {"principal": ag, "action": "acquire", "target": "host_memory"}
            req_seal = {"principal": ag, "action": "seal", "target": "vault"}
            req_raw = {"principal": ag, "action": "read_raw", "target": "original_evidence"}

            self.assertFalse(self.evaluator.evaluate(req_acq).allow)
            self.assertFalse(self.evaluator.evaluate(req_seal).allow)
            self.assertFalse(self.evaluator.evaluate(req_raw).allow)

            with self.assertRaises(PermissionError):
                self.evaluator.enforce(req_acq)

    def test_universal_denial_for_mutation_and_deletion(self):
        # Even soc-operator cannot delete or update original sealed evidence
        principals = ["soc-operator", "compliance-officer", "agent_g", "admin", "root"]
        destructive_actions = ["delete", "update", "modify", "truncate", "overwrite"]

        for p in principals:
            for act in destructive_actions:
                req = {"principal": p, "action": act, "target": "sealed_evidence"}
                decision = self.evaluator.evaluate(req)
                self.assertFalse(decision.allow, f"Principal {p} must NOT be allowed to {act}")
                self.assertIn("Destructive operations on sealed evidence are strictly forbidden", decision.reason)

                with self.assertRaises(PermissionError):
                    self.evaluator.enforce(req)

    def test_unknown_principal_denied(self):
        req = {"principal": "untrusted_external_actor", "action": "read_derived", "target": "working_copy"}
        decision = self.evaluator.evaluate(req)
        self.assertFalse(decision.allow)
        self.assertIn("Unauthorized principal", decision.reason)


if __name__ == "__main__":
    unittest.main()
