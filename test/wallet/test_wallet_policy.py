"""
Task P12-011: Unit tests for Wallet OPA Policy Evaluator.
Verifies RBAC rules, token expiration, agent restrictions, and fail-closed defaults.
"""

from pathlib import Path
import time
import unittest

from src.wallet.wallet_policy import WalletPolicyEvaluator


class TestWalletPolicy(unittest.TestCase):
    def setUp(self):
        self.evaluator = WalletPolicyEvaluator()
        self.rego_file = Path("policies/wallet_policy.rego")
        self.assertTrue(self.rego_file.exists(), "policies/wallet_policy.rego must exist.")

    def test_rego_policy_file_declares_package(self):
        content = self.rego_file.read_text(encoding="utf-8")
        self.assertIn("package wallet.authz", content)
        self.assertIn("default allow = false", content)

    def test_agents_allowed_for_read_and_simulate_actions(self):
        agents = ["Agent-A", "Agent-B", "Agent-D", "Agent-E"]
        actions = ["read", "audit", "simulate", "observe"]
        for agent in agents:
            for action in actions:
                decision = self.evaluator.evaluate(principal=agent, action=action)
                self.assertTrue(decision.allow, f"Expected {agent} to be allowed for {action}")

    def test_agents_strictly_denied_for_key_reconstruction_and_signing(self):
        agents = ["Agent-A", "Agent-D", "Agent-E"]
        blocked_actions = ["export_private_key", "shamir_reconstruct", "hsm_sign", "broadcast_transaction"]
        for agent in agents:
            for action in blocked_actions:
                decision = self.evaluator.evaluate(principal=agent, action=action)
                self.assertFalse(decision.allow, f"Expected {agent} to be denied for {action}")
                self.assertIn("strictly forbidden", decision.reason)

    def test_soc_operator_allowed_with_valid_token(self):
        now = time.time()
        token = {
            "valid": True,
            "role": "soc_operator",
            "expires_at": now + 300,
        }
        actions = ["emergency_pause", "hsm_sign", "shamir_reconstruct"]
        for action in actions:
            decision = self.evaluator.evaluate(
                principal="soc_operator",
                action=action,
                token=token,
                current_time=now,
            )
            self.assertTrue(decision.allow, f"Expected soc_operator to be allowed for {action} with valid token")

    def test_soc_operator_denied_without_token(self):
        decision = self.evaluator.evaluate(principal="soc_operator", action="hsm_sign", token=None)
        self.assertFalse(decision.allow)
        self.assertIn("Missing mandatory authorization token", decision.reason)

    def test_soc_operator_denied_with_expired_token(self):
        now = time.time()
        token = {
            "valid": True,
            "role": "soc_operator",
            "expires_at": now - 10,
        }
        decision = self.evaluator.evaluate(
            principal="soc_operator",
            action="hsm_sign",
            token=token,
            current_time=now,
        )
        self.assertFalse(decision.allow)
        self.assertIn("expired", decision.reason)

    def test_compliance_officer_boundary(self):
        dec_read = self.evaluator.evaluate(principal="compliance_officer", action="observe")
        self.assertTrue(dec_read.allow)

        dec_mutate = self.evaluator.evaluate(principal="compliance_officer", action="hsm_sign")
        self.assertFalse(dec_mutate.allow)

    def test_unknown_principal_denied(self):
        decision = self.evaluator.evaluate(principal="unknown_attacker", action="read")
        self.assertFalse(decision.allow)
        self.assertIn("Unknown or unauthorized principal", decision.reason)


if __name__ == "__main__":
    unittest.main()
