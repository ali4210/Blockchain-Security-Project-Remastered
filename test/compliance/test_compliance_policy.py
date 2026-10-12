"""
Task P13-007: Unit tests for Compliance OPA Policy and Engine.
Validates:
1. Rego policy file exists and declares package compliance_policy.
2. Autonomous agents are allowed for screening and drafting actions.
3. Autonomous agents are strictly denied for approval and filing actions.
4. Compliance officer is allowed for approval/filing with valid cryptographic token.
5. Compliance officer is denied with expired, forged, or missing token.
6. Universal denial for block_transaction_inclusion across all principals.
"""

from pathlib import Path
import time
import hmac
import hashlib
import unittest

from src.compliance.compliance_policy import CompliancePolicyEngine


class TestCompliancePolicy(unittest.TestCase):
    def setUp(self):
        self.secret = b"test-compliance-secret-key-32b"
        self.engine = CompliancePolicyEngine(secret_key=self.secret)
        self.now = time.time()

    def _create_valid_token(self, ttl: float = 3600.0) -> dict:
        expires = self.now + ttl
        payload = f"compliance_officer:{expires}:OFFICER-001".encode("utf-8")
        sig = hmac.new(self.secret, payload, hashlib.sha256).hexdigest()
        return {
            "role": "compliance_officer",
            "officer_id": "OFFICER-001",
            "expires_at": expires,
            "signature": sig,
        }

    def test_rego_policy_file_exists_and_declares_package(self):
        policy_file = Path("policies/compliance_policy.rego")
        self.assertTrue(policy_file.exists())
        content = policy_file.read_text(encoding="utf-8")
        self.assertIn("package compliance_policy", content)
        self.assertIn("officer_exclusive_actions", content)

    def test_agents_allowed_for_read_and_screen(self):
        for agent in self.engine.AUTONOMOUS_AGENTS:
            res = self.engine.evaluate({
                "principal": agent,
                "action": "screen_address",
                "current_timestamp": self.now,
            })
            self.assertTrue(res["allow"])

    def test_agent_c_allowed_for_drafting(self):
        res = self.engine.evaluate({
            "principal": "agent_c_compliance_judge",
            "action": "generate_draft_sar",
            "current_timestamp": self.now,
        })
        self.assertTrue(res["allow"])

    def test_all_agents_strictly_denied_for_approval_and_filing(self):
        for agent in self.engine.AUTONOMOUS_AGENTS:
            for action in self.engine.OFFICER_EXCLUSIVE_ACTIONS:
                res = self.engine.evaluate({
                    "principal": agent,
                    "action": action,
                    "current_timestamp": self.now,
                })
                self.assertFalse(res["allow"])
                self.assertIn("strictly denied", res["reason"])

    def test_compliance_officer_allowed_with_valid_token(self):
        token = self._create_valid_token(ttl=600.0)
        res = self.engine.evaluate({
            "principal": "compliance_officer",
            "action": "approve_sar_report",
            "current_timestamp": self.now,
            "token": token,
        })
        self.assertTrue(res["allow"])

    def test_compliance_officer_denied_without_token(self):
        res = self.engine.evaluate({
            "principal": "compliance_officer",
            "action": "approve_sar_report",
            "current_timestamp": self.now,
            "token": None,
        })
        self.assertFalse(res["allow"])

    def test_compliance_officer_denied_with_expired_token(self):
        expired_token = self._create_valid_token(ttl=-100.0)
        res = self.engine.evaluate({
            "principal": "compliance_officer",
            "action": "approve_sar_report",
            "current_timestamp": self.now,
            "token": expired_token,
        })
        self.assertFalse(res["allow"])

    def test_compliance_officer_denied_with_tampered_signature(self):
        token = self._create_valid_token(ttl=600.0)
        token["signature"] = "deadbeef" * 8
        res = self.engine.evaluate({
            "principal": "compliance_officer",
            "action": "approve_sar_report",
            "current_timestamp": self.now,
            "token": token,
        })
        self.assertFalse(res["allow"])

    def test_block_transaction_inclusion_strictly_denied_for_all(self):
        for principal in ["agent_a_auditor", "compliance_officer", "soc_operator"]:
            res = self.engine.evaluate({
                "principal": principal,
                "action": "block_transaction_inclusion",
                "current_timestamp": self.now,
            })
            self.assertFalse(res["allow"])
            self.assertIn("cannot block blockchain transaction inclusion", res["reason"])


if __name__ == "__main__":
    unittest.main()
