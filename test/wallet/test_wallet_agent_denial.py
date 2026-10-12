"""
Task P12-012: Agent Denial Test Suite for Shamir Reconstruction and HSM Signing.
Exhaustively verifies negative security constraints:
1. Autonomous agents (Agent-A through Agent-G) are strictly denied from Shamir reconstruction.
2. Autonomous agents are strictly denied from HSM signing and raw key operations.
3. Universal fail-closed behavior across forged tokens, missing roles, and direct API gating.
4. Zero secret or share leakage in denial exception payloads.
"""

from pathlib import Path
import time
import unittest

from src.wallet.shamir_engine import ShamirSecretSharing, ShamirShare
from src.wallet.hsm_emulator import HsmEmulator, HsmAuthenticationError
from src.wallet.hsm_signer_interface import HsmSignerInterface
from src.wallet.wallet_policy import (
    WalletPolicyEvaluator,
    VALID_AGENT_PRINCIPALS,
    FORBIDDEN_AGENT_ACTIONS,
)


class TestWalletAgentDenial(unittest.TestCase):
    def setUp(self):
        self.evaluator = WalletPolicyEvaluator()
        self.shamir = ShamirSecretSharing()
        self.test_agents = list(VALID_AGENT_PRINCIPALS)

    def test_all_autonomous_agents_denied_for_shamir_reconstruction(self):
        for agent in self.test_agents:
            decision = self.evaluator.evaluate(principal=agent, action="shamir_reconstruct")
            self.assertFalse(decision.allow, f"Expected {agent} to be denied for shamir_reconstruct")
            self.assertIn("strictly forbidden", decision.reason)

    def test_all_autonomous_agents_denied_for_hsm_signing(self):
        for agent in self.test_agents:
            decision = self.evaluator.evaluate(principal=agent, action="hsm_sign")
            self.assertFalse(decision.allow, f"Expected {agent} to be denied for hsm_sign")
            self.assertIn("strictly forbidden", decision.reason)

    def test_all_autonomous_agents_denied_for_all_forbidden_wallet_actions(self):
        for agent in self.test_agents:
            for forbidden_action in FORBIDDEN_AGENT_ACTIONS:
                decision = self.evaluator.evaluate(principal=agent, action=forbidden_action)
                self.assertFalse(
                    decision.allow,
                    f"Agent {agent} must be denied for forbidden action {forbidden_action}",
                )
                self.assertIn("strictly forbidden", decision.reason)

    def test_agent_presenting_forged_bearer_token_denied(self):
        now = time.time()
        forged_token = {
            "valid": True,
            "role": "soc_operator",  # Forged claim
            "expires_at": now + 600,
        }
        for agent in self.test_agents:
            # Policy evaluates principal identity first; agents cannot assume operator roles via bearer token
            decision = self.evaluator.evaluate(
                principal=agent,
                action="hsm_sign",
                token=forged_token,
                current_time=now,
            )
            self.assertFalse(decision.allow)
            self.assertIn("strictly forbidden", decision.reason)

    def test_operator_token_role_mismatch_fails_closed(self):
        now = time.time()
        mismatched_token = {
            "valid": True,
            "role": "lead_incident_commander",  # Token role differs from principal
            "expires_at": now + 600,
        }
        decision = self.evaluator.evaluate(
            principal="soc_operator",
            action="hsm_sign",
            token=mismatched_token,
            current_time=now,
        )
        self.assertFalse(decision.allow)
        self.assertIn("does not match principal", decision.reason)

    def test_shamir_engine_subthreshold_and_tamper_isolation(self):
        secret = b"AgentDenialRootKey32ByteTarget!"
        shares = self.shamir.split_secret(secret, threshold=3, total_shares=5)

        # Ensure that attempting reconstruction with 2 shares fails closed
        with self.assertRaises(Exception) as ctx:
            self.shamir.reconstruct_secret(shares[:2])
        # Ensure raw secret is not leaked in exception string
        self.assertNotIn("AgentDenialRootKey", str(ctx.exception))

    def test_zero_leakage_on_unauthenticated_hsm_calls(self):
        emulator = HsmEmulator(slot_id=0, user_pin="4321", so_pin="87654321")
        # Generate key while authenticated
        emulator.login("4321")
        handle = emulator.generate_key_pair("denial-target")
        emulator.logout()

        signer = HsmSignerInterface(emulator, handle)
        test_digest = b"\x11" * 32

        # Unauthenticated sign attempt fails closed without key leakage
        with self.assertRaises(HsmAuthenticationError) as ctx:
            signer.sign_hash(test_digest)
        self.assertIn("authentication required", str(ctx.exception).lower())
        self.assertNotIn("private", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
