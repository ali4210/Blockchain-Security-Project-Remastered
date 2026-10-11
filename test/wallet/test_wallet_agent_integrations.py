"""
Task P12-010: Unit tests for Agents A, D, and E Wallet Security Integrations.
Validates:
1. Agent A triggers WalletAuditMcpRegistry on vulnerable wallet fixtures.
2. Agent D synthesizes authorized PoC stubs for replay and delegatecall flaws.
3. Agent E enforces mandatory pre-sign simulation receipts before gating actions.
All LLM chat invocations are mocked to run deterministically in headless CI.
"""

from pathlib import Path
import unittest
from unittest.mock import patch

from src.agents.agent_a_auditor import run_agent_a, audit_contract_node
from src.agents.agent_d_red_teamer import run_agent_d, red_teamer_node
from src.agents.agent_e_incident_commander import run_agent_e, incident_commander_node
from src.agents.state import SwarmState


class TestWalletAgentIntegrations(unittest.TestCase):
    def setUp(self):
        self.fixture_path = "test/wallet/fixtures/VulnerableWallet.sol"
        self.assertTrue(Path(self.fixture_path).exists())

    def test_aliases_are_consistent(self):
        self.assertIs(run_agent_a, audit_contract_node)
        self.assertIs(run_agent_d, red_teamer_node)
        self.assertIs(run_agent_e, incident_commander_node)

    @patch("src.agents.agent_a_auditor.chat", return_value="[OFFLINE_FALLBACK]")
    def test_agent_a_executes_wallet_audit_and_sets_quarantine(self, _mock_chat):
        state = SwarmState(
            target_contract=self.fixture_path,
            findings=[],
            current_stage="initial",
            escalation_needed=False,
            errors=[],
            metadata={},
        )

        next_state = run_agent_a(state)

        self.assertTrue(next_state["metadata"].get("agent_a_executed"))
        self.assertTrue(next_state["metadata"].get("wallet_audit_executed"))
        self.assertTrue(next_state["metadata"].get("quarantine_required"))
        self.assertTrue(next_state.get("escalation_needed"))

        rule_ids = {f.get("rule_id") for f in next_state.get("findings", []) if "rule_id" in f}
        self.assertIn("RULE-WLT-001", rule_ids)
        self.assertIn("RULE-WLT-002", rule_ids)
        self.assertIn("RULE-WLT-003", rule_ids)

    @patch("src.agents.agent_d_red_teamer.chat", return_value="[OFFLINE_FALLBACK]")
    def test_agent_d_synthesizes_authorized_wallet_pocs(self, _mock_chat):
        mock_prior_findings = [
            {"finding_id": "FINDING-A-WLT-001", "rule_id": "RULE-WLT-001", "title": "Replay", "severity": "CRITICAL"},
            {"finding_id": "FINDING-A-WLT-003", "rule_id": "RULE-WLT-003", "title": "Delegatecall", "severity": "CRITICAL"},
        ]
        state = SwarmState(
            target_contract=self.fixture_path,
            findings=mock_prior_findings,
            current_stage="agent_c_completed",
            escalation_needed=True,
            errors=[],
            metadata={"agent_a_executed": True},
        )

        next_state = run_agent_d(state)

        self.assertTrue(next_state["metadata"].get("agent_d_executed"))
        self.assertTrue(next_state["metadata"].get("wallet_poc_synthesized"))

        finding_ids = {f.get("finding_id") for f in next_state.get("findings", [])}
        self.assertIn("FINDING-D-WLT-001", finding_ids)
        self.assertIn("FINDING-D-WLT-003", finding_ids)

    @patch("src.agents.agent_e_incident_commander.chat", return_value="[OFFLINE_FALLBACK]")
    def test_agent_e_enforces_presign_simulation_success(self, _mock_chat):
        mock_findings = [
            {"finding_id": "FINDING-A-WLT-001", "rule_id": "RULE-WLT-001", "severity": "CRITICAL"},
        ]
        state = SwarmState(
            target_contract=self.fixture_path,
            findings=mock_findings,
            current_stage="agent_d_completed",
            escalation_needed=True,
            errors=[],
            metadata={"agent_a_executed": True, "agent_d_executed": True},
        )

        next_state = run_agent_e(state)

        self.assertTrue(next_state["metadata"].get("agent_e_executed"))
        self.assertTrue(next_state["metadata"].get("presign_simulation_passed"))
        self.assertIn("simulation_receipt_digest", next_state["metadata"])

    @patch("src.agents.agent_e_incident_commander.chat", return_value="[OFFLINE_FALLBACK]")
    def test_agent_e_blocks_mitigation_on_simulation_failure(self, _mock_chat):
        mock_findings = [
            {"finding_id": "FINDING-A-WLT-001", "rule_id": "RULE-WLT-001", "severity": "CRITICAL"},
        ]
        state = SwarmState(
            target_contract=self.fixture_path,
            findings=mock_findings,
            current_stage="agent_d_completed",
            escalation_needed=True,
            errors=[],
            metadata={"mock_simulation_failure": True},
        )

        next_state = run_agent_e(state)

        self.assertTrue(next_state["metadata"].get("agent_e_executed"))
        self.assertFalse(next_state["metadata"].get("presign_simulation_passed"))
        self.assertEqual(next_state["metadata"].get("containment_status"), "BLOCKED_SIMULATION_FAILURE")
        self.assertIn("reverted on contract execution", next_state["metadata"].get("simulation_error", ""))


if __name__ == "__main__":
    unittest.main()
