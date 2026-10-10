"""
Task P08-005: Unit Tests for RASP Threat Router.
Validates routing of confirmed exploits to Agent B, filtering of benign runs,
SIEM telemetry log string synthesis, and fail-closed error handling.
"""

import unittest
from unittest.mock import MagicMock

from src.agents.state import SwarmState
from src.observability.shadow_fork_verifier import (
    AgentEShadowVerificationReport,
    ShadowReplayOutcome,
)
from src.observability.rasp_router import (
    RaspThreatRouter,
    RouterDispatchResult,
    RoutingStatus,
)


class TestRaspThreatRouter(unittest.TestCase):
    def setUp(self):
        self.mock_agent_b = MagicMock()
        self.router = RaspThreatRouter(threat_hunter_fn=self.mock_agent_b)

    def test_benign_report_is_filtered(self):
        benign_report = AgentEShadowVerificationReport(
            finding_id="FINDING-BENIGN-01",
            target="VulnerableVault",
            outcome=ShadowReplayOutcome.EXECUTION_CLEAN,
            severity_level="SEV-4",
            containment_status="MONITORING_ONLY",
            playbook_actions=["LOG_TELEMETRY"],
            execution_trace={"tx_hash": "0x123", "gas_used": 21000, "balance_delta_wei": 0},
            audit_record_digest="a" * 64,
        )

        result = self.router.route_to_agent_b(benign_report)
        self.assertEqual(result.status, RoutingStatus.FILTERED_BENIGN)
        self.assertEqual(result.finding_id, "FINDING-BENIGN-01")
        self.mock_agent_b.assert_not_called()

    def test_confirmed_exploit_routes_to_agent_b(self):
        exploit_report = AgentEShadowVerificationReport(
            finding_id="FINDING-EXPLOIT-01",
            target="VulnerableVault",
            outcome=ShadowReplayOutcome.CONFIRMED_EXPLOIT,
            severity_level="SEV-1",
            containment_status="IMMEDIATE_ACTION_REQUIRED",
            playbook_actions=["TRIGGER_PAUSE_CIRCUIT_BREAKER", "ISOLATE_RPC_INGEST_NODE"],
            execution_trace={
                "tx_hash": "0xdeadbeef",
                "gas_used": 185000,
                "balance_delta_wei": -10_000_000_000_000_000_000,  # 10 ETH
            },
            audit_record_digest="b" * 64,
        )

        # Mock Agent B output state
        def fake_agent_b(state: SwarmState) -> SwarmState:
            findings = list(state.get("findings", []))
            findings.append({
                "finding_id": "FINDING-B-CORRELATED-01",
                "threat_type": "On-Chain Draining Vector",
                "severity": "CRITICAL",
                "target": state["target_contract"],
            })
            new_s = SwarmState(
                target_contract=state["target_contract"],
                findings=findings,
                current_stage="agent_b_completed",
                escalation_needed=True,
                errors=[],
                metadata=state.get("metadata", {}),
            )
            return new_s

        self.mock_agent_b.side_effect = fake_agent_b

        result = self.router.route_to_agent_b(exploit_report)
        self.assertEqual(result.status, RoutingStatus.ROUTED_TO_AGENT_B)
        self.assertEqual(result.finding_id, "FINDING-EXPLOIT-01")
        self.assertEqual(len(result.agent_b_findings), 1)
        self.assertEqual(result.agent_b_findings[0]["finding_id"], "FINDING-B-CORRELATED-01")

        # Verify dispatched state content
        call_args = self.mock_agent_b.call_args[0][0]
        self.assertIn("10.0000", call_args["telemetry_logs"])
        self.assertIn("EVENT=RASP_SHADOW_REPLAY_EXPLOIT", call_args["telemetry_logs"])
        self.assertTrue(call_args["metadata"]["rasp_escalated"])
        self.assertEqual(call_args["metadata"]["rasp_finding_id"], "FINDING-EXPLOIT-01")

    def test_invalid_or_missing_report_fail_closed(self):
        result = self.router.route_to_agent_b(None)
        self.assertEqual(result.status, RoutingStatus.INVALID_REPORT)
        self.mock_agent_b.assert_not_called()

    def test_agent_b_exception_handling(self):
        exploit_report = AgentEShadowVerificationReport(
            finding_id="FINDING-EXPLOIT-ERR",
            target="VulnerableVault",
            outcome=ShadowReplayOutcome.CONFIRMED_EXPLOIT,
            severity_level="SEV-1",
            containment_status="IMMEDIATE_ACTION_REQUIRED",
            playbook_actions=["NOTIFY_SECURITY_MULTISIG"],
            execution_trace={"tx_hash": "0xbad", "gas_used": 100000, "balance_delta_wei": -1000},
            audit_record_digest="c" * 64,
        )

        self.mock_agent_b.side_effect = RuntimeError("VRAM Allocation Failed")

        result = self.router.route_to_agent_b(exploit_report)
        self.assertEqual(result.status, RoutingStatus.INVALID_REPORT)
        self.assertIn("VRAM Allocation Failed", result.reason)


if __name__ == "__main__":
    unittest.main()
