import unittest
from unittest.mock import patch

from src.agents.graph import SwarmState
from src.agents.agent_b_threat_hunter import (
    extract_telemetry_logs,
    parse_threat_findings,
    threat_hunter_node,
)


class TestAgentBThreatHunter(unittest.TestCase):
    def test_extract_telemetry_logs_default(self):
        state = SwarmState(target_contract="VulnerableVault")
        logs = extract_telemetry_logs(state)
        self.assertIsInstance(logs, str)
        self.assertIn("TRANSACTION_EXECUTION", logs)

    def test_parse_threat_findings_json_block(self):
        sample_response = '```json\n[{"finding_id": "FINDING-B-201", "threat_type": "Front-Running", "severity": "HIGH", "target": "VulnerableVault", "correlated_indicators": ["GAS_USED"], "details": "Suspicious transaction detected", "confidence": 0.91}]\n```'
        findings = parse_threat_findings(sample_response, "VulnerableVault")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_id"], "FINDING-B-201")
        self.assertEqual(findings[0]["threat_type"], "Front-Running")

    def test_parse_threat_findings_offline_simulation(self):
        sim_response = "[OFFLINE_FALLBACK] Simulated response for agent=B model=deepseek-r1:32b ctx=16384: Host unavailable"
        findings = parse_threat_findings(sim_response, "VulnerableVault")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_id"], "FINDING-B-SIM-001")

    def test_threat_hunter_node_execution(self):
        state = SwarmState(
            target_contract="contracts/solidity/VulnerableVault.sol",
            findings=[{"finding_id": "FINDING-A-101", "vulnerability": "Reentrancy"}],
        )

        purged = []
        with patch("src.llm_client.ollama_client.purge_model", side_effect=lambda m: purged.append(m)):
            with patch("src.llm_client.ollama_client.chat", return_value="[OFFLINE_FALLBACK] host offline"):
                next_state = threat_hunter_node(state)

        self.assertEqual(next_state["current_step"], "agent_b_completed")
        self.assertEqual(next_state["current_stage"], "agent_b_completed")
        self.assertTrue(next_state["metadata"].get("agent_b_executed"))
        self.assertEqual(len(next_state["findings"]), 2)
        self.assertTrue(len(purged) > 0)


if __name__ == "__main__":
    unittest.main()
