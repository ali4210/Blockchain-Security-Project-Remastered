import unittest
from unittest.mock import patch

from src.agents.graph import SwarmState
from src.agents.agent_g_guardrail import (
    parse_guardrail_report,
    guardrail_watchdog_node,
)


class TestAgentGGuardrail(unittest.TestCase):
    def test_parse_guardrail_report_json_block(self):
        sample_response = """```json
{
  "finding_id": "FINDING-G-701",
  "category": "OUTPUT_GUARDRAIL_AUDIT",
  "target": "VulnerableVault",
  "sanitization_status": "SANITIZED",
  "injections_detected": false,
  "redacted_items_count": 0,
  "sanitization_notes": "All downstream outputs adhere to safety invariants.",
  "terminal_gate_cleared": true
}
```"""
        parsed = parse_guardrail_report(sample_response, "VulnerableVault")
        self.assertEqual(parsed["finding_id"], "FINDING-G-701")
        self.assertEqual(parsed["sanitization_status"], "SANITIZED")
        self.assertFalse(parsed["injections_detected"])
        self.assertTrue(parsed["terminal_gate_cleared"])

    def test_parse_guardrail_report_offline_simulation(self):
        sim_response = "[OFFLINE_FALLBACK] Simulated response for agent=G model=qwen2.5:32b ctx=8192: Host unavailable"
        parsed = parse_guardrail_report(sim_response, "VulnerableVault")
        self.assertEqual(parsed["finding_id"], "FINDING-G-SIM-001")
        self.assertEqual(parsed["sanitization_status"], "SANITIZED")
        self.assertTrue(parsed["terminal_gate_cleared"])

    def test_guardrail_watchdog_node_execution(self):
        state = SwarmState(
            target_contract="contracts/solidity/VulnerableVault.sol",
            findings=[
                {"finding_id": "FINDING-A-101", "vulnerability": "Reentrancy"},
                {"finding_id": "FINDING-E-501", "severity_level": "SEV-1"},
            ],
        )

        purged = []
        with patch("src.llm_client.ollama_client.purge_model", side_effect=lambda m: purged.append(m)):
            with patch("src.agents.agent_g_guardrail.chat", return_value="[OFFLINE_FALLBACK] host offline"):
                next_state = guardrail_watchdog_node(state)

        self.assertEqual(next_state["current_step"], "agent_g_completed")
        self.assertEqual(next_state["current_stage"], "agent_g_completed")
        self.assertTrue(next_state["metadata"].get("agent_g_executed"))
        self.assertTrue(next_state["metadata"].get("terminal_gate_cleared"))
        self.assertEqual(len(next_state["findings"]), 3)
        self.assertTrue(len(purged) > 0)


if __name__ == "__main__":
    unittest.main()
