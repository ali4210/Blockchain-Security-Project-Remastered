import unittest
from unittest.mock import patch

from src.agents.graph import SwarmState
from src.agents.agent_e_incident_commander import (
    parse_incident_commander_report,
    incident_commander_node,
)


class TestAgentEIncidentCommander(unittest.TestCase):
    def test_parse_incident_commander_report_json_block(self):
        sample_response = """```json
{
  "finding_id": "FINDING-E-501",
  "category": "INCIDENT_TRIAGE",
  "severity_level": "SEV-1",
  "target": "VulnerableVault",
  "containment_status": "IMMEDIATE_ACTION_REQUIRED",
  "playbook_actions": ["PAUSE_VAULT", "ALERT_CORE_DEV"],
  "rationale": "Active reentrancy exploit scenario confirmed by red team.",
  "escalation_required": true
}
```"""
        parsed = parse_incident_commander_report(sample_response, "VulnerableVault")
        self.assertEqual(parsed["severity_level"], "SEV-1")
        self.assertEqual(parsed["containment_status"], "IMMEDIATE_ACTION_REQUIRED")
        self.assertTrue(parsed["escalation_required"])
        self.assertEqual(len(parsed["playbook_actions"]), 2)

    def test_parse_incident_commander_report_offline_simulation(self):
        sim_response = "[OFFLINE_FALLBACK] Simulated response for agent=E model=qwen2.5:32b ctx=8192: Host unavailable"
        parsed = parse_incident_commander_report(sim_response, "VulnerableVault")
        self.assertEqual(parsed["finding_id"], "FINDING-E-SIM-001")
        self.assertEqual(parsed["severity_level"], "SEV-1")
        self.assertTrue(parsed["escalation_required"])

    def test_incident_commander_node_execution(self):
        state = SwarmState(
            target_contract="contracts/solidity/VulnerableVault.sol",
            findings=[
                {"finding_id": "FINDING-A-101", "vulnerability": "Reentrancy", "severity": "CRITICAL"},
                {"finding_id": "FINDING-D-301", "exploit_scenario": "Reentrancy Drain PoC", "severity": "CRITICAL"},
            ],
        )

        purged = []
        with patch("src.llm_client.ollama_client.purge_model", side_effect=lambda m: purged.append(m)):
            with patch("src.llm_client.ollama_client.chat", return_value="[OFFLINE_FALLBACK] host offline"):
                next_state = incident_commander_node(state)

        self.assertEqual(next_state["current_step"], "agent_e_completed")
        self.assertEqual(next_state["current_stage"], "agent_e_completed")
        self.assertTrue(next_state["metadata"].get("agent_e_executed"))
        self.assertTrue(next_state["escalation_needed"])
        self.assertEqual(len(next_state["findings"]), 3)
        self.assertTrue(len(purged) > 0)


if __name__ == "__main__":
    unittest.main()
