import unittest
from unittest.mock import patch

from src.agents.graph import SwarmState
from src.agents.agent_d_red_teamer import (
    parse_red_team_findings,
    red_teamer_node,
)


class TestAgentDRedTeamer(unittest.TestCase):
    def test_parse_red_team_findings_json_block(self):
        sample_response = """```json
[
  {
    "finding_id": "FINDING-D-301",
    "exploit_scenario": "Reentrancy Drain PoC",
    "target": "VulnerableVault",
    "severity": "CRITICAL",
    "attack_vector": "External call before balance decrement",
    "poc_stub": "function testExploit() public { ... }",
    "details": "Contract balances drained via recursive call.",
    "confidence": 0.96
  }
]
```"""
        findings = parse_red_team_findings(sample_response, "VulnerableVault")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_id"], "FINDING-D-301")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("poc_stub", findings[0])

    def test_parse_red_team_findings_offline_simulation(self):
        sim_response = "[OFFLINE_FALLBACK] Simulated response for agent=D model=deepseek-r1:32b ctx=16384: Host unavailable"
        findings = parse_red_team_findings(sim_response, "VulnerableVault")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_id"], "FINDING-D-SIM-001")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_red_teamer_node_execution(self):
        state = SwarmState(
            target_contract="contracts/solidity/VulnerableVault.sol",
            findings=[
                {"finding_id": "FINDING-A-101", "vulnerability": "Reentrancy"},
                {"finding_id": "FINDING-C-COMPLIANCE-001", "verdict": "FAIL"},
            ],
        )

        purged = []
        with patch("src.llm_client.ollama_client.purge_model", side_effect=lambda m: purged.append(m)):
            with patch("src.llm_client.ollama_client.chat", return_value="[OFFLINE_FALLBACK] host offline"):
                next_state = red_teamer_node(state)

        self.assertEqual(next_state["current_step"], "agent_d_completed")
        self.assertEqual(next_state["current_stage"], "agent_d_completed")
        self.assertTrue(next_state["metadata"].get("agent_d_executed"))
        self.assertEqual(len(next_state["findings"]), 3)
        self.assertTrue(len(purged) > 0)


if __name__ == "__main__":
    unittest.main()
