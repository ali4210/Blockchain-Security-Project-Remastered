import unittest
from unittest.mock import patch

from src.agents.graph import SwarmState
from src.agents.agent_f_logic_analyzer import (
    parse_logic_findings,
    logic_analyzer_node,
)


class TestAgentFLogicAnalyzer(unittest.TestCase):
    def test_parse_logic_findings_json_block(self):
        sample_response = """```json
[
  {
    "finding_id": "FINDING-F-601",
    "category": "DEEP_LOGIC_INVARIANT",
    "invariant_tested": "Conservation of Deposits",
    "target": "VulnerableVault",
    "severity": "CRITICAL",
    "violation_scenario": "Balance mapping underflow upon reentered withdrawal invocation.",
    "mathematical_rationale": "Vault solvent condition fails: sum(balances) > total_supply.",
    "confidence": 0.98
  }
]
```"""
        findings = parse_logic_findings(sample_response, "VulnerableVault")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_id"], "FINDING-F-601")
        self.assertEqual(findings[0]["category"], "DEEP_LOGIC_INVARIANT")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_parse_logic_findings_offline_simulation(self):
        sim_response = "[OFFLINE_FALLBACK] Simulated response for agent=F model=deepseek-r1:32b ctx=16384: Host unavailable"
        findings = parse_logic_findings(sim_response, "VulnerableVault")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_id"], "FINDING-F-SIM-001")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_logic_analyzer_node_execution(self):
        state = SwarmState(
            target_contract="contracts/solidity/VulnerableVault.sol",
            findings=[
                {"finding_id": "FINDING-A-101", "vulnerability": "Reentrancy"},
                {"finding_id": "FINDING-E-501", "severity_level": "SEV-1"},
            ],
        )

        purged = []
        with patch("src.llm_client.ollama_client.purge_model", side_effect=lambda m: purged.append(m)):
            with patch("src.llm_client.ollama_client.chat", return_value="[OFFLINE_FALLBACK] host offline"):
                next_state = logic_analyzer_node(state)

        self.assertEqual(next_state["current_step"], "agent_f_completed")
        self.assertEqual(next_state["current_stage"], "agent_f_completed")
        self.assertTrue(next_state["metadata"].get("agent_f_executed"))
        self.assertEqual(len(next_state["findings"]), 3)
        self.assertTrue(len(purged) > 0)


if __name__ == "__main__":
    unittest.main()
