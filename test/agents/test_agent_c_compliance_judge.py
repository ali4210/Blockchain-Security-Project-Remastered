import unittest
from unittest.mock import patch

from src.agents.graph import SwarmState
from src.agents.agent_c_compliance_judge import (
    parse_compliance_verdict,
    compliance_judge_node,
)


class TestAgentCComplianceJudge(unittest.TestCase):
    def test_parse_compliance_verdict_json_block(self):
        sample_response = """```json
{
  "verdict": "FAIL",
  "compliance_score": 45,
  "frameworks_evaluated": ["OWASP-SC-2023", "NIST-SP-800-53"],
  "violations": [
    {
      "control_id": "OWASP-SC-01",
      "description": "Critical reentrancy flaw detected.",
      "severity": "CRITICAL",
      "remediation": "Apply nonReentrant modifier."
    }
  ],
  "details": "Contract fails primary controls."
}
```"""
        parsed = parse_compliance_verdict(sample_response)
        self.assertEqual(parsed["verdict"], "FAIL")
        self.assertEqual(parsed["compliance_score"], 45)
        self.assertEqual(len(parsed["violations"]), 1)

    def test_parse_compliance_verdict_offline_simulation(self):
        sim_response = "[OFFLINE_FALLBACK] Simulated response for agent=C model=qwen2.5:32b ctx=8192: Host unavailable"
        parsed = parse_compliance_verdict(sim_response)
        self.assertEqual(parsed["verdict"], "CONDITIONAL_PASS")
        self.assertEqual(parsed["compliance_score"], 78)

    def test_compliance_judge_node_execution(self):
        state = SwarmState(
            target_contract="contracts/solidity/VulnerableVault.sol",
            findings=[
                {"finding_id": "FINDING-A-101", "vulnerability": "Reentrancy"},
                {"finding_id": "FINDING-B-201", "threat_type": "Front-Running"},
            ],
        )

        purged = []
        with patch("src.llm_client.ollama_client.purge_model", side_effect=lambda m: purged.append(m)):
            with patch("src.llm_client.ollama_client.chat", return_value="[OFFLINE_FALLBACK] host offline"):
                next_state = compliance_judge_node(state)

        self.assertEqual(next_state["current_step"], "agent_c_completed")
        self.assertEqual(next_state["current_stage"], "agent_c_completed")
        self.assertTrue(next_state["metadata"].get("agent_c_executed"))
        self.assertIn("compliance_verdict", next_state["metadata"])
        self.assertEqual(len(next_state["findings"]), 3)
        self.assertTrue(len(purged) > 0)


if __name__ == "__main__":
    unittest.main()
