import unittest
from unittest.mock import patch

from src.agents.graph import SwarmState
from src.agents.agent_a_auditor import (
    extract_contract_source,
    parse_auditor_findings,
    audit_contract_node,
)


class TestAgentAAuditor(unittest.TestCase):
    def test_extract_contract_source_fallback(self):
        state = SwarmState(target_contract="contracts/solidity/VulnerableVault.sol")
        source = extract_contract_source(state)
        self.assertIsInstance(source, str)
        self.assertTrue(len(source) > 0)

    def test_parse_auditor_findings_json_block(self):
        sample_response = '```json\n[{"finding_id": "FINDING-A-101", "vulnerability": "Reentrancy", "severity": "CRITICAL", "contract": "VulnerableVault.sol", "details": "Withdraw flaw", "confidence": 0.95}]\n```'
        findings = parse_auditor_findings(sample_response, "VulnerableVault.sol")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_id"], "FINDING-A-101")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_parse_auditor_findings_offline_simulation(self):
        sim_response = "[OFFLINE_FALLBACK] Simulated response for agent=A model=qwen2.5-coder:32b ctx=32768: Host unavailable"
        findings = parse_auditor_findings(sim_response, "VulnerableVault.sol")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_id"], "FINDING-A-SIM-001")

    def test_audit_contract_node_execution(self):
        state = SwarmState(target_contract="contracts/solidity/VulnerableVault.sol")
        purged = []
        with patch("src.llm_client.ollama_client.purge_model", side_effect=lambda m: purged.append(m)):
            with patch("src.llm_client.ollama_client.chat", return_value="[OFFLINE_FALLBACK] host offline"):
                next_state = audit_contract_node(state)

        self.assertEqual(next_state["current_step"], "agent_a_completed")
        self.assertTrue(next_state["metadata"].get("agent_a_executed"))
        self.assertTrue(len(next_state["findings"]) > 0)
        self.assertTrue(len(purged) > 0)


if __name__ == "__main__":
    unittest.main()
