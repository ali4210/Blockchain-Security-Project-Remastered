import unittest
from unittest.mock import patch

from src.agents.state import SwarmState
from src.agents.graph import (
    EphemeralVRAMManager,
    SequentialGraph,
    build_graph,
)


class TestSwarmGraph(unittest.TestCase):
    def test_swarm_state_initialization(self):
        state = SwarmState(target_contract="contracts/solidity/VulnerableVault.sol")
        self.assertEqual(state["target_contract"], "contracts/solidity/VulnerableVault.sol")
        self.assertEqual(state["current_stage"], "INITIAL")
        self.assertEqual(len(state["findings"]), 0)
        self.assertFalse(state["escalation_needed"])

    def test_ephemeral_vram_manager(self):
        receipt = EphemeralVRAMManager.cleanup_vram("test-model")
        self.assertEqual(receipt["status"], "evicted")
        self.assertEqual(receipt["model"], "test-model")
        self.assertEqual(receipt["keep_alive"], 0)

    def test_sequential_graph_execution(self):
        graph = build_graph()
        purged = []
        with patch("src.llm_client.ollama_client.purge_model", side_effect=lambda m: purged.append(m)):
            with patch("src.llm_client.ollama_client.chat", return_value="[OFFLINE_FALLBACK] host offline"):
                result = graph.run({"target_contract": "contracts/solidity/VulnerableVault.sol"})

        self.assertEqual(result["current_stage"], "COMPLETED")
        self.assertTrue(result["metadata"].get("agent_a_executed"))
        self.assertTrue(result["metadata"].get("agent_b_executed"))
        self.assertTrue(result["metadata"].get("agent_c_executed"))
        self.assertTrue(result["metadata"].get("agent_d_executed"))
        self.assertTrue(result["metadata"].get("agent_e_executed"))
        self.assertTrue(result["metadata"].get("agent_f_executed"))
        self.assertTrue(result["metadata"].get("agent_g_executed"))
        self.assertIn("vram_cleanup_agent_a_auditor", result["metadata"])
        self.assertIn("vram_cleanup_agent_g_guardrail", result["metadata"])

    def test_graph_handles_node_failure_gracefully(self):
        graph = SequentialGraph()

        def failing_node(s):
            raise RuntimeError("AST parsing failure")

        graph.add_node("broken_node", failing_node)
        result = graph.run({"target_contract": "sample.sol"})

        self.assertEqual(result["current_stage"], "FAILED")
        self.assertTrue(result["escalation_needed"])
        self.assertIn("AST parsing failure", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
