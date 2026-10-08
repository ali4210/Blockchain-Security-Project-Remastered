import unittest

from src.agents.graph import (
    SwarmState,
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
        result = graph.run({"target_contract": "contracts/solidity/VulnerableVault.sol"})

        self.assertEqual(result["current_stage"], "COMPLETED")
        self.assertTrue(result["metadata"]["audited"])
        self.assertTrue(result["metadata"]["threat_hunted"])
        self.assertTrue(result["metadata"]["compliance_judged"])
        self.assertTrue(result["metadata"]["red_teamed"])
        self.assertTrue(result["metadata"]["guardrails_enforced"])
        self.assertIn("vram_cleanup_agent_a_auditor", result["metadata"])

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
