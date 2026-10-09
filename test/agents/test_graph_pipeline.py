import unittest
from unittest.mock import patch, MagicMock
from typing import List, Any

from src.agents.state import SwarmState
from src.agents.graph import (
    EphemeralVRAMManager,
    SequentialGraph,
    build_graph,
    run_swarm_pipeline,
)

AGENT_MODULES = [
    "src.agents.agent_a_auditor",
    "src.agents.agent_b_threat_hunter",
    "src.agents.agent_c_compliance_judge",
    "src.agents.agent_d_red_teamer",
    "src.agents.agent_e_incident_commander",
    "src.agents.agent_f_logic_analyzer",
    "src.agents.agent_g_guardrail",
    "src.llm_client.ollama_client",
]


class TestGraphPipeline(unittest.TestCase):
    def test_ephemeral_vram_cleanup(self):
        receipt = EphemeralVRAMManager.cleanup_vram("test-model")
        self.assertEqual(receipt["status"], "evicted")
        self.assertEqual(receipt["model"], "test-model")
        self.assertEqual(receipt["keep_alive"], 0)

    def test_build_graph_node_registration(self):
        graph = build_graph()
        self.assertEqual(len(graph.nodes), 7)
        expected_nodes = [
            "agent_a_auditor",
            "agent_b_threat_hunter",
            "agent_c_compliance_judge",
            "agent_d_red_teamer",
            "agent_e_incident_commander",
            "agent_f_deep_logic",
            "agent_g_guardrail",
        ]
        registered_names = [n["name"] for n in graph.nodes]
        self.assertEqual(registered_names, expected_nodes)

    def test_sequential_graph_error_handling(self):
        graph = SequentialGraph()

        def good_node(s):
            s["metadata"]["good"] = True
            return s

        def bad_node(s):
            raise RuntimeError("Simulation failure in test node")

        graph.add_node("good", good_node, "model1")
        graph.add_node("bad", bad_node, "model2")

        result = graph.run({"target_contract": "TestContract.sol"})
        self.assertEqual(result["current_stage"], "FAILED")
        self.assertTrue(result["escalation_needed"])
        self.assertTrue(any("Simulation failure" in err for err in result["errors"]))

    def test_end_to_end_swarm_pipeline_offline(self):
        purged_models = []
        patches: List[Any] = []

        for mod in AGENT_MODULES:
            try:
                p = patch(f"{mod}.chat", return_value="[OFFLINE_FALLBACK] host offline")
                p.start()
                patches.append(p)
            except (AttributeError, ModuleNotFoundError):
                pass

        p_purge = patch("src.llm_client.ollama_client.purge_model", side_effect=lambda m: purged_models.append(m))
        p_purge.start()
        patches.append(p_purge)

        try:
            final_state = run_swarm_pipeline(
                target_contract="contracts/solidity/VulnerableVault.sol",
                telemetry_logs="TEST_EVENT=DEPOSIT AMOUNT=100",
            )
        finally:
            for p in patches:
                try:
                    p.stop()
                except RuntimeError:
                    pass

        # Assert clean completion
        self.assertEqual(final_state["current_stage"], "COMPLETED")
        self.assertEqual(len(final_state["errors"]), 0)

        # Assert all 7 agents recorded their execution in metadata
        metadata = final_state.get("metadata", {})
        self.assertTrue(metadata.get("agent_a_executed"), "Agent A should have executed")
        self.assertTrue(metadata.get("agent_b_executed"), "Agent B should have executed")
        self.assertTrue(metadata.get("agent_c_executed"), "Agent C should have executed")
        self.assertTrue(metadata.get("agent_d_executed"), "Agent D should have executed")
        self.assertTrue(metadata.get("agent_e_executed"), "Agent E should have executed")
        self.assertTrue(metadata.get("agent_f_executed"), "Agent F should have executed")
        self.assertTrue(metadata.get("agent_g_executed"), "Agent G should have executed")

        # Assert terminal guardrail cleared
        self.assertTrue(metadata.get("terminal_gate_cleared"))
        self.assertEqual(metadata.get("sanitization_status"), "SANITIZED")

        # Assert cumulative findings accumulated across all nodes
        findings = final_state.get("findings", [])
        self.assertGreaterEqual(len(findings), 7)

        # Assert VRAM eviction was invoked between stages
        self.assertGreater(len(purged_models), 0)
        for node_name in [
            "agent_a_auditor",
            "agent_b_threat_hunter",
            "agent_c_compliance_judge",
            "agent_d_red_teamer",
            "agent_e_incident_commander",
            "agent_f_deep_logic",
            "agent_g_guardrail",
        ]:
            self.assertIn(f"vram_cleanup_{node_name}", metadata)


if __name__ == "__main__":
    unittest.main()
