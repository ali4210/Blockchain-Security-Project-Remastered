"""
Task P05-014: Swarm Integration Regression, Benchmark Harness, and State Persistence.
Profiles multi-stage execution latency, verifies JSON serialization of SwarmState,
validates broker storage persistence, and asserts deterministic replay.
"""

from typing import Any, Dict, List
import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from src.agents.state import SwarmState
from src.agents.graph import run_swarm_pipeline, build_graph
from src.storage.broker_store import BrokerStore

# Target modules importing chat directly
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


def mock_chat_fn(*args, **kwargs) -> str:
    return "[OFFLINE_FALLBACK] host offline"


class TestSwarmBenchmark(unittest.TestCase):
    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(self.temp_db_fd)
        self.store = BrokerStore(self.temp_db_path)

        # Patch chat in all consuming namespaces to prevent network calls and timeouts
        self.patches: List[Any] = []
        for mod in AGENT_MODULES:
            try:
                p = patch(f"{mod}.chat", side_effect=mock_chat_fn)
                p.start()
                self.patches.append(p)
            except (AttributeError, ModuleNotFoundError):
                pass

        p_purge = patch("src.llm_client.ollama_client.purge_model", return_value=None)
        p_purge.start()
        self.patches.append(p_purge)

    def tearDown(self):
        for p in self.patches:
            try:
                p.stop()
            except RuntimeError:
                pass

        if hasattr(self, "store") and hasattr(self.store, "close"):
            self.store.close()
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    def test_multi_stage_latency_profiling(self):
        """Measures stage duration and ensures latency profiling is recorded."""
        graph = build_graph()
        latencies: Dict[str, float] = {}

        def timed_run(initial_state: Dict[str, Any]) -> SwarmState:
            state = SwarmState(**initial_state)
            for step in graph.nodes:
                node_name = step["name"]
                action = step["action"]
                t0 = time.perf_counter()
                state = action(state)
                t1 = time.perf_counter()
                latencies[node_name] = t1 - t0
            return state

        final_state = timed_run({"target_contract": "contracts/solidity/VulnerableVault.sol"})

        self.assertEqual(len(latencies), 7)
        for node in [
            "agent_a_auditor",
            "agent_b_threat_hunter",
            "agent_c_compliance_judge",
            "agent_d_red_teamer",
            "agent_e_incident_commander",
            "agent_f_deep_logic",
            "agent_g_guardrail",
        ]:
            self.assertIn(node, latencies)
            self.assertGreaterEqual(latencies[node], 0.0)

        self.assertEqual(final_state.get("metadata", {}).get("agent_g_executed"), True)

    def test_state_serialization_round_trip(self):
        """Verifies complete serialization and deserialization fidelity for SwarmState."""
        state = run_swarm_pipeline(target_contract="contracts/solidity/VulnerableVault.sol")

        serialized = json.dumps(state)
        self.assertIsInstance(serialized, str)

        deserialized = json.loads(serialized)
        restored_state = SwarmState(**deserialized)

        self.assertEqual(restored_state["target_contract"], state["target_contract"])
        self.assertEqual(len(restored_state["findings"]), len(state["findings"]))
        self.assertEqual(restored_state["current_stage"], state["current_stage"])
        self.assertEqual(
            restored_state["metadata"]["sanitization_status"],
            state["metadata"]["sanitization_status"],
        )

    def test_broker_store_state_persistence(self):
        """Validates writing and reading swarm findings to the broker store."""
        state = run_swarm_pipeline(target_contract="contracts/solidity/VulnerableVault.sol")

        findings = state.get("findings", [])
        self.assertGreater(len(findings), 0)

        saved_ids = []
        for finding in findings:
            payload = dict(finding)
            payload["id"] = finding.get("finding_id", "FINDING-TEST")
            payload["severity"] = finding.get("severity", finding.get("severity_level", "MEDIUM"))
            payload["title"] = finding.get("category", "Swarm Security Finding")
            fid = self.store.write_finding(payload)
            saved_ids.append(fid)

        self.assertEqual(len(saved_ids), len(findings))

        first_finding = self.store.get_finding(saved_ids[0])
        self.assertIsNotNone(first_finding)
        self.assertEqual(first_finding["id"], saved_ids[0])
        self.assertIn("details", first_finding)

        all_findings = self.store.list_findings()
        self.assertEqual(len(all_findings), len(findings))

    def test_deterministic_replay_consistency(self):
        """Runs multiple sequential executions under offline conditions to assert deterministic reproducibility."""
        runs = []
        for _ in range(2):
            res = run_swarm_pipeline(target_contract="contracts/solidity/VulnerableVault.sol")
            runs.append(res)

        self.assertEqual(len(runs[0]["findings"]), len(runs[1]["findings"]))
        self.assertEqual(runs[0]["current_stage"], runs[1]["current_stage"])
        self.assertEqual(
            runs[0]["metadata"]["sanitization_status"],
            runs[1]["metadata"]["sanitization_status"],
        )
        self.assertEqual(
            runs[0]["metadata"]["terminal_gate_cleared"],
            runs[1]["metadata"]["terminal_gate_cleared"],
        )


if __name__ == "__main__":
    unittest.main()
