"""
Task P11-010: Unit tests for Agent Consensus Integration Client.
Validates client creation for Agents B, E, and G, rate-limiting enforcement,
OPA policy denial on mutation tools, and specialized query convenience routines.
"""

import time
import unittest

from src.consensus.agent_consensus_client import (
    AgentConsensusClient,
    RateLimitExceededError,
)
from src.consensus.consensus_mcp import ConsensusMcpRegistry
from src.consensus.consensus_policy import ConsensusPolicyEvaluator


class TestAgentConsensusClient(unittest.TestCase):
    def setUp(self):
        self.mcp = ConsensusMcpRegistry()
        self.policy = ConsensusPolicyEvaluator(rego_policy_path="policy/consensus_boundary.rego")

    def test_unauthorized_agent_principal_rejected_at_instantiation(self):
        with self.assertRaises(ValueError) as ctx:
            AgentConsensusClient("agent_x")
        self.assertIn("Unauthorized or unconfigured agent identifier", str(ctx.exception))

    def test_agent_b_telemetry_and_reorg_queries_succeed(self):
        client = AgentConsensusClient("agent_b", mcp_registry=self.mcp, policy_evaluator=self.policy)
        res_mempool = client.query_pipeline_telemetry(limit=10)
        self.assertEqual(res_mempool["status"], "success")

        res_reorg = client.query_reorg_history()
        self.assertEqual(res_reorg["status"], "success")

    def test_agent_e_network_stability_query_succeeds(self):
        client = AgentConsensusClient("agent_e", mcp_registry=self.mcp, policy_evaluator=self.policy)
        res_stability = client.query_network_stability()
        self.assertEqual(res_stability["status"], "success")
        self.assertIn("topology", res_stability["data"])
        self.assertIn("concentration", res_stability["data"])

    def test_agent_g_incident_consensus_context_query_succeeds(self):
        client = AgentConsensusClient("agent_g", mcp_registry=self.mcp, policy_evaluator=self.policy)
        res_context = client.query_incident_consensus_context(suspected_miner="pool-9")
        self.assertEqual(res_context["status"], "success")
        self.assertIn("reorgs", res_context["data"])
        self.assertIn("eclipse", res_context["data"])
        self.assertIn("selfish_mining", res_context["data"])

    def test_agent_strictly_blocked_from_mitigation_actions(self):
        client = AgentConsensusClient("agent_g", mcp_registry=self.mcp, policy_evaluator=self.policy)
        for forbidden in ["mitigate", "evict_peer", "slash_validator", "override_gate"]:
            with self.assertRaises(PermissionError) as ctx:
                client.execute_tool(forbidden)
            self.assertIn("denied execution", str(ctx.exception))

    def test_rate_limiting_exhaustion_raises_error(self):
        # Configure tight bucket: capacity 2, slow refill 0.1
        tight_client = AgentConsensusClient(
            "agent_b",
            mcp_registry=self.mcp,
            policy_evaluator=self.policy,
            rate_limit_capacity=2.0,
            rate_limit_refill_per_sec=0.1,
        )

        # First 2 queries consume capacity
        res1 = tight_client.execute_tool("get_topology_summary")
        self.assertEqual(res1["status"], "success")
        res2 = tight_client.execute_tool("get_topology_summary")
        self.assertEqual(res2["status"], "success")

        # Third immediate query breaches rate limit
        with self.assertRaises(RateLimitExceededError) as ctx:
            tight_client.execute_tool("get_topology_summary")
        self.assertIn("exceeded consensus query rate limit", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
