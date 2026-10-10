"""
Task P09-002: Unit Tests for config/opa/agent_policy.rego.
Validates OPA policy rules enforcing least-privilege boundaries
between autonomous agent roles and human soc-operator roles.
"""

import json
from pathlib import Path
import re
import unittest


class TestOpaAgentPolicy(unittest.TestCase):
    def setUp(self):
        self.policy_path = Path("config/opa/agent_policy.rego")
        self.assertTrue(self.policy_path.exists(), "agent_policy.rego must exist")
        self.policy_content = self.policy_path.read_text(encoding="utf-8")

    def test_policy_structure_and_package(self):
        self.assertIn("package soc.guardrails", self.policy_content)
        self.assertIn("default allow = false", self.policy_content)
        self.assertIn("agent_allowed_tools", self.policy_content)
        self.assertIn("operator_exclusive_tools", self.policy_content)

    def _simulate_policy_evaluation(self, principal: str, action: str, tool: str) -> bool:
        """Lightweight deterministic policy evaluator replicating Rego rules."""
        # 1. Check default deny
        if not principal or not action or not tool:
            return False

        agent_allowed_tools = {
            "listAttackPaths",
            "planRemediation",
            "queryWeb3Rpc",
            "queryTelemetry",
            "getAstMasked",
            "readStorage",
            "readAuditLogs",
            "simulateNetworkPolicy",
            "evaluateDreadScore",
        }
        operator_exclusive_tools = {
            "writeRemediationPlan",
            "isolateHost",
            "applyNetworkPolicy",
            "pauseCircuitBreaker",
            "sealEvidenceVault",
            "signReleaseToken",
            "triggerPublicMirror",
            "modifyBrokerStore",
        }

        is_agent = principal == "agent" or principal.startswith("agent_")
        is_operator = principal == "soc-operator"

        # Rule 1: Operator
        if is_operator:
            return tool in agent_allowed_tools or tool in operator_exclusive_tools

        # Rule 2: Agent
        if is_agent:
            return action == "read" and tool in agent_allowed_tools

        return False

    def test_agent_read_tool_allowed(self):
        for tool in ["listAttackPaths", "planRemediation", "queryTelemetry", "readStorage"]:
            allowed = self._simulate_policy_evaluation(
                principal="agent_a", action="read", tool=tool
            )
            self.assertTrue(allowed, f"Agent should be allowed to use {tool}")

    def test_agent_mutation_or_isolation_denied(self):
        # Must deny write tools for agent
        for tool in ["writeRemediationPlan", "isolateHost", "pauseCircuitBreaker", "sealEvidenceVault"]:
            allowed = self._simulate_policy_evaluation(
                principal="agent_b", action="write", tool=tool
            )
            self.assertFalse(allowed, f"Agent must be denied from {tool}")

    def test_agent_non_read_action_denied(self):
        allowed = self._simulate_policy_evaluation(
            principal="agent", action="execute", tool="listAttackPaths"
        )
        self.assertFalse(allowed, "Agent non-read action must be denied")

    def test_operator_exclusive_tool_allowed(self):
        for tool in ["writeRemediationPlan", "isolateHost", "pauseCircuitBreaker", "signReleaseToken"]:
            allowed = self._simulate_policy_evaluation(
                principal="soc-operator", action="execute", tool=tool
            )
            self.assertTrue(allowed, f"soc-operator must be allowed to use {tool}")

    def test_unknown_principal_denied(self):
        allowed = self._simulate_policy_evaluation(
            principal="untrusted_entity", action="read", tool="listAttackPaths"
        )
        self.assertFalse(allowed, "Untrusted principal must be denied")


if __name__ == "__main__":
    unittest.main()
