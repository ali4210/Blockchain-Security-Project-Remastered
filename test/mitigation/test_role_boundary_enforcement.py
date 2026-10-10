"""
Task P09-006: Integration tests for role boundary enforcement.
Validates agent denial for remediation write/live isolation and operator
allowance for authorized actions across all swarm agents (A-G).
"""

import unittest
from src.mcp_middleware.opa_guardrail import McpOpaGuardrail


class TestRoleBoundaryEnforcement(unittest.TestCase):
    def setUp(self):
        self.guardrail = McpOpaGuardrail()
        self.agent_roles = [
            "agent",
            "agent_a",
            "agent_b",
            "agent_c",
            "agent_d",
            "agent_e",
            "agent_f",
            "agent_g",
        ]
        self.mutation_tools = [
            "writeRemediationPlan",
            "isolateHost",
            "applyNetworkPolicy",
            "pauseCircuitBreaker",
            "sealEvidenceVault",
            "signReleaseToken",
            "triggerPublicMirror",
            "modifyBrokerStore",
        ]
        self.read_tools = [
            "listAttackPaths",
            "planRemediation",
            "queryWeb3Rpc",
            "queryTelemetry",
            "getAstMasked",
            "readStorage",
            "readAuditLogs",
            "simulateNetworkPolicy",
            "evaluateDreadScore",
        ]

    def test_all_agents_denied_for_all_mutation_tools(self):
        def dummy_action():
            return "EXECUTED"

        for role in self.agent_roles:
            for tool in self.mutation_tools:
                with self.assertRaises(
                    PermissionError,
                    msg=f"Role '{role}' should be denied from mutation tool '{tool}'",
                ) as ctx:
                    self.guardrail.dispatch(
                        principal=role,
                        action="write",
                        tool=tool,
                        handler=dummy_action,
                    )
                self.assertIn("OPA Policy Denial", str(ctx.exception))

    def test_all_agents_denied_for_live_isolation_execute_action(self):
        def dummy_action():
            return "ISOLATED"

        for role in self.agent_roles:
            for tool in ["isolateHost", "applyNetworkPolicy"]:
                with self.assertRaises(
                    PermissionError,
                    msg=f"Role '{role}' must be denied from isolation tool '{tool}' with action 'execute'",
                ):
                    self.guardrail.dispatch(
                        principal=role,
                        action="execute",
                        tool=tool,
                        handler=dummy_action,
                    )

    def test_all_agents_allowed_for_read_tools(self):
        def dummy_read(target):
            return f"READ_{target}"

        for role in self.agent_roles:
            for tool in self.read_tools:
                res = self.guardrail.dispatch(
                    principal=role,
                    action="read",
                    tool=tool,
                    handler=dummy_read,
                    target="sample",
                )
                self.assertEqual(res, "READ_sample")

    def test_soc_operator_allowed_for_all_authorized_tools(self):
        def dummy_exec(target):
            return f"OPERATOR_{target}"

        all_tools = self.read_tools + self.mutation_tools
        for tool in all_tools:
            res = self.guardrail.dispatch(
                principal="soc-operator",
                action="write" if tool in self.mutation_tools else "read",
                tool=tool,
                handler=dummy_exec,
                target=tool,
            )
            self.assertEqual(res, f"OPERATOR_{tool}")

    def test_compliance_officer_boundary(self):
        def dummy_call():
            return "COMPLIANCE_OK"

        # Allowed read
        res = self.guardrail.dispatch(
            principal="compliance-officer",
            action="read",
            tool="readAuditLogs",
            handler=dummy_call,
        )
        self.assertEqual(res, "COMPLIANCE_OK")

        # Denied remediation write
        with self.assertRaises(PermissionError):
            self.guardrail.dispatch(
                principal="compliance-officer",
                action="write",
                tool="writeRemediationPlan",
                handler=dummy_call,
            )


if __name__ == "__main__":
    unittest.main()
