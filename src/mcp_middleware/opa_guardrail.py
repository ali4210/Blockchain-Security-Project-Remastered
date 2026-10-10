"""
Task P09-003: Zone 4 — MCP OPA Guardrail Middleware.
Intercepts all MCP agent tool calls, evaluating contextual authorization
against config/opa/agent_policy.rego least-privilege rules before execution.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Set


@dataclass(frozen=True)
class OpaEvaluationResult:
    allowed: bool
    principal: str
    action: str
    tool: str
    deny_reasons: list[str] = field(default_factory=list)


class McpOpaGuardrail:
    """Enforces Open Policy Agent least-privilege rules on every MCP tool dispatch."""

    def __init__(self, policy_path: str = "config/opa/agent_policy.rego"):
        self.policy_path = Path(policy_path)
        if not self.policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {self.policy_path}")

        # Authoritative tool registries mirroring config/opa/agent_policy.rego
        self.agent_allowed_tools: Set[str] = {
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
        self.operator_exclusive_tools: Set[str] = {
            "writeRemediationPlan",
            "isolateHost",
            "applyNetworkPolicy",
            "pauseCircuitBreaker",
            "sealEvidenceVault",
            "signReleaseToken",
            "triggerPublicMirror",
            "modifyBrokerStore",
        }

    def evaluate_request(
        self,
        principal: str,
        action: str,
        tool: str,
        resource: Optional[str] = None,
    ) -> OpaEvaluationResult:
        """Evaluates input against least-privilege policy rules with fail-closed default."""
        deny_reasons = []

        if not principal:
            deny_reasons.append("Missing principal")
            return OpaEvaluationResult(False, principal, action, tool, deny_reasons)

        if not action or not tool:
            deny_reasons.append("Missing action or tool identifier")
            return OpaEvaluationResult(False, principal, action, tool, deny_reasons)

        is_agent = principal == "agent" or principal.startswith("agent_")
        is_operator = principal == "soc-operator"
        is_compliance = principal == "compliance-officer"

        # Check unknown principal
        if not (is_agent or is_operator or is_compliance):
            deny_reasons.append(f"Unknown or unauthorized principal: {principal}")
            return OpaEvaluationResult(False, principal, action, tool, deny_reasons)

        # Check unregistered tool
        if tool not in self.agent_allowed_tools and tool not in self.operator_exclusive_tools:
            deny_reasons.append(f"Tool not recognized in system capability registry: {tool}")
            return OpaEvaluationResult(False, principal, action, tool, deny_reasons)

        # Rule 1: Human soc-operator
        if is_operator:
            return OpaEvaluationResult(True, principal, action, tool)

        # Rule 2: Autonomous agent
        if is_agent:
            if tool in self.operator_exclusive_tools:
                deny_reasons.append(
                    "Autonomous agent is prohibited from executing mutation or active remediation tools"
                )
                return OpaEvaluationResult(False, principal, action, tool, deny_reasons)

            if action != "read":
                deny_reasons.append("Autonomous agent action must be read-only")
                return OpaEvaluationResult(False, principal, action, tool, deny_reasons)

            if tool in self.agent_allowed_tools:
                return OpaEvaluationResult(True, principal, action, tool)

        # Rule 3: Compliance officer (read-only compliance tasks)
        if is_compliance:
            if action == "read" and tool in self.agent_allowed_tools:
                return OpaEvaluationResult(True, principal, action, tool)
            deny_reasons.append("Compliance officer restricted from active operational tool calls")
            return OpaEvaluationResult(False, principal, action, tool, deny_reasons)

        deny_reasons.append("Default deny: action not authorized by policy")
        return OpaEvaluationResult(False, principal, action, tool, deny_reasons)

    def dispatch(
        self,
        principal: str,
        action: str,
        tool: str,
        handler: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Evaluates policy guardrail before invoking tool handler; fails closed with PermissionError."""
        eval_result = self.evaluate_request(principal=principal, action=action, tool=tool)

        if not eval_result.allowed:
            reasons_str = "; ".join(eval_result.deny_reasons)
            raise PermissionError(
                f"OPA Policy Denial: principal '{principal}' denied from tool '{tool}' "
                f"(action='{action}'). Reasons: {reasons_str}"
            )

        # Authorized: execute tool handler
        return handler(*args, **kwargs)
