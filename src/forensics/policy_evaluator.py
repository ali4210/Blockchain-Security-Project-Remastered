"""
Task P10B-001: Forensic Policy Evaluator.
Evaluates DFIR authorization requests against config/opa/forensic_policy.rego rules.
Provides deterministic local evaluation with strict deny-by-default behavior.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Set

AGENT_ROLES: Set[str] = {
    "agent",
    "agent_a",
    "agent_b",
    "agent_c",
    "agent_d",
    "agent_e",
    "agent_f",
    "agent_g",
}

DESTRUCTIVE_ACTIONS: Set[str] = {
    "delete",
    "update",
    "modify",
    "truncate",
    "overwrite",
}

DESTRUCTIVE_TOOLS: Set[str] = {
    "deleteEvidence",
    "updateEvidence",
    "truncateLog",
    "dropTrigger",
}


@dataclass(frozen=True)
class PolicyDecision:
    allow: bool
    reason: Optional[str] = None


class ForensicPolicyEvaluator:
    """Evaluates DFIR access requests enforcing Zone 5 forensic immutability rules."""

    def __init__(self, policy_path: str = "config/opa/forensic_policy.rego"):
        self.policy_path = Path(policy_path)
        if not self.policy_path.is_file():
            raise FileNotFoundError(f"Forensic policy definition not found at: {self.policy_path}")

    def evaluate(self, request: Dict[str, Any]) -> PolicyDecision:
        """Evaluates authorization request dictionary containing principal, action, target, tool."""
        principal = request.get("principal", "")
        action = request.get("action", "")
        target = request.get("target", "")
        tool = request.get("tool", "")

        # 1. Universal immutability check: Destructive mutations forbidden for everyone
        if action in DESTRUCTIVE_ACTIONS or tool in DESTRUCTIVE_TOOLS:
            return PolicyDecision(
                allow=False,
                reason="Destructive operations on sealed evidence are strictly forbidden for all principals",
            )

        # 2. SOC Operator: Authorized for DFIR operations
        if principal == "soc-operator":
            if action in {
                "acquire",
                "seal",
                "dispatch_working_copy",
                "verify_vault",
                "read_derived",
                "read_custody",
            }:
                return PolicyDecision(allow=True)

        # 3. Compliance Officer: Audit and custody read access
        if principal == "compliance-officer":
            if action in {"read_custody", "read_derived", "verify_vault"}:
                return PolicyDecision(allow=True)

        # 4. Swarm Agents: Read-only access strictly to derived/sanitized artifacts
        if principal in AGENT_ROLES:
            if action == "read_derived" and target in {
                "working_copy",
                "sanitized_artifact",
                "derived_report",
            }:
                return PolicyDecision(allow=True)
            return PolicyDecision(
                allow=False,
                reason="Autonomous agents are strictly forbidden from acquiring or modifying raw forensic evidence",
            )

        # Default Deny
        return PolicyDecision(
            allow=False,
            reason="Unauthorized principal or action not permitted under DFIR policy",
        )

    def enforce(self, request: Dict[str, Any]) -> None:
        """Enforces policy decision; raises PermissionError on denial."""
        decision = self.evaluate(request)
        if not decision.allow:
            raise PermissionError(f"Forensic policy violation: {decision.reason}")
