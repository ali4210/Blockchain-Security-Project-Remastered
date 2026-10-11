"""
Task P11-009: Consensus OPA Policy Evaluator.
Enforces zero-trust role boundaries: autonomous agents may read/correlate;
only authenticated human SOC operators may mitigate or override consensus gates.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


@dataclass(frozen=True)
class PolicyEvaluationResult:
    allowed: bool
    principal: str
    action: str
    resource: str
    reason: str
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ConsensusPolicyEvaluator:
    """Evaluates access requests against consensus role boundary policies."""

    AGENT_PRINCIPALS: Set[str] = {
        "agent_a", "agent_b", "agent_c", "agent_d", "agent_e", "agent_f", "agent_g"
    }
    OPERATOR_PRINCIPALS: Set[str] = {"operator", "soc_lead", "soc_operator"}
    COMPLIANCE_PRINCIPALS: Set[str] = {"compliance_officer"}

    READ_ACTIONS: Set[str] = {
        "read",
        "observe",
        "correlate",
        "get_mempool_telemetry",
        "get_topology_summary",
        "get_reorg_history",
        "get_concentration_metrics",
        "evaluate_selfish_mining",
        "evaluate_eclipse_status",
    }

    MITIGATION_ACTIONS: Set[str] = {
        "mitigate",
        "evict_peer",
        "slash_validator",
        "override_gate",
        "quarantine_node",
        "isolate_network",
        "execute_action",
    }

    def __init__(self, rego_policy_path: Optional[str] = "policy/consensus_boundary.rego"):
        self.rego_policy_path = rego_policy_path
        self._policy_text: Optional[str] = None
        if rego_policy_path and Path(rego_policy_path).exists():
            self._policy_text = Path(rego_policy_path).read_text(encoding="utf-8")

    def evaluate(
        self,
        principal: str,
        action: str,
        resource: str = "consensus_engine",
        token_valid: bool = False,
    ) -> PolicyEvaluationResult:
        """
        Evaluates whether a principal is authorized to perform an action on a resource.
        Returns PolicyEvaluationResult.
        """
        now = datetime.now(timezone.utc).timestamp()
        p = principal.lower()
        a = action.lower()

        # Rule 1: Unknown principal
        if (
            p not in self.AGENT_PRINCIPALS
            and p not in self.OPERATOR_PRINCIPALS
            and p not in self.COMPLIANCE_PRINCIPALS
        ):
            return PolicyEvaluationResult(
                allowed=False,
                principal=principal,
                action=action,
                resource=resource,
                reason=f"Unknown or unauthorized principal '{principal}'",
                timestamp=now,
            )

        # Rule 2: Agent principals
        if p in self.AGENT_PRINCIPALS:
            if a in self.READ_ACTIONS:
                return PolicyEvaluationResult(
                    allowed=True,
                    principal=principal,
                    action=action,
                    resource=resource,
                    reason="Agent authorized for read-only consensus telemetry inspection",
                    timestamp=now,
                )
            if a in self.MITIGATION_ACTIONS:
                return PolicyEvaluationResult(
                    allowed=False,
                    principal=principal,
                    action=action,
                    resource=resource,
                    reason="Autonomous agents are strictly prohibited from executing consensus mitigations or overrides",
                    timestamp=now,
                )
            return PolicyEvaluationResult(
                allowed=False,
                principal=principal,
                action=action,
                resource=resource,
                reason=f"Agent denied unapproved action '{action}'",
                timestamp=now,
            )

        # Rule 3: Operator principals
        if p in self.OPERATOR_PRINCIPALS:
            if token_valid:
                return PolicyEvaluationResult(
                    allowed=True,
                    principal=principal,
                    action=action,
                    resource=resource,
                    reason="Human operator authorized with valid credentials",
                    timestamp=now,
                )
            return PolicyEvaluationResult(
                allowed=False,
                principal=principal,
                action=action,
                resource=resource,
                reason="Human operator denied: missing or invalid credentials",
                timestamp=now,
            )

        # Rule 4: Compliance principals
        if p in self.COMPLIANCE_PRINCIPALS:
            if a in self.READ_ACTIONS:
                return PolicyEvaluationResult(
                    allowed=True,
                    principal=principal,
                    action=action,
                    resource=resource,
                    reason="Compliance officer authorized for read-only consensus audit inspection",
                    timestamp=now,
                )
            return PolicyEvaluationResult(
                allowed=False,
                principal=principal,
                action=action,
                resource=resource,
                reason="Compliance officer prohibited from executing mutations or mitigations",
                timestamp=now,
            )

        # Catch-all
        return PolicyEvaluationResult(
            allowed=False,
            principal=principal,
            action=action,
            resource=resource,
            reason="Access denied by policy boundary",
            timestamp=now,
        )
