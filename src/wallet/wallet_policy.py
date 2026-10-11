"""
Task P12-011: Wallet OPA Policy Engine Wrapper.
Provides deterministic Python evaluation of Zone 7 wallet access control,
enforcing RBAC boundaries, token validity, and autonomous agent restrictions.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


ALLOWED_AGENT_ACTIONS: Set[str] = {
    "read",
    "audit",
    "simulate",
    "observe",
    "evaluate_status",
    "query_telemetry",
}

FORBIDDEN_AGENT_ACTIONS: Set[str] = {
    "export_private_key",
    "shamir_reconstruct",
    "hsm_sign",
    "broadcast_transaction",
    "drain_balance",
    "rotate_master_key",
}

AUTHORIZED_OPERATOR_ACTIONS: Set[str] = {
    "emergency_pause",
    "hsm_sign",
    "shamir_reconstruct",
    "dispatch_mitigation",
    "rotate_master_key",
}

VALID_AGENT_PRINCIPALS: Set[str] = {
    "Agent-A",
    "Agent-B",
    "Agent-C",
    "Agent-D",
    "Agent-E",
    "Agent-F",
    "Agent-G",
}

VALID_OPERATOR_PRINCIPALS: Set[str] = {
    "soc_operator",
    "lead_incident_commander",
}


@dataclass(frozen=True)
class WalletPolicyDecision:
    allow: bool
    principal: str
    action: str
    reason: str


class WalletPolicyEvaluator:
    """
    Evaluates wallet authorization decisions adhering to policies/wallet_policy.rego.
    """

    def __init__(self, rego_path: Optional[Path] = None):
        self.rego_path = rego_path or Path("policies/wallet_policy.rego")

    def evaluate(
        self,
        principal: str,
        action: str,
        token: Optional[Dict[str, Any]] = None,
        current_time: Optional[float] = None,
    ) -> WalletPolicyDecision:
        now = current_time if current_time is not None else datetime.now(timezone.utc).timestamp()

        # Rule 1: Autonomous Agent Evaluation
        if principal in VALID_AGENT_PRINCIPALS:
            if action in FORBIDDEN_AGENT_ACTIONS:
                return WalletPolicyDecision(
                    allow=False,
                    principal=principal,
                    action=action,
                    reason=f"Agent principal '{principal}' strictly forbidden from action '{action}'",
                )
            if action in ALLOWED_AGENT_ACTIONS:
                return WalletPolicyDecision(
                    allow=True,
                    principal=principal,
                    action=action,
                    reason="Agent permitted for read-only / simulation action",
                )
            return WalletPolicyDecision(
                allow=False,
                principal=principal,
                action=action,
                reason=f"Action '{action}' is not in allowed agent actions",
            )

        # Rule 2: Operator Evaluation
        if principal in VALID_OPERATOR_PRINCIPALS:
            if action in AUTHORIZED_OPERATOR_ACTIONS:
                if not token:
                    return WalletPolicyDecision(
                        allow=False,
                        principal=principal,
                        action=action,
                        reason="Missing mandatory authorization token for operator action",
                    )
                if not token.get("valid", False):
                    return WalletPolicyDecision(
                        allow=False,
                        principal=principal,
                        action=action,
                        reason="Authorization token is invalid or unauthenticated",
                    )
                if token.get("expires_at", 0) <= now:
                    return WalletPolicyDecision(
                        allow=False,
                        principal=principal,
                        action=action,
                        reason="Authorization token has expired",
                    )
                if token.get("role") != principal:
                    return WalletPolicyDecision(
                        allow=False,
                        principal=principal,
                        action=action,
                        reason=f"Token role '{token.get('role')}' does not match principal '{principal}'",
                    )
                return WalletPolicyDecision(
                    allow=True,
                    principal=principal,
                    action=action,
                    reason="Operator authenticated with valid token",
                )
            return WalletPolicyDecision(
                allow=False,
                principal=principal,
                action=action,
                reason=f"Operator action '{action}' is unclassified or unauthorized",
            )

        # Rule 3: Compliance Officer
        if principal == "compliance_officer":
            if action in ALLOWED_AGENT_ACTIONS:
                return WalletPolicyDecision(
                    allow=True,
                    principal=principal,
                    action=action,
                    reason="Compliance officer permitted for observation",
                )
            return WalletPolicyDecision(
                allow=False,
                principal=principal,
                action=action,
                reason=f"Compliance officer cannot perform mutation action '{action}'",
            )

        # Default Deny
        return WalletPolicyDecision(
            allow=False,
            principal=principal,
            action=action,
            reason=f"Unknown or unauthorized principal '{principal}'",
        )
