"""
Task P13-007: Compliance Open Policy Agent (OPA) Engine Wrapper.
Enforces role boundaries, preventing autonomous agents from approving or filing SARs,
and ensuring that on-chain transaction inclusion blocking is universally rejected.
"""

from pathlib import Path
from typing import Any, Dict, Optional
import hmac
import hashlib


class CompliancePolicyEngine:
    """
    Evaluates compliance authorization requests according to policies/compliance_policy.rego.
    """

    POLICY_PATH = Path("policies/compliance_policy.rego")

    READ_ACTIONS = {
        "screen_address",
        "evaluate_aml",
        "verify_zk_attestation",
        "read_draft_sar",
    }

    DRAFT_ACTIONS = {
        "generate_draft_sar",
    }

    OFFICER_EXCLUSIVE_ACTIONS = {
        "approve_sar_report",
        "file_sar_report",
        "export_sar_report",
    }

    AUTONOMOUS_AGENTS = {
        "agent_a_auditor",
        "agent_b_threat_hunter",
        "agent_c_compliance_judge",
        "agent_d_red_teamer",
        "agent_e_incident_commander",
        "agent_f_logic_analyzer",
        "agent_g_guardrail",
    }

    def __init__(self, secret_key: bytes = b"compliance-officer-secret-key-32b"):
        self.secret_key = secret_key

    def verify_token(self, token: Optional[Dict[str, Any]], current_timestamp: float) -> bool:
        """
        Verifies compliance officer bearer token structure, signature, and expiration.
        """
        if not token:
            return False

        if token.get("role") != "compliance_officer":
            return False

        if float(token.get("expires_at", 0)) <= current_timestamp:
            return False

        sig = token.get("signature")
        if not sig:
            return False

        # Validate signature integrity: HMAC-SHA256 over role:expires_at:officer_id
        payload = f"{token.get('role')}:{token.get('expires_at')}:{token.get('officer_id')}".encode("utf-8")
        expected_sig = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected_sig)

    def evaluate(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates input against compliance security invariants.
        """
        principal = input_data.get("principal")
        action = input_data.get("action")
        timestamp = float(input_data.get("current_timestamp", 0))
        token = input_data.get("token")

        # Invariant 1: block_transaction_inclusion is universally prohibited
        if action == "block_transaction_inclusion":
            return {
                "allow": False,
                "reason": "Architectural Invariant: Compliance monitoring layer cannot block blockchain transaction inclusion.",
            }

        # Invariant 2: Autonomous agents are strictly denied for officer-exclusive actions
        if principal in self.AUTONOMOUS_AGENTS and action in self.OFFICER_EXCLUSIVE_ACTIONS:
            return {
                "allow": False,
                "reason": f"Agent '{principal}' is strictly denied for compliance approval/filing action '{action}'.",
            }

        # Rule 1: Read and screen actions
        if action in self.READ_ACTIONS:
            if principal in self.AUTONOMOUS_AGENTS or principal in {"compliance_officer", "soc_operator"}:
                return {"allow": True, "reason": "Authorized read/screening action."}

        # Rule 2: Draft generation
        if action in self.DRAFT_ACTIONS:
            if principal in {"compliance_officer", "soc_operator", "agent_c_compliance_judge"}:
                return {"allow": True, "reason": "Authorized drafting action."}

        # Rule 3: Officer exclusive actions
        if action in self.OFFICER_EXCLUSIVE_ACTIONS:
            if principal == "compliance_officer":
                if self.verify_token(token, timestamp):
                    return {"allow": True, "reason": "Compliance officer authenticated with valid token."}
                return {"allow": False, "reason": "Invalid, expired, or untrusted compliance officer token."}

        return {"allow": False, "reason": "Default deny: unauthorized principal or action."}
