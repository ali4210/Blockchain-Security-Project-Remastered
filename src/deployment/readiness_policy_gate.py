"""
Task P07-003: Consensus-Rejected Abort Path and Production Readiness-Policy Gate.
Enforces fail-closed deployment aborts when consensus quorum rejects releases or
when production readiness policies are violated.
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.consensus.avs_gate import ConsensusResult, ConsensusStatus
from src.deployment.consensus_deployer import DeploymentPlan, DeploymentReceipt


class AbortReasonCode(str, Enum):
    ERR_CONSENSUS_REJECTED = "ERR_CONSENSUS_REJECTED"
    ERR_POLICY_GATE_FAILED = "ERR_POLICY_GATE_FAILED"
    ERR_MISSING_CERTIFICATE = "ERR_MISSING_CERTIFICATE"
    ERR_UNCONFIGURED_HARDWARE = "ERR_UNCONFIGURED_HARDWARE"


class DeploymentAbortError(RuntimeError):
    """Raised when deployment is aborted by policy or consensus gate."""
    def __init__(self, message: str, event: "DeploymentAbortEvent"):
        super().__init__(message)
        self.event = event


@dataclass(frozen=True)
class DeploymentAbortEvent:
    schemaVersion: int
    eventType: str
    planId: str
    targetContract: str
    targetNetwork: str
    abortCode: AbortReasonCode
    reason: str
    timestamp: str
    eventDigest: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProductionReadinessPolicy:
    enforce_hardware_token: bool = False
    enforce_clean_audit: bool = True
    enforce_consensus_quorum: bool = True
    allowed_networks: List[str] = field(default_factory=lambda: ["local-anvil", "testnet", "mainnet"])


class ReadinessPolicyGate:
    """
    Evaluates deployment readiness policy and consensus status.
    Guarantees fail-closed aborts with zero persisted deployment state.
    """

    SCHEMA_VERSION = 1
    EVENT_TYPE = "deployment-aborted"

    def __init__(
        self,
        policy: Optional[ProductionReadinessPolicy] = None,
        log_path: Optional[Path] = None,
    ):
        self.policy = policy or ProductionReadinessPolicy()
        self.log_path = log_path
        self._abort_history: List[DeploymentAbortEvent] = []

    def compute_event_digest(self, payload: Dict[str, Any]) -> str:
        canonical_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def evaluate_and_assert(
        self,
        plan: DeploymentPlan,
        consensus_result: Optional[ConsensusResult] = None,
        hardware_token_configured: bool = False,
    ) -> None:
        """
        Validates the deployment plan against consensus outcome and readiness policies.
        Raises DeploymentAbortError and emits a canonical DeploymentAbortEvent if invalid.
        """
        ts = datetime.now(timezone.utc).isoformat()

        # 1. Consensus supermajority check
        if self.policy.enforce_consensus_quorum:
            if consensus_result is None:
                self._record_and_raise(
                    plan=plan,
                    code=AbortReasonCode.ERR_MISSING_CERTIFICATE,
                    reason=f"Deployment aborted: Plan '{plan.plan_id}' has no verified QuorumCertificate.",
                    ts=ts,
                )

            # Prioritize explicit rejection status check over certificate absence
            if consensus_result.status == ConsensusStatus.REJECTED or not consensus_result.supermajority_achieved:
                self._record_and_raise(
                    plan=plan,
                    code=AbortReasonCode.ERR_CONSENSUS_REJECTED,
                    reason=(
                        f"Deployment aborted: Consensus gate rejected plan '{plan.plan_id}' "
                        f"(status: {consensus_result.status}, valid votes: {consensus_result.validated_votes}/{consensus_result.total_validators})."
                    ),
                    ts=ts,
                )

            if not consensus_result.certificate:
                self._record_and_raise(
                    plan=plan,
                    code=AbortReasonCode.ERR_MISSING_CERTIFICATE,
                    reason=f"Deployment aborted: Plan '{plan.plan_id}' has no verified QuorumCertificate.",
                    ts=ts,
                )

        # 2. Network policy check
        if plan.target_network not in self.policy.allowed_networks:
            self._record_and_raise(
                plan=plan,
                code=AbortReasonCode.ERR_POLICY_GATE_FAILED,
                reason=f"Deployment aborted: Target network '{plan.target_network}' is not in allowed policy networks.",
                ts=ts,
            )

        # 3. Production hardware policy check
        if plan.target_network == "mainnet" or self.policy.enforce_hardware_token:
            if not hardware_token_configured:
                self._record_and_raise(
                    plan=plan,
                    code=AbortReasonCode.ERR_UNCONFIGURED_HARDWARE,
                    reason="Deployment aborted: Hardware security module/token is unconfigured for production gate.",
                    ts=ts,
                )

    def _record_and_raise(
        self,
        plan: DeploymentPlan,
        code: AbortReasonCode,
        reason: str,
        ts: str,
    ) -> None:
        raw_event = {
            "schemaVersion": self.SCHEMA_VERSION,
            "eventType": self.EVENT_TYPE,
            "planId": plan.plan_id,
            "targetContract": plan.target_contract,
            "targetNetwork": plan.target_network,
            "abortCode": code.value,
            "reason": reason,
            "timestamp": ts,
        }
        digest = self.compute_event_digest(raw_event)

        abort_event = DeploymentAbortEvent(
            schemaVersion=self.SCHEMA_VERSION,
            eventType=self.EVENT_TYPE,
            planId=plan.plan_id,
            targetContract=plan.target_contract,
            targetNetwork=plan.target_network,
            abortCode=code,
            reason=reason,
            timestamp=ts,
            eventDigest=digest,
        )

        self._abort_history.append(abort_event)

        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(abort_event.to_dict()) + "\n")

        raise DeploymentAbortError(reason, abort_event)

    def get_abort_history(self) -> List[DeploymentAbortEvent]:
        return list(self._abort_history)
