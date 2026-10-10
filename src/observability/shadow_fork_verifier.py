"""
Task P08-004: Agent E Shadow-Fork Transaction Verifier & Persistent Network Logging.
Wires Agent E to replay suspicious RASP findings in an isolated local shadow-fork,
evaluates state transitions and balance drains, generates containment playbooks,
and logs structured execution records to persistent append-only audit files.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from src.observability.rasp_shield import RaspFinding, ThreatSeverity
from src.agents.agent_e_incident_commander import parse_incident_commander_report


class ShadowReplayOutcome(str, Enum):
    CONFIRMED_EXPLOIT = "CONFIRMED_EXPLOIT"
    BENIGN_REVERT = "BENIGN_REVERT"
    STATE_DIVERGENCE = "STATE_DIVERGENCE"
    EXECUTION_CLEAN = "EXECUTION_CLEAN"


@dataclass(frozen=True)
class ShadowForkConfig:
    network_id: str = "hardhat-shadow-fork"
    rpc_url: str = "http://127.0.0.1:8545"
    fork_block: int = 19_000_000
    timeout_seconds: float = 5.0
    audit_log_path: str = "audit/shadow_network_logs.jsonl"


@dataclass
class ShadowExecutionTrace:
    tx_hash: str
    target_contract: str
    caller: str
    success: bool
    gas_used: int
    balance_delta_wei: int
    state_mutations_count: int
    revert_reason: Optional[str] = None
    outcome: ShadowReplayOutcome = ShadowReplayOutcome.EXECUTION_CLEAN


@dataclass
class AgentEShadowVerificationReport:
    finding_id: str
    target: str
    outcome: ShadowReplayOutcome
    severity_level: str
    containment_status: str
    playbook_actions: List[str]
    execution_trace: Dict[str, Any]
    audit_record_digest: str
    verified_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "target": self.target,
            "outcome": self.outcome.value,
            "severity_level": self.severity_level,
            "containment_status": self.containment_status,
            "playbook_actions": self.playbook_actions,
            "execution_trace": self.execution_trace,
            "audit_record_digest": self.audit_record_digest,
            "verified_at": self.verified_at,
        }


class ShadowForkVerifier:
    """Manages isolated shadow-fork transaction replays and structured network logging."""

    def __init__(
        self,
        config: Optional[ShadowForkConfig] = None,
        replay_executor: Optional[Callable[[str, str, Dict[str, Any]], ShadowExecutionTrace]] = None,
    ):
        self.config = config or ShadowForkConfig()
        self._replay_executor = replay_executor or self._default_mock_replay_executor
        # Ensure log directory exists
        Path(self.config.audit_log_path).parent.mkdir(parents=True, exist_ok=True)

    def _default_mock_replay_executor(
        self, target_contract: str, tx_hash: str, params: Dict[str, Any]
    ) -> ShadowExecutionTrace:
        """Default deterministic local executor for shadow replay simulation."""
        call_depth = params.get("call_depth", 1)
        value = params.get("value", 0)

        # If abnormal call depth or simulation revert was noted in signals
        if call_depth > 4 or params.get("sim_reverted", False):
            return ShadowExecutionTrace(
                tx_hash=tx_hash,
                target_contract=target_contract,
                caller=params.get("from", "0x0"),
                success=True,
                gas_used=185_000,
                balance_delta_wei=-10_000_000_000_000_000_000,  # 10 ETH drained
                state_mutations_count=4,
                revert_reason=None,
                outcome=ShadowReplayOutcome.CONFIRMED_EXPLOIT,
            )

        return ShadowExecutionTrace(
            tx_hash=tx_hash,
            target_contract=target_contract,
            caller=params.get("from", "0x0"),
            success=True,
            gas_used=21_000,
            balance_delta_wei=0,
            state_mutations_count=0,
            revert_reason=None,
            outcome=ShadowReplayOutcome.EXECUTION_CLEAN,
        )

    def replay_transaction(
        self, target_contract: str, tx_hash: str, params: Dict[str, Any]
    ) -> ShadowExecutionTrace:
        """Executes transaction replay in isolated shadow fork."""
        return self._replay_executor(target_contract, tx_hash, params)

    def record_network_log(self, record: Dict[str, Any]) -> str:
        """Appends persistent structured log entry to JSONL with SHA-256 digest."""
        log_file = Path(self.config.audit_log_path)
        record_bytes = json.dumps(record, sort_keys=True).encode("utf-8")
        digest = hashlib.sha256(record_bytes).hexdigest()
        record_entry = {
            "record_digest": digest,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "payload": record,
        }

        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record_entry) + "\n")

        return digest

    def verify_rasp_finding(
        self,
        finding: RaspFinding,
        target_name: str,
        replay_params: Optional[Dict[str, Any]] = None,
    ) -> AgentEShadowVerificationReport:
        """Replays suspicious RASP finding in shadow fork and triggers Agent E assessment."""
        params = replay_params or {}
        # Propagate indicators from finding
        for s in finding.signals:
            if s.indicator == "ABNORMAL_CALL_DEPTH":
                params["call_depth"] = s.details.get("call_depth", 5)
            elif s.indicator == "TRACE_SIMULATION_REVERT":
                params["sim_reverted"] = True

        params.setdefault("from", "0xattacker")

        # Step 1: Replay in shadow fork
        trace = self.replay_transaction(finding.target_contract, finding.tx_hash, params)

        # Step 2: Agent E triage synthesis
        if trace.outcome == ShadowReplayOutcome.CONFIRMED_EXPLOIT:
            model_response = (
                f"[OFFLINE_FALLBACK] Target: {target_name}. "
                f"Drained: {trace.balance_delta_wei} wei. Exploitation confirmed."
            )
            agent_e_assessment = parse_incident_commander_report(model_response, target_name)
            sev_level = "SEV-1"
            status = "IMMEDIATE_ACTION_REQUIRED"
            playbook = agent_e_assessment.get("playbook_actions", [
                "TRIGGER_PAUSE_CIRCUIT_BREAKER",
                "NOTIFY_SECURITY_MULTISIG",
                "ISOLATE_RPC_INGEST_NODE",
            ])
        else:
            sev_level = "SEV-4"
            status = "MONITORING_ONLY"
            playbook = ["LOG_TELEMETRY", "MAINTAIN_OBSERVATION"]

        # Step 3: Record persistent network audit log
        audit_payload = {
            "finding_id": finding.finding_id,
            "target": target_name,
            "contract": finding.target_contract,
            "tx_hash": finding.tx_hash,
            "outcome": trace.outcome.value,
            "severity_level": sev_level,
            "gas_used": trace.gas_used,
            "balance_delta_wei": trace.balance_delta_wei,
            "playbook_actions": playbook,
        }
        digest = self.record_network_log(audit_payload)

        return AgentEShadowVerificationReport(
            finding_id=finding.finding_id,
            target=target_name,
            outcome=trace.outcome,
            severity_level=sev_level,
            containment_status=status,
            playbook_actions=playbook,
            execution_trace={
                "tx_hash": trace.tx_hash,
                "gas_used": trace.gas_used,
                "balance_delta_wei": trace.balance_delta_wei,
                "state_mutations_count": trace.state_mutations_count,
                "revert_reason": trace.revert_reason,
            },
            audit_record_digest=digest,
        )
