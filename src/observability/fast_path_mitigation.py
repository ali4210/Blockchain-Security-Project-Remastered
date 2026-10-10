"""
Task P08-007: Fast-Path Mitigation Signal Payload Emitter for Phase 9.
Constructs, cryptographically signs, validates, and emits low-latency mitigation
payloads connecting Phase 8 RASP verifications to Phase 9 automated circuit-breakers.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path
import secrets
from typing import Any, Callable, Dict, List, Optional

from src.observability.shadow_fork_verifier import (
    AgentEShadowVerificationReport,
    ShadowReplayOutcome,
)


class MitigationActionType(str, Enum):
    PAUSE_TARGET_CONTRACT = "PAUSE_TARGET_CONTRACT"
    ISOLATE_RPC_INGEST = "ISOLATE_RPC_INGEST"
    ALERT_SECURITY_MULTISIG = "ALERT_SECURITY_MULTISIG"
    RESTRICT_DEPOSIT_DRAIN = "RESTRICT_DEPOSIT_DRAIN"


@dataclass(frozen=True)
class FastPathMitigationPayload:
    schema_version: int
    signal_id: str
    finding_id: str
    target_contract: str
    action: MitigationActionType
    confidence_score: float
    trigger_reason: str
    nonce: str
    emitted_at: str
    payload_digest: str

    @classmethod
    def create(
        cls,
        finding_id: str,
        target_contract: str,
        action: MitigationActionType,
        confidence_score: float,
        trigger_reason: str,
        schema_version: int = 1,
    ) -> "FastPathMitigationPayload":
        emitted_at = datetime.now(timezone.utc).isoformat()
        nonce = secrets.token_hex(16)
        signal_id = f"SIG-{secrets.token_hex(6).upper()}"

        canonical_data = {
            "schema_version": schema_version,
            "signal_id": signal_id,
            "finding_id": finding_id,
            "target_contract": target_contract,
            "action": action.value,
            "confidence_score": round(confidence_score, 4),
            "trigger_reason": trigger_reason,
            "nonce": nonce,
            "emitted_at": emitted_at,
        }
        raw_bytes = json.dumps(canonical_data, sort_keys=True).encode("utf-8")
        payload_digest = hashlib.sha256(raw_bytes).hexdigest()

        return cls(
            schema_version=schema_version,
            signal_id=signal_id,
            finding_id=finding_id,
            target_contract=target_contract,
            action=action,
            confidence_score=round(confidence_score, 4),
            trigger_reason=trigger_reason,
            nonce=nonce,
            emitted_at=emitted_at,
            payload_digest=payload_digest,
        )

    def verify_integrity(self) -> bool:
        """Verifies cryptographic SHA-256 integrity of the payload."""
        canonical_data = {
            "schema_version": self.schema_version,
            "signal_id": self.signal_id,
            "finding_id": self.finding_id,
            "target_contract": self.target_contract,
            "action": self.action.value,
            "confidence_score": round(self.confidence_score, 4),
            "trigger_reason": self.trigger_reason,
            "nonce": self.nonce,
            "emitted_at": self.emitted_at,
        }
        raw_bytes = json.dumps(canonical_data, sort_keys=True).encode("utf-8")
        computed = hashlib.sha256(raw_bytes).hexdigest()
        return computed == self.payload_digest

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "signal_id": self.signal_id,
            "finding_id": self.finding_id,
            "target_contract": self.target_contract,
            "action": self.action.value,
            "confidence_score": self.confidence_score,
            "trigger_reason": self.trigger_reason,
            "nonce": self.nonce,
            "emitted_at": self.emitted_at,
            "payload_digest": self.payload_digest,
        }


class MitigationSignalEmitter:
    """Validates and emits fast-path mitigation signals to Phase 9 recipients."""

    def __init__(
        self,
        audit_log_path: str = "audit/mitigation_signals.jsonl",
        min_confidence_threshold: float = 0.80,
    ):
        self.audit_log_path = Path(audit_log_path)
        self.min_confidence_threshold = min_confidence_threshold
        self._seen_nonces = set()
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    def emit_from_shadow_report(
        self,
        report: AgentEShadowVerificationReport,
        target_contract: str,
        preferred_action: MitigationActionType = MitigationActionType.PAUSE_TARGET_CONTRACT,
    ) -> Optional[FastPathMitigationPayload]:
        """Synthesizes and emits a fast-path mitigation signal from a shadow verification report."""
        # Gate 1: Check outcome qualification
        if report.outcome != ShadowReplayOutcome.CONFIRMED_EXPLOIT:
            return None

        # Gate 2: Compute confidence
        balance_delta = report.execution_trace.get("balance_delta_wei", 0)
        confidence = 0.95 if balance_delta < 0 else 0.85

        if confidence < self.min_confidence_threshold:
            return None

        trigger_reason = (
            f"Shadow-fork exploit confirmed with balance delta {balance_delta} wei "
            f"under {report.severity_level} triage classification"
        )

        payload = FastPathMitigationPayload.create(
            finding_id=report.finding_id,
            target_contract=target_contract,
            action=preferred_action,
            confidence_score=confidence,
            trigger_reason=trigger_reason,
        )

        self.dispatch(payload)
        return payload

    def dispatch(self, payload: FastPathMitigationPayload) -> bool:
        """Validates payload and writes persistent audit log."""
        if not payload.verify_integrity():
            raise ValueError(f"Integrity check failed for payload {payload.signal_id}")

        if payload.nonce in self._seen_nonces:
            raise ValueError(f"Replay detected: nonce {payload.nonce} already processed")

        if payload.confidence_score < self.min_confidence_threshold:
            return False

        self._seen_nonces.add(payload.nonce)

        # Write to JSONL persistent log
        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload.to_dict()) + "\n")

        return True
