"""
Task P06-008: Versioned Forensic Event Emitter for Phase 10 Forensic Ingestion.
Translates verified AVS consensus results backed by cryptographic QuorumCertificates
into canonical, schemaVersion: 1 'case-opened' audit events.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.consensus.avs_gate import ConsensusResult, ConsensusStatus
from src.consensus.bls_aggregation import QuorumCertificate


@dataclass(frozen=True)
class CaseOpenedEvent:
    schemaVersion: int
    eventType: str
    caseId: str
    attestationId: str
    findingId: str
    targetContract: str
    severity: str
    executionReceiptHash: str
    quorumCertificate: Dict[str, Any]
    emittedAt: str
    eventDigest: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ForensicEventEmitter:
    """
    Emits canonical 'case-opened' forensic events bound to AVS QuorumCertificates.
    Rejects uncertified or rejected findings strictly.
    """

    SCHEMA_VERSION = 1
    EVENT_TYPE = "case-opened"

    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = log_path
        self._emitted_events: List[CaseOpenedEvent] = []

    def compute_event_digest(self, payload: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 digest over canonical JSON representation."""
        canonical_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def emit_case_opened(
        self,
        finding: Dict[str, Any],
        consensus_result: ConsensusResult,
        execution_receipt_hash: str,
    ) -> CaseOpenedEvent:
        """
        Emits a versioned case-opened event if and only if consensus reached AGREED
        with an attached valid QuorumCertificate.
        """
        if consensus_result.status != ConsensusStatus.AGREED or not consensus_result.certificate:
            raise PermissionError(
                f"Cannot emit 'case-opened' event: Finding '{consensus_result.finding_id}' "
                f"did not achieve supermajority quorum (status: {consensus_result.status})."
            )

        cert = consensus_result.certificate
        finding_id = consensus_result.finding_id
        target = str(finding.get("target_contract") or finding.get("target") or "UnknownTarget")
        target_name = Path(target).stem or "Contract"
        severity = str(finding.get("severity") or "HIGH").upper()
        ts = datetime.now(timezone.utc).isoformat()

        # Deterministic case identifier
        case_id_hash = hashlib.sha256(f"{target_name}:{cert.attestation_id}".encode("utf-8")).hexdigest()[:8]
        case_id = f"CASE-{target_name}-{case_id_hash}"

        raw_event_data = {
            "schemaVersion": self.SCHEMA_VERSION,
            "eventType": self.EVENT_TYPE,
            "caseId": case_id,
            "attestationId": cert.attestation_id,
            "findingId": finding_id,
            "targetContract": target,
            "severity": severity,
            "executionReceiptHash": execution_receipt_hash,
            "quorumCertificate": cert.to_dict(),
            "emittedAt": ts,
        }

        event_digest = self.compute_event_digest(raw_event_data)

        event = CaseOpenedEvent(
            schemaVersion=self.SCHEMA_VERSION,
            eventType=self.EVENT_TYPE,
            caseId=case_id,
            attestationId=cert.attestation_id,
            findingId=finding_id,
            targetContract=target,
            severity=severity,
            executionReceiptHash=execution_receipt_hash,
            quorumCertificate=cert.to_dict(),
            emittedAt=ts,
            eventDigest=event_digest,
        )

        self._emitted_events.append(event)

        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict()) + "\n")

        return event

    def get_emitted_events(self) -> List[CaseOpenedEvent]:
        return list(self._emitted_events)
