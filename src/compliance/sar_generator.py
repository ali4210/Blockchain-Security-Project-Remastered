"""
Task P13-004: Draft Suspicious Activity Report (SAR/STR) Generator.
Generates deterministic, audit-ready draft reports for detected compliance typologies.
Enforces human-in-the-loop (HITL) boundaries: all generated artifacts remain in
DRAFT_PENDING_REVIEW status and cannot be autonomously filed externally.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional


class ReportStatus(str, Enum):
    DRAFT_PENDING_REVIEW = "DRAFT_PENDING_REVIEW"
    APPROVED_FOR_FILING = "APPROVED_FOR_FILING"
    REJECTED = "REJECTED"


class RegulatoryJurisdiction(str, Enum):
    FINCEN_US = "FINCEN_US"
    FATF_GLOBAL = "FATF_GLOBAL"
    EU_AMLD = "EU_AMLD"


@dataclass(frozen=True)
class InvolvedSubject:
    address: str
    role: str  # "SENDER", "RECIPIENT", "INTERMEDIARY"
    risk_tier: str
    sanction_category: Optional[str] = None


@dataclass(frozen=True)
class DraftSAR:
    report_id: str
    created_at_utc: str
    status: ReportStatus
    jurisdiction: RegulatoryJurisdiction
    case_summary: str
    typologies_detected: List[str]
    subjects: List[Dict[str, Any]]
    transaction_hashes: List[str]
    total_suspicious_volume_wei: int
    narrative: str
    draft_digest: str
    requires_human_approval: bool = True
    filing_channel: str = "LOCAL_STAGING_ONLY"


class SARReportGenerator:
    """
    Deterministic draft SAR / STR generation engine.
    """

    def __init__(self, jurisdiction: RegulatoryJurisdiction = RegulatoryJurisdiction.FINCEN_US):
        self.jurisdiction = jurisdiction

    @staticmethod
    def _compute_digest(payload: Dict[str, Any]) -> str:
        serialized = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def generate_draft(
        self,
        case_id: str,
        findings: List[Dict[str, Any]],
        subjects: List[InvolvedSubject],
        transactions: List[Dict[str, Any]],
        created_at_override: Optional[str] = None,
    ) -> DraftSAR:
        """
        Generates an immutable draft SAR report from compliance findings.
        """
        timestamp = created_at_override or datetime.now(timezone.utc).isoformat()
        
        # Aggregate typologies and transaction hashes
        typologies: List[str] = []
        for f in findings:
            typ = f.get("risk_type") or f.get("category") or "UNKNOWN"
            if typ not in typologies:
                typologies.append(str(typ))

        tx_hashes = sorted(list({t.get("tx_hash") for t in transactions if t.get("tx_hash")}))
        total_volume = sum(int(t.get("value_wei", 0)) for t in transactions)

        # Build formal narrative
        narrative_lines = [
            f"SUSPICIOUS ACTIVITY REPORT DRAFT [CASE REF: {case_id}]",
            f"Jurisdiction Framework: {self.jurisdiction.value}",
            f"Generated Timestamp: {timestamp}",
            f"Identified Typologies: {', '.join(typologies)}",
            f"Total Number of Suspect Transactions: {len(tx_hashes)}",
            f"Cumulative Volume: {total_volume} wei",
            "Summary of Suspicious Activity:",
        ]

        for finding in findings:
            desc = finding.get("description", "No description provided.")
            rule = finding.get("rule_id", "N/A")
            narrative_lines.append(f" - [{rule}] {desc}")

        narrative_lines.append(
            "GOVERNANCE NOTICE: This artifact is an automated internal draft. "
            "Autonomous external submission is strictly prohibited. Filing requires "
            "independent review and cryptographic token release by an authorized Compliance Officer."
        )
        full_narrative = "\n".join(narrative_lines)

        subjects_payload = [asdict(s) for s in sorted(subjects, key=lambda x: x.address)]

        core_payload = {
            "case_id": case_id,
            "jurisdiction": self.jurisdiction.value,
            "created_at_utc": timestamp,
            "typologies": typologies,
            "subjects": subjects_payload,
            "tx_hashes": tx_hashes,
            "total_volume_wei": total_volume,
            "narrative": full_narrative,
        }
        draft_digest = self._compute_digest(core_payload)

        return DraftSAR(
            report_id=f"SAR-DRAFT-{case_id}",
            created_at_utc=timestamp,
            status=ReportStatus.DRAFT_PENDING_REVIEW,
            jurisdiction=self.jurisdiction,
            case_summary=f"Automated draft for {len(typologies)} compliance typologies across {len(subjects)} subjects.",
            typologies_detected=typologies,
            subjects=subjects_payload,
            transaction_hashes=tx_hashes,
            total_suspicious_volume_wei=total_volume,
            narrative=full_narrative,
            draft_digest=draft_digest,
            requires_human_approval=True,
            filing_channel="LOCAL_STAGING_ONLY",
        )

    @staticmethod
    def verify_draft_integrity(draft: DraftSAR) -> bool:
        """
        Verifies that draft content matches the recorded cryptographic digest.
        """
        core_payload = {
            "case_id": draft.report_id.replace("SAR-DRAFT-", ""),
            "jurisdiction": draft.jurisdiction.value,
            "created_at_utc": draft.created_at_utc,
            "typologies": draft.typologies_detected,
            "subjects": draft.subjects,
            "tx_hashes": draft.transaction_hashes,
            "total_volume_wei": draft.total_suspicious_volume_wei,
            "narrative": draft.narrative,
        }
        computed = SARReportGenerator._compute_digest(core_payload)
        return computed == draft.draft_digest
