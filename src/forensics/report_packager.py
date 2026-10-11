"""
Task P10C-003: Forensic Incident Report Packager.
Compiles post-incident evidence summaries, chronological custody timelines,
RFC 6962 Merkle tree roots, and HMAC-SHA256 human-authoritative signing.
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.forensics.collector import AcquiredStageResult
from src.forensics.hasher import StreamingEvidenceHasher
from src.forensics.vault import EvidenceVaultManager


class IncidentReportPackager:
    """Compiles and cryptographically signs tamper-evident forensic incident reports."""

    def __init__(
        self,
        vault_manager: Optional[EvidenceVaultManager] = None,
        vault_root: str = "vault/sealed",
        db_path: str = "forensics.db",
    ):
        self.vault = vault_manager or EvidenceVaultManager(vault_root=vault_root, db_path=db_path)
        self.hasher = StreamingEvidenceHasher()

    def package_report(
        self,
        incident_id: str,
        acquired_stages: List[AcquiredStageResult],
        operator_principal: str = "soc-operator",
        signing_key: Optional[bytes] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Compiles evidence bundle into a structured, signed forensic incident report."""
        if operator_principal != "soc-operator":
            raise PermissionError("Only human 'soc-operator' can author and sign forensic incident reports")
        if not signing_key:
            raise ValueError("Signing key required for HMAC-SHA256 authoritative report sealing")

        meta = metadata or {}
        generated_at = datetime.now(timezone.utc).isoformat()

        # 1. Compile and verify evidence records
        evidence_entries: List[Dict[str, Any]] = []
        artifact_digests: List[str] = []

        for st in acquired_stages:
            # Cryptographically verify file on disk against database
            self.vault.verify(st.evidence_id)

            evidence_entries.append({
                "stage": st.stage,
                "order_sequence": st.order_sequence,
                "evidence_id": st.evidence_id,
                "file_path": st.file_path,
                "byte_size": st.byte_size,
                "sha256": st.sha256,
                "sha512": st.sha512,
                "timestamp": st.timestamp,
            })
            artifact_digests.append(st.sha256)

        # 2. Build RFC 6962 Merkle tree over all artifact SHA-256 digests
        merkle_root = self.hasher.build_rfc6962_merkle_tree(artifact_digests)

        # 3. Compile custody timelines from database
        cur = self.vault.db.conn.cursor()
        timeline: List[Dict[str, Any]] = []
        for st in acquired_stages:
            cur.execute(
                """
                SELECT sequence_num, evidence_id, action, actor, timestamp, prev_hash, record_hash, details
                FROM chain_of_custody
                WHERE evidence_id = ?
                ORDER BY sequence_num ASC
                """,
                (st.evidence_id,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            timeline.extend(rows)

        # Sort combined timeline chronologically
        timeline.sort(key=lambda r: (r["timestamp"], r["sequence_num"]))

        report_payload = {
            "schema_version": "1.0.0",
            "incident_id": incident_id,
            "generated_at": generated_at,
            "author": operator_principal,
            "metadata": meta,
            "evidence_count": len(evidence_entries),
            "evidence_items": evidence_entries,
            "merkle_root": merkle_root,
            "custody_timeline": timeline,
            "integrity_status": "VERIFIED_VALID",
        }

        # 4. Generate HMAC-SHA256 signature over canonical report JSON
        canonical_bytes = json.dumps(report_payload, sort_keys=True).encode("utf-8")
        signature = hmac.new(signing_key, canonical_bytes, hashlib.sha256).hexdigest()

        return {
            "report": report_payload,
            "signature": {
                "algorithm": "HMAC-SHA256",
                "signer": operator_principal,
                "signature_hex": signature,
            },
        }

    def verify_report(self, report_package: Dict[str, Any], signing_key: bytes) -> bool:
        """Verifies report HMAC signature and cryptographic consistency."""
        report = report_package.get("report")
        sig_info = report_package.get("signature")

        if not report or not sig_info:
            raise ValueError("Malformed report package")

        if sig_info.get("signer") != "soc-operator":
            return False

        canonical_bytes = json.dumps(report, sort_keys=True).encode("utf-8")
        expected_sig = hmac.new(signing_key, canonical_bytes, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_sig, sig_info.get("signature_hex", "")):
            return False

        # Recompute Merkle root over items
        digests = [item["sha256"] for item in report.get("evidence_items", [])]
        expected_root = self.hasher.build_rfc6962_merkle_tree(digests)
        if expected_root != report.get("merkle_root"):
            return False

        return True
