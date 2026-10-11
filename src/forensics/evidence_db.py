"""
Task P10A-002: Forensics Database & Immutable Chain of Custody.
Implements SQLite-backed forensics storage with append-only SQL triggers,
cryptographic record hash chaining, and deterministic integrity verification.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

GENESIS_HASH = "0" * 64


class EvidenceDatabaseManager:
    """Manages immutable digital evidence tracking and cryptographic chain of custody."""

    def __init__(self, db_path: str = "forensics.db"):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        """Initializes tables and append-only immutability triggers."""
        with self.conn:
            # Evidence registry table
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    byte_size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    sha512 TEXT NOT NULL,
                    acquired_by TEXT NOT NULL,
                    acquired_at TEXT NOT NULL,
                    status TEXT NOT NULL
                )
                """
            )

            # Chain of custody ledger table
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_of_custody (
                    custody_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    sequence_num INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL,
                    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id)
                )
                """
            )

            # Enforce append-only triggers: Abort all UPDATE and DELETE mutations
            self.conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_evidence_update
                BEFORE UPDATE ON evidence
                BEGIN
                    SELECT RAISE(ABORT, 'Mutation forbidden: evidence table is append-only');
                END;
                """
            )
            self.conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_evidence_delete
                BEFORE DELETE ON evidence
                BEGIN
                    SELECT RAISE(ABORT, 'Deletion forbidden: evidence table is append-only');
                END;
                """
            )
            self.conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_custody_update
                BEFORE UPDATE ON chain_of_custody
                BEGIN
                    SELECT RAISE(ABORT, 'Mutation forbidden: chain_of_custody is append-only');
                END;
                """
            )
            self.conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_custody_delete
                BEFORE DELETE ON chain_of_custody
                BEGIN
                    SELECT RAISE(ABORT, 'Deletion forbidden: chain_of_custody is append-only');
                END;
                """
            )

    @staticmethod
    def _compute_record_hash(
        prev_hash: str,
        custody_id: str,
        evidence_id: str,
        sequence_num: int,
        action: str,
        actor: str,
        timestamp: str,
        details: str,
    ) -> str:
        """Computes deterministic SHA-256 over linked previous hash and record fields."""
        payload = {
            "prev_hash": prev_hash,
            "custody_id": custody_id,
            "evidence_id": evidence_id,
            "sequence_num": sequence_num,
            "action": action,
            "actor": actor,
            "timestamp": timestamp,
            "details": details,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def register_evidence(
        self,
        evidence_id: str,
        file_path: str,
        byte_size: int,
        sha256: str,
        sha512: str,
        acquired_by: str = "soc-operator",
        status: str = "SEALED",
    ) -> Dict[str, Any]:
        """Registers new evidence artifact and inserts genesis chain of custody entry."""
        acquired_at = datetime.now(timezone.utc).isoformat()
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO evidence (evidence_id, file_path, byte_size, sha256, sha512, acquired_by, acquired_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (evidence_id, file_path, byte_size, sha256, sha512, acquired_by, acquired_at, status),
            )

        # Record initial acquisition in chain of custody
        self.append_custody_event(
            evidence_id=evidence_id,
            action="ACQUIRED",
            actor=acquired_by,
            details=f"Acquisition of {file_path} (size={byte_size}, sha256={sha256})",
        )

        return {
            "evidence_id": evidence_id,
            "file_path": file_path,
            "byte_size": byte_size,
            "sha256": sha256,
            "sha512": sha512,
            "acquired_by": acquired_by,
            "acquired_at": acquired_at,
            "status": status,
        }

    def append_custody_event(
        self,
        evidence_id: str,
        action: str,
        actor: str,
        details: str = "",
    ) -> Dict[str, Any]:
        """Appends a new event to the evidence custody hash chain."""
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT sequence_num, record_hash
            FROM chain_of_custody
            WHERE evidence_id = ?
            ORDER BY sequence_num DESC
            LIMIT 1
            """,
            (evidence_id,),
        )
        last_row = cur.fetchone()

        if last_row is None:
            sequence_num = 1
            prev_hash = GENESIS_HASH
        else:
            sequence_num = last_row["sequence_num"] + 1
            prev_hash = last_row["record_hash"]

        timestamp = datetime.now(timezone.utc).isoformat()
        custody_id = f"coc-{evidence_id}-{sequence_num}"
        record_hash = self._compute_record_hash(
            prev_hash=prev_hash,
            custody_id=custody_id,
            evidence_id=evidence_id,
            sequence_num=sequence_num,
            action=action,
            actor=actor,
            timestamp=timestamp,
            details=details,
        )

        with self.conn:
            self.conn.execute(
                """
                INSERT INTO chain_of_custody (custody_id, evidence_id, sequence_num, action, actor, timestamp, details, prev_hash, record_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (custody_id, evidence_id, sequence_num, action, actor, timestamp, details, prev_hash, record_hash),
            )

        return {
            "custody_id": custody_id,
            "evidence_id": evidence_id,
            "sequence_num": sequence_num,
            "action": action,
            "actor": actor,
            "timestamp": timestamp,
            "details": details,
            "prev_hash": prev_hash,
            "record_hash": record_hash,
        }

    def verify_chain_integrity(self, evidence_id: str) -> bool:
        """Verifies the unbroken cryptographic chain of custody for a given artifact."""
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT * FROM chain_of_custody
            WHERE evidence_id = ?
            ORDER BY sequence_num ASC
            """,
            (evidence_id,),
        )
        rows = cur.fetchall()

        if not rows:
            raise ValueError(f"No chain of custody records found for evidence '{evidence_id}'")

        expected_prev_hash = GENESIS_HASH
        for idx, row in enumerate(rows, start=1):
            if row["sequence_num"] != idx:
                raise ValueError(
                    f"Sequence discontinuity in custody chain: expected {idx}, found {row['sequence_num']}"
                )
            if row["prev_hash"] != expected_prev_hash:
                raise ValueError(
                    f"Hash link broken at sequence {idx}: expected prev_hash {expected_prev_hash}, found {row['prev_hash']}"
                )

            recalc_hash = self._compute_record_hash(
                prev_hash=row["prev_hash"],
                custody_id=row["custody_id"],
                evidence_id=row["evidence_id"],
                sequence_num=row["sequence_num"],
                action=row["action"],
                actor=row["actor"],
                timestamp=row["timestamp"],
                details=row["details"],
            )
            if recalc_hash != row["record_hash"]:
                raise ValueError(
                    f"Record tamper detected at sequence {idx}: hash mismatch (expected {row['record_hash']}, recalculated {recalc_hash})"
                )

            expected_prev_hash = row["record_hash"]

        return True

    def close(self) -> None:
        """Closes active database connection."""
        self.conn.close()
