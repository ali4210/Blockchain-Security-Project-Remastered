"""
SQLite Broker Storage Engine (Task P04-001).
Implements thread-safe SQLite storage with WAL mode, busy timeout,
pre-swarm online backups, and normalized finding persistence.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import hashlib
import json
import os
import sqlite3
import time
import uuid


class BrokerStore:
    """
    Broker store backed by SQLite with WAL mode and snapshot support.
    """

    def __init__(self, db_path: Optional[str] = None, timeout: float = 30.0):
        if db_path is None:
            # Persistent default storage path so in-memory connections don't discard state
            default_dir = Path(".broker_storage").resolve()
            default_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(default_dir / "broker.db")
        else:
            self.db_path = str(Path(db_path).resolve())
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        self.timeout = timeout
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path,
            timeout=self.timeout,
            isolation_level=None,  # Autocommit mode
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    source_tool TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.close()

    def verify_wal_mode(self) -> bool:
        """Verifies that the SQLite database is operating under WAL mode."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            row = cursor.fetchone()
            mode = row[0].lower() if row else ""
            cursor.close()
            return mode == "wal"

    def write_finding(self, finding: Dict[str, Any]) -> str:
        """Persists a normalized finding to the broker store."""
        finding_id = str(finding.get("id") or f"FINDING-{uuid.uuid4().hex[:8].upper()}")
        source_tool = str(finding.get("source_tool") or finding.get("tool") or "unknown")
        severity = str(finding.get("severity") or "MEDIUM").upper()
        title = str(finding.get("title") or "Security Finding")
        details = json.dumps(finding.get("details") or finding)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO findings (id, source_tool, severity, title, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (finding_id, source_tool, severity, title, details),
            )
            cursor.close()

        return finding_id

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single finding by identifier."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings WHERE id = ?", (str(finding_id),))
            r = cursor.fetchone()
            cursor.close()
            if not r:
                return None
            return {
                "id": r["id"],
                "source_tool": r["source_tool"],
                "severity": r["severity"],
                "title": r["title"],
                "details": json.loads(r["details"]),
                "created_at": r["created_at"],
            }

    def list_findings(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves findings optionally filtered by severity."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if severity:
                cursor.execute("SELECT * FROM findings WHERE severity = ? ORDER BY id", (severity.upper(),))
            else:
                cursor.execute("SELECT * FROM findings ORDER BY id")

            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "id": r["id"],
                    "source_tool": r["source_tool"],
                    "severity": r["severity"],
                    "title": r["title"],
                    "details": json.loads(r["details"]),
                    "created_at": r["created_at"],
                })
            cursor.close()
            return results

    def snapshot(self, label: str = "default_snapshot") -> Dict[str, Any]:
        """Creates an atomic online backup snapshot of the SQLite database."""
        db_dir = Path(self.db_path).parent
        snap_dir = db_dir / "snapshots"
        snap_dir.mkdir(parents=True, exist_ok=True)
        dest_path = snap_dir / f"{label}.db"

        with self._get_connection() as conn:
            dest_conn = sqlite3.connect(str(dest_path))
            try:
                conn.backup(dest_conn)
            finally:
                dest_conn.close()

        # Compute SHA-256 checksum of the created snapshot
        sha = hashlib.sha256()
        with open(dest_path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)

        findings_count = len(self.list_findings())

        return {
            "snapshot_id": label,
            "finding_count": findings_count,
            "snapshot_path": str(dest_path),
            "checksum": sha.hexdigest(),
        }


# Global/module-level default store instance and exports
_default_store: Optional[BrokerStore] = None


def get_default_store() -> BrokerStore:
    global _default_store
    if _default_store is None:
        _default_store = BrokerStore()
    return _default_store


def write_finding(finding: Dict[str, Any]) -> str:
    return get_default_store().write_finding(finding)


def get_finding(finding_id: str) -> Optional[Dict[str, Any]]:
    return get_default_store().get_finding(finding_id)


def list_findings(severity: Optional[str] = None) -> List[Dict[str, Any]]:
    return get_default_store().list_findings(severity=severity)


def snapshot(label: str = "default_snapshot") -> Dict[str, Any]:
    return get_default_store().snapshot(label=label)
