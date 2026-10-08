"""
Zone 3 — Local Broker Store (Task P04-001).
Embedded SQLite with Write-Ahead Logging (WAL mode), exclusive/busy locking,
optional Redis cache layer with graceful fallback, and automated pre-swarm snapshots.
"""

import hashlib
import json
import os
import shutil
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_DB_PATH = os.environ.get("BROKER_STORE_PATH", "data/broker_store.db")


class BrokerStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH, enable_redis: bool = False, redis_url: Optional[str] = None):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.enable_redis = enable_redis
        self.redis_client = None
        self._memory_cache: Dict[str, Any] = {}

        if self.enable_redis and redis_url:
            try:
                import redis
                self.redis_client = redis.from_url(redis_url, decode_responses=True)
                self.redis_client.ping()
            except Exception:
                self.redis_client = None

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA busy_timeout=5000;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    source_tool TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    snapshot_path TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    finding_count INTEGER NOT NULL,
                    created_at REAL NOT NULL
                );
            """)
            conn.commit()

    def write_finding(self, finding: Dict[str, Any]) -> str:
        """Writes a normalized finding to SQLite and syncs the cache."""
        source_tool = str(finding.get("source_tool", "unknown"))
        severity = str(finding.get("severity", "MEDIUM")).upper()
        title = str(finding.get("title", "Untitled finding"))
        payload_json = json.dumps(finding.get("details", {}), sort_keys=True)

        finding_id = finding.get("id")
        if not finding_id:
            raw_id = f"{source_tool}:{severity}:{title}:{payload_json}"
            finding_id = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:16]

        created_at = float(finding.get("created_at", time.time()))

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO findings (id, source_tool, severity, title, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?);
            """, (finding_id, source_tool, severity, title, payload_json, created_at))
            conn.commit()

        if self.redis_client:
            try:
                self.redis_client.set(f"finding:{finding_id}", payload_json, ex=3600)
            except Exception:
                pass
        self._memory_cache[f"finding:{finding_id}"] = finding

        return finding_id

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a finding by ID, checking cache first then SQLite."""
        if self.redis_client:
            try:
                cached = self.redis_client.get(f"finding:{finding_id}")
                if cached:
                    return json.loads(cached)
            except Exception:
                pass

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings WHERE id = ?;", (finding_id,))
            row = cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "source_tool": row["source_tool"],
                    "severity": row["severity"],
                    "title": row["title"],
                    "details": json.loads(row["payload_json"]),
                    "created_at": row["created_at"],
                }
        return None

    def list_findings(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings ORDER BY created_at ASC;")
            rows = cursor.fetchall()
            return [
                {
                    "id": r["id"],
                    "source_tool": r["source_tool"],
                    "severity": r["severity"],
                    "title": r["title"],
                    "details": json.loads(r["payload_json"]),
                    "created_at": r["created_at"],
                }
                for r in rows
            ]

    def snapshot(self, label: Optional[str] = None) -> Dict[str, Any]:
        """
        Creates an atomic pre-swarm snapshot of the database using SQLite backup API.
        Guarantees point-in-time consistency under WAL mode.
        """
        timestamp = int(time.time())
        tag = label or f"pre_swarm_{timestamp}"
        snapshot_dir = self.db_path.parent / "snapshots"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        dest_path = snapshot_dir / f"{self.db_path.stem}_{tag}.db"

        # Perform online backup
        src_conn = self._get_connection()
        try:
            dest_conn = sqlite3.connect(str(dest_path))
            with dest_conn:
                src_conn.backup(dest_conn)
            dest_conn.close()
        finally:
            src_conn.close()

        # Checksum and count
        content = dest_path.read_bytes()
        chk = hashlib.sha256(content).hexdigest()
        count = len(self.list_findings())

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO snapshots (snapshot_id, snapshot_path, checksum, finding_count, created_at)
                VALUES (?, ?, ?, ?, ?);
            """, (tag, str(dest_path), chk, count, time.time()))
            conn.commit()

        return {
            "snapshot_id": tag,
            "snapshot_path": str(dest_path),
            "checksum": chk,
            "finding_count": count,
        }

    def verify_wal_mode(self) -> bool:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            mode = cursor.fetchone()[0]
            cursor.close()
            return str(mode).lower() == "wal"
        finally:
            conn.close()


# Global/module-level default interface to satisfy legacy imports
_default_store: Optional[BrokerStore] = None


def get_default_store() -> BrokerStore:
    global _default_store
    if _default_store is None:
        _default_store = BrokerStore()
    return _default_store


def snapshot(label: Optional[str] = None) -> Dict[str, Any]:
    """Default snapshot helper."""
    return get_default_store().snapshot(label=label)


def write_finding(finding: Dict[str, Any]) -> str:
    """Default write_finding helper."""
    return get_default_store().write_finding(finding)
