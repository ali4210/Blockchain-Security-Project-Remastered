"""
Task P10A-003: Write-Once Forensic Evidence Vault.
Enforces write-once filesystem attributes, cryptographic verification against
forensics.db, and integrity-validated working copy dispatch for agent analysis.
"""

from pathlib import Path
import shutil
import stat
from typing import Any, Dict, Optional, Union

from src.forensics.evidence_db import EvidenceDatabaseManager
from src.forensics.hasher import ArtifactDigest, StreamingEvidenceHasher


class EvidenceVaultManager:
    """Manages write-once sealed forensic evidence and controlled working copy generation."""

    def __init__(
        self,
        vault_root: Union[str, Path] = "vault/sealed",
        db_path: str = "forensics.db",
    ):
        self.vault_root = Path(vault_root).resolve()
        self.vault_root.mkdir(parents=True, exist_ok=True)
        self.hasher = StreamingEvidenceHasher()
        self.db = EvidenceDatabaseManager(db_path=db_path)

    def seal(
        self,
        artifact_path: Union[str, Path],
        evidence_id: str,
        acquired_by: str = "soc-operator",
    ) -> Dict[str, Any]:
        """Locks an artifact into the vault with read-only permissions and registers it in DB."""
        src_path = Path(artifact_path).resolve()
        if not src_path.is_file():
            raise FileNotFoundError(f"Source artifact not found: {src_path}")

        # Compute initial cryptographic digest
        digest: ArtifactDigest = self.hasher.hash_file(src_path)

        dest_path = self.vault_root / f"{evidence_id}_{src_path.name}"
        if dest_path.exists():
            raise FileExistsError(f"Sealed artifact already exists at destination: {dest_path}")

        # Copy file into vault
        shutil.copy2(src_path, dest_path)

        # Enforce read-only filesystem attributes (0o400: read-only by owner)
        dest_path.chmod(stat.S_IRUSR | stat.S_IRGRP)

        # Register evidence and initial custody in append-only SQLite DB
        record = self.db.register_evidence(
            evidence_id=evidence_id,
            file_path=str(dest_path),
            byte_size=digest.byte_size,
            sha256=digest.sha256,
            sha512=digest.sha512,
            acquired_by=acquired_by,
            status="SEALED",
        )

        return record

    def verify(self, evidence_id: str) -> bool:
        """Verifies physical file integrity against database record and checks chain of custody."""
        cur = self.db.conn.cursor()
        cur.execute("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))
        row = cur.fetchone()

        if not row:
            raise KeyError(f"No evidence registered with id: {evidence_id}")

        file_path = Path(row["file_path"])
        if not file_path.is_file():
            raise FileNotFoundError(f"Sealed evidence file missing from vault: {file_path}")

        # Recompute streaming hashes directly from disk
        current_digest = self.hasher.hash_file(file_path)

        if current_digest.byte_size != row["byte_size"]:
            raise ValueError(
                f"Integrity violation on {evidence_id}: size mismatch (expected {row['byte_size']}, found {current_digest.byte_size})"
            )
        if current_digest.sha256 != row["sha256"]:
            raise ValueError(
                f"Integrity violation on {evidence_id}: SHA-256 mismatch (expected {row['sha256']}, found {current_digest.sha256})"
            )
        if current_digest.sha512 != row["sha512"]:
            raise ValueError(
                f"Integrity violation on {evidence_id}: SHA-512 mismatch (expected {row['sha512']}, found {current_digest.sha512})"
            )

        # Check cryptographic chain of custody
        self.db.verify_chain_integrity(evidence_id)

        # Append audit verification event
        self.db.append_custody_event(
            evidence_id=evidence_id,
            action="VERIFIED",
            actor="soc-operator",
            details="Cryptographic disk and hash chain verification passed",
        )

        return True

    def open_working_copy(
        self,
        evidence_id: str,
        destination_dir: Union[str, Path],
        requester: str = "agent_analysis",
    ) -> Path:
        """Verifies sealed artifact integrity and generates a working copy for agent consumption."""
        cur = self.db.conn.cursor()
        cur.execute("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))
        row = cur.fetchone()

        if not row:
            raise KeyError(f"Evidence {evidence_id} not registered")

        src_file = Path(row["file_path"])
        if not src_file.is_file():
            raise FileNotFoundError(f"Vault source file missing: {src_file}")

        # 1. Verify source file before extraction
        source_digest = self.hasher.hash_file(src_file)
        if source_digest.sha256 != row["sha256"]:
            raise ValueError(f"Cannot dispatch corrupted sealed artifact {evidence_id}")

        dest_dir = Path(destination_dir).resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)
        working_file = dest_dir / f"working_{src_file.name}"

        shutil.copy2(src_file, working_file)
        # Working copy is made writable for the agent workspace
        working_file.chmod(stat.S_IRUSR | stat.S_IWUSR)

        # 2. Re-hash working copy to confirm byte fidelity
        copy_digest = self.hasher.hash_file(working_file)
        if copy_digest.sha256 != source_digest.sha256:
            raise IOError("Working copy replication corrupted during transfer")

        # 3. Log custody event
        self.db.append_custody_event(
            evidence_id=evidence_id,
            action="WORKING_COPY_DISPATCHED",
            actor="soc-operator",
            details=f"Dispatched working copy to {working_file} for requester {requester}",
        )

        return working_file

    def close(self) -> None:
        """Closes underlying database connection."""
        self.db.close()
