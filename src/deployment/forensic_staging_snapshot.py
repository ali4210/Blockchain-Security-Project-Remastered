"""
Task P07-006: Forensic Staging Snapshot Engine.
Snapshots execution logs, WAL journals, masked ASTs, PoCs, and receipts into
an immutable protected staging directory layout ready for Phase 10 sealing.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class StagingManifest:
    schemaVersion: int
    runId: str
    timestamp: str
    fileDigests: Dict[str, str]
    rootDigest: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ForensicStagingSnapshot:
    """
    Orchestrates bundling of run artifacts into staging/forensics/run-<id>/.
    Enforces per-file cryptographic integrity and post-snapshot read-only permissions.
    """

    SCHEMA_VERSION = 1

    def __init__(self, base_staging_dir: Optional[Path] = None):
        self.base_staging_dir = (base_staging_dir or Path("staging/forensics")).resolve()

    def compute_file_sha256(self, file_path: Path) -> str:
        hasher = hashlib.sha256()
        with file_path.open("rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def compute_root_digest(self, file_digests: Dict[str, str]) -> str:
        canonical = json.dumps(file_digests, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def create_snapshot(
        self,
        run_id: str,
        artifacts: Dict[str, bytes],
        freeze_permissions: bool = True,
    ) -> StagingManifest:
        """
        Creates a staging snapshot bundle from in-memory or sourced artifacts.
        Paths in artifacts dictionary should be relative subpaths (e.g. 'logs/run.log').
        """
        target_dir = self.base_staging_dir / f"run-{run_id}"
        target_dir.mkdir(parents=True, exist_ok=True)

        file_digests: Dict[str, str] = {}

        # Write artifacts
        for rel_path_str, data in artifacts.items():
            rel_path = Path(rel_path_str)
            if ".." in rel_path.parts:
                raise ValueError(f"Path traversal rejected: '{rel_path_str}'")

            dest_path = target_dir / rel_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_bytes(data)

            digest = hashlib.sha256(data).hexdigest()
            file_digests[rel_path.as_posix()] = digest

        # Compute root digest
        root_digest = self.compute_root_digest(file_digests)
        ts = datetime.now(timezone.utc).isoformat()

        manifest = StagingManifest(
            schemaVersion=self.SCHEMA_VERSION,
            runId=run_id,
            timestamp=ts,
            fileDigests=file_digests,
            rootDigest=root_digest,
        )

        manifest_path = target_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")

        # Freeze bundle if requested
        if freeze_permissions:
            self._freeze_directory(target_dir)

        return manifest

    def _freeze_directory(self, target_dir: Path) -> None:
        """Applies read-only permissions across directory tree."""
        for root, dirs, files in os.walk(target_dir):
            for f in files:
                f_path = Path(root) / f
                f_path.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
            for d in dirs:
                d_path = Path(root) / d
                d_path.chmod(stat.S_IREAD | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        target_dir.chmod(stat.S_IREAD | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

    def verify_snapshot(self, target_dir: Path) -> bool:
        """Verifies bundle against manifest.json."""
        manifest_path = target_dir / "manifest.json"
        if not manifest_path.exists():
            return False

        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            file_digests = data.get("fileDigests", {})
            recorded_root = data.get("rootDigest")

            # Check root digest
            if self.compute_root_digest(file_digests) != recorded_root:
                return False

            # Check individual files
            for rel_str, expected_digest in file_digests.items():
                p = target_dir / rel_str
                if not p.exists():
                    return False
                if self.compute_file_sha256(p) != expected_digest:
                    return False

            return True
        except Exception:
            return False
