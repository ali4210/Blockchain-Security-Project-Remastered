"""
Task P07-006: Unit Tests for Forensic Staging Snapshot Engine.
Validates bundle creation, per-file cryptographic digests, root manifest integrity,
immutability freezing, and tamper detection.
"""

import json
from pathlib import Path
import stat
import tempfile
import unittest

from src.deployment.forensic_staging_snapshot import (
    ForensicStagingSnapshot,
    StagingManifest,
)


class TestForensicStagingSnapshot(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base_staging = Path(self.tmp_dir.name)
        self.engine = ForensicStagingSnapshot(base_staging_dir=self.base_staging)

        self.sample_artifacts = {
            "logs/job_run.log": b"[2026-10-10 07:00:00] Run initiated\n[2026-10-10 07:00:01] Complete\n",
            "wal/broker_store.db-wal": b"WAL-MAGIC-BYTES-1234567890\n",
            "ast/ast_projection.json": b'{"maskedNodes": 42, "contract": "VulnerableVault"}',
            "pocs/reentrancy_poc.sol": b"// PoC exploit fixture\ncontract Exploit {}",
            "receipts/deployment_receipt.json": b'{"status": "DEPLOYED", "txHash": "0x123"}',
        }

    def tearDown(self):
        for p in Path(self.tmp_dir.name).rglob("*"):
            try:
                p.chmod(stat.S_IWRITE | stat.S_IREAD | stat.S_IXUSR)
            except Exception:
                pass
        self.tmp_dir.cleanup()

    def test_create_snapshot_success(self):
        run_id = "RUN-TEST-001"
        manifest = self.engine.create_snapshot(run_id, self.sample_artifacts, freeze_permissions=False)

        self.assertIsInstance(manifest, StagingManifest)
        self.assertEqual(manifest.schemaVersion, 1)
        self.assertEqual(manifest.runId, run_id)
        self.assertEqual(len(manifest.fileDigests), 5)
        self.assertEqual(len(manifest.rootDigest), 64)

        bundle_dir = self.base_staging / f"run-{run_id}"
        self.assertTrue((bundle_dir / "manifest.json").exists())
        self.assertTrue((bundle_dir / "logs" / "job_run.log").exists())
        self.assertTrue((bundle_dir / "wal" / "broker_store.db-wal").exists())

        # Verify manifest matches on disk
        data = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(data["rootDigest"], manifest.rootDigest)

        # Verify integrity check passes
        self.assertTrue(self.engine.verify_snapshot(bundle_dir))

    def test_path_traversal_rejected(self):
        invalid_artifacts = {
            "../escape.txt": b"Malicious data",
        }
        with self.assertRaises(ValueError) as ctx:
            self.engine.create_snapshot("RUN-BAD", invalid_artifacts, freeze_permissions=False)
        self.assertIn("Path traversal rejected", str(ctx.exception))

    def test_tamper_detection(self):
        run_id = "RUN-TAMPER-001"
        self.engine.create_snapshot(run_id, self.sample_artifacts, freeze_permissions=False)
        bundle_dir = self.base_staging / f"run-{run_id}"

        # Tamper with an artifact
        log_file = bundle_dir / "logs" / "job_run.log"
        log_file.write_bytes(b"tampered content")

        # Verification must now fail
        self.assertFalse(self.engine.verify_snapshot(bundle_dir))

    def test_freeze_permissions_prevents_write(self):
        run_id = "RUN-IMMUTABLE-001"
        self.engine.create_snapshot(run_id, self.sample_artifacts, freeze_permissions=True)
        bundle_dir = self.base_staging / f"run-{run_id}"

        log_file = bundle_dir / "logs" / "job_run.log"
        # Attempting to write to read-only file should raise PermissionError
        with self.assertRaises(PermissionError):
            log_file.write_bytes(b"overwrite attempt")


if __name__ == "__main__":
    unittest.main()
