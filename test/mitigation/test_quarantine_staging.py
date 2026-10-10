"""
Task P09-004: Unit tests for Quarantine Staging and Signed Release Token Gate.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

from src.mitigation.quarantine_staging import (
    QuarantineStagingManager,
    SignedReleaseToken,
)


class TestQuarantineStaging(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = "quarantine/test_staging"
        self.manager = QuarantineStagingManager(quarantine_dir=self.tmp_dir)
        self.sample_content = b"SECURE_REMEDIATION_PATCH_CONTENT_V1"

    def tearDown(self):
        p = Path(self.tmp_dir)
        if p.exists():
            for f in p.glob("*"):
                f.unlink()
            p.rmdir()

    def test_stage_artifact_encrypted(self):
        pkg = self.manager.stage_artifact("patch-001", self.sample_content)
        self.assertEqual(pkg.artifact_id, "patch-001")
        # Ensure ciphertext does not leak plaintext substring
        self.assertNotIn(self.sample_content, bytes.fromhex(pkg.ciphertext_hex))

    def test_verify_and_release_success(self):
        pkg = self.manager.stage_artifact("patch-002", self.sample_content)
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        token = self.manager.sign_release_token(
            token_id="tok-001",
            artifact_id=pkg.artifact_id,
            artifact_digest=pkg.artifact_digest,
            target_destination="gitlab-mr",
            operator_principal="soc-operator",
            expires_at=expires_at,
        )

        released_bytes = self.manager.verify_and_release(pkg, token)
        self.assertEqual(released_bytes, self.sample_content)

    def test_reject_forged_signature(self):
        pkg = self.manager.stage_artifact("patch-003", self.sample_content)
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        token = self.manager.sign_release_token(
            token_id="tok-002",
            artifact_id=pkg.artifact_id,
            artifact_digest=pkg.artifact_digest,
            target_destination="gitlab-mr",
            operator_principal="soc-operator",
            expires_at=expires_at,
        )

        forged_token = SignedReleaseToken(
            token_id=token.token_id,
            artifact_id=token.artifact_id,
            artifact_digest=token.artifact_digest,
            target_destination=token.target_destination,
            operator_principal=token.operator_principal,
            issued_at=token.issued_at,
            expires_at=token.expires_at,
            signature="deadbeef" * 8,
        )

        with self.assertRaises(PermissionError) as ctx:
            self.manager.verify_and_release(pkg, forged_token)
        self.assertIn("signature verification failed", str(ctx.exception))

    def test_reject_unauthorized_principal(self):
        pkg = self.manager.stage_artifact("patch-004", self.sample_content)
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        token = self.manager.sign_release_token(
            token_id="tok-003",
            artifact_id=pkg.artifact_id,
            artifact_digest=pkg.artifact_digest,
            target_destination="gitlab-mr",
            operator_principal="agent_e",  # Autonomous agent cannot author release tokens
            expires_at=expires_at,
        )

        with self.assertRaises(PermissionError) as ctx:
            self.manager.verify_and_release(pkg, token)
        self.assertIn("Must be 'soc-operator'", str(ctx.exception))

    def test_reject_expired_token(self):
        pkg = self.manager.stage_artifact("patch-005", self.sample_content)
        expired_at = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

        token = self.manager.sign_release_token(
            token_id="tok-004",
            artifact_id=pkg.artifact_id,
            artifact_digest=pkg.artifact_digest,
            target_destination="gitlab-mr",
            operator_principal="soc-operator",
            expires_at=expired_at,
        )

        with self.assertRaises(ValueError) as ctx:
            self.manager.verify_and_release(pkg, token)
        self.assertIn("expired", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
