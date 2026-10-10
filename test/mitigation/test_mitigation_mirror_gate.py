"""
Task P09-005: Unit tests for GitHub Mirror Release Gate.
Verifies human release token gating, rejection of unsigned/forged tokens,
and blocking of unauthorized autonomous agent release attempts.
"""

from datetime import datetime, timedelta, timezone
import unittest

from src.mitigation.mirror_gate import MirrorReleaseGate
from src.mitigation.quarantine_staging import QuarantineStagingManager, SignedReleaseToken


class TestMirrorReleaseGate(unittest.TestCase):
    def setUp(self):
        self.manager = QuarantineStagingManager()
        self.gate = MirrorReleaseGate()
        self.commit_sha = "40e829e32534c2e09ba33c6ae5747d7136d458b0"

    def test_valid_human_release_token_clears_gate(self):
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        token = self.manager.sign_release_token(
            token_id="tok-mirror-001",
            artifact_id="commit-head",
            artifact_digest=self.commit_sha,
            target_destination="github-mirror",
            operator_principal="soc-operator",
            expires_at=expires_at,
        )

        cleared = self.gate.execute_mirror_sync(token, self.commit_sha, dry_run=True)
        self.assertTrue(cleared)

    def test_reject_when_author_is_agent(self):
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        token = self.manager.sign_release_token(
            token_id="tok-mirror-002",
            artifact_id="commit-head",
            artifact_digest=self.commit_sha,
            target_destination="github-mirror",
            operator_principal="agent_e",  # Autonomous agent blocked
            expires_at=expires_at,
        )

        with self.assertRaises(PermissionError) as ctx:
            self.gate.execute_mirror_sync(token, self.commit_sha, dry_run=True)
        self.assertIn("Must be 'soc-operator'", str(ctx.exception))

    def test_reject_wrong_target_destination(self):
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        token = self.manager.sign_release_token(
            token_id="tok-mirror-003",
            artifact_id="commit-head",
            artifact_digest=self.commit_sha,
            target_destination="gitlab-mr",  # Wrong destination for public mirror
            operator_principal="soc-operator",
            expires_at=expires_at,
        )

        with self.assertRaises(ValueError) as ctx:
            self.gate.execute_mirror_sync(token, self.commit_sha, dry_run=True)
        self.assertIn("does not authorize GitHub mirror", str(ctx.exception))

    def test_reject_forged_token_signature(self):
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        token = self.manager.sign_release_token(
            token_id="tok-mirror-004",
            artifact_id="commit-head",
            artifact_digest=self.commit_sha,
            target_destination="github-mirror",
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
            signature="baadc0de" * 8,
        )

        with self.assertRaises(PermissionError) as ctx:
            self.gate.execute_mirror_sync(forged_token, self.commit_sha, dry_run=True)
        self.assertIn("invalid or forged release token signature", str(ctx.exception))

    def test_reject_commit_digest_mismatch(self):
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        token = self.manager.sign_release_token(
            token_id="tok-mirror-005",
            artifact_id="commit-head",
            artifact_digest="old_commit_sha_1234567890",
            target_destination="github-mirror",
            operator_principal="soc-operator",
            expires_at=expires_at,
        )

        with self.assertRaises(ValueError) as ctx:
            self.gate.execute_mirror_sync(token, self.commit_sha, dry_run=True)
        self.assertIn("does not match commit", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
