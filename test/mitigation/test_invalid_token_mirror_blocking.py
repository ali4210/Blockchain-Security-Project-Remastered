"""
Task P09-007: Integration tests for invalid/unsigned release token blocking.
Verifies that public mirroring strictly fails closed across all invalid,
unsigned, forged, expired, mismatched, and agent-authored release tokens.
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import unittest

from src.mitigation.mirror_gate import MirrorReleaseGate
from src.mitigation.quarantine_staging import (
    QuarantineStagingManager,
    SignedReleaseToken,
)


class TestInvalidTokenMirrorBlocking(unittest.TestCase):
    def setUp(self):
        self.manager = QuarantineStagingManager()
        self.gate = MirrorReleaseGate()
        self.valid_commit = "80d2713d0b11e69d16b8358d2eb92d95403f9720"
        self.tmp_dir = Path("quarantine/test_tokens")
        self.tmp_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        if self.tmp_dir.exists():
            for f in self.tmp_dir.glob("*"):
                f.unlink()
            self.tmp_dir.rmdir()

    def test_missing_token_file_blocks_cli_gate(self):
        res = subprocess.run(
            ["./scripts/mirror-release-gate.sh", "quarantine/non_existent_token.json"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Missing or unreadable human release token file", res.stderr)

    def test_corrupt_json_blocks_cli_gate(self):
        corrupt_path = self.tmp_dir / "corrupt_token.json"
        corrupt_path.write_text("{ this is not valid json }", encoding="utf-8")

        res = subprocess.run(
            ["./scripts/mirror-release-gate.sh", str(corrupt_path)],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Denial:", res.stderr)

    def test_unsigned_token_rejected(self):
        unsigned_token = SignedReleaseToken(
            token_id="tok-unsigned",
            artifact_id="commit-head",
            artifact_digest=self.valid_commit,
            target_destination="github-mirror",
            operator_principal="soc-operator",
            issued_at=datetime.now(timezone.utc).isoformat(),
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            signature="",
        )
        with self.assertRaises(PermissionError) as ctx:
            self.gate.execute_mirror_sync(unsigned_token, self.valid_commit, dry_run=True)
        self.assertIn("invalid or forged release token signature", str(ctx.exception))

    def test_tampered_payload_digest_rejected(self):
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        token = self.manager.sign_release_token(
            token_id="tok-valid-base",
            artifact_id="commit-head",
            artifact_digest=self.valid_commit,
            target_destination="github-mirror",
            operator_principal="soc-operator",
            expires_at=expires_at,
        )

        tampered_token = SignedReleaseToken(
            token_id=token.token_id,
            artifact_id=token.artifact_id,
            artifact_digest="altered_commit_digest_0000000000000000",
            target_destination=token.target_destination,
            operator_principal=token.operator_principal,
            issued_at=token.issued_at,
            expires_at=token.expires_at,
            signature=token.signature,  # Retains original signature
        )

        with self.assertRaises(ValueError) as ctx:
            self.gate.execute_mirror_sync(tampered_token, self.valid_commit, dry_run=True)
        self.assertIn("does not match commit", str(ctx.exception))

    def test_forged_signature_rejected(self):
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        token = self.manager.sign_release_token(
            token_id="tok-valid-base",
            artifact_id="commit-head",
            artifact_digest=self.valid_commit,
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
            signature="0123456789abcdef" * 4,
        )

        with self.assertRaises(PermissionError) as ctx:
            self.gate.execute_mirror_sync(forged_token, self.valid_commit, dry_run=True)
        self.assertIn("invalid or forged release token signature", str(ctx.exception))

    def test_expired_token_rejected(self):
        expired_at = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        token = self.manager.sign_release_token(
            token_id="tok-expired",
            artifact_id="commit-head",
            artifact_digest=self.valid_commit,
            target_destination="github-mirror",
            operator_principal="soc-operator",
            expires_at=expired_at,
        )

        with self.assertRaises(ValueError) as ctx:
            self.gate.execute_mirror_sync(token, self.valid_commit, dry_run=True)
        self.assertIn("expired", str(ctx.exception))

    def test_wrong_target_destination_rejected(self):
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        token = self.manager.sign_release_token(
            token_id="tok-mr-dest",
            artifact_id="commit-head",
            artifact_digest=self.valid_commit,
            target_destination="gitlab-mr",
            operator_principal="soc-operator",
            expires_at=expires_at,
        )

        with self.assertRaises(ValueError) as ctx:
            self.gate.execute_mirror_sync(token, self.valid_commit, dry_run=True)
        self.assertIn("does not authorize GitHub mirror", str(ctx.exception))

    def test_agent_principal_author_rejected(self):
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        for role in ["agent_a", "agent_b", "agent_c", "agent_d", "agent_e", "agent_f", "agent_g"]:
            token = self.manager.sign_release_token(
                token_id=f"tok-{role}",
                artifact_id="commit-head",
                artifact_digest=self.valid_commit,
                target_destination="github-mirror",
                operator_principal=role,
                expires_at=expires_at,
            )
            with self.assertRaises(
                PermissionError,
                msg=f"Agent role '{role}' must be rejected from mirror authorization",
            ) as ctx:
                self.gate.execute_mirror_sync(token, self.valid_commit, dry_run=True)
            self.assertIn("Must be 'soc-operator'", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
