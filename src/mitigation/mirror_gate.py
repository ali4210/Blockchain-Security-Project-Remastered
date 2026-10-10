"""
Task P09-005: Zone 4 — GitHub Mirror Release Gate.
Enforces invariant that GitHub mirroring is never triggered automatically
and executes strictly upon cryptographic verification of a valid signed human
release token authored by soc-operator.
"""

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import sys
from typing import Optional

from src.mitigation.quarantine_staging import SignedReleaseToken


class MirrorReleaseGate:
    """Gatekeeper enforcing human-authorized release before syncing to public GitHub."""

    def __init__(self, signing_key: bytes = b"SOC_OPERATOR_SIGNING_KEY_P09_HMAC256"):
        self.signing_key = signing_key

    def verify_token(self, token: SignedReleaseToken, current_commit_sha: str) -> bool:
        """Validates token authenticity, operator role, destination, expiration, and commit binding."""
        # Rule 1: Author must be soc-operator
        if token.operator_principal != "soc-operator":
            raise PermissionError(
                f"Mirror gate denied: author '{token.operator_principal}' is unauthorized. Must be 'soc-operator'."
            )

        # Rule 2: Target destination must match github-mirror
        if token.target_destination != "github-mirror":
            raise ValueError(
                f"Mirror gate denied: target destination '{token.target_destination}' does not authorize GitHub mirror."
            )

        # Rule 3: Expiration check
        now_dt = datetime.now(timezone.utc)
        exp_dt = datetime.fromisoformat(token.expires_at)
        if now_dt > exp_dt:
            raise ValueError(f"Mirror gate denied: release token expired at {token.expires_at}")

        # Rule 4: Commit SHA / Artifact digest match
        if token.artifact_digest != current_commit_sha:
            raise ValueError(
                f"Mirror gate denied: token artifact digest '{token.artifact_digest}' does not match commit '{current_commit_sha}'."
            )

        # Rule 5: Cryptographic signature verification
        expected_sig = hmac.new(
            self.signing_key, token.canonical_bytes(), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_sig, token.signature):
            raise PermissionError("Mirror gate denied: invalid or forged release token signature.")

        return True

    def execute_mirror_sync(
        self, token: SignedReleaseToken, current_commit_sha: str, dry_run: bool = False
    ) -> bool:
        """Executes verification and performs authorized push to GitHub origin."""
        self.verify_token(token, current_commit_sha)

        if dry_run:
            return True

        # Authorized: trigger git push origin main
        cmd = ["git", "push", "origin", "main"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Git push origin failed: {res.stderr}")
        return True
