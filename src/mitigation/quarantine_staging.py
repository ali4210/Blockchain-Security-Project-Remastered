"""
Task P09-004: Zone 4 — Encrypted Quarantine Staging Workflow & Release Token Gate.
Ensures remediation and egress artifacts remain encrypted in quarantine until
an explicit, cryptographically signed human release token from soc-operator is verified.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class SignedReleaseToken:
    token_id: str
    artifact_id: str
    artifact_digest: str  # SHA-256
    target_destination: str
    operator_principal: str  # Must be 'soc-operator'
    issued_at: str
    expires_at: str
    signature: str

    def canonical_bytes(self) -> bytes:
        data = {
            "token_id": self.token_id,
            "artifact_id": self.artifact_id,
            "artifact_digest": self.artifact_digest,
            "target_destination": self.target_destination,
            "operator_principal": self.operator_principal,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")


@dataclass(frozen=True)
class QuarantinePackage:
    package_id: str
    artifact_id: str
    ciphertext_hex: str
    nonce_hex: str
    salt_hex: str
    artifact_digest: str
    staged_at: str


class QuarantineStagingManager:
    """Manages encrypted quarantine storage and cryptographic release token gates."""

    def __init__(
        self,
        quarantine_dir: str = "quarantine/staging",
        signing_key: bytes = b"SOC_OPERATOR_SIGNING_KEY_P09_HMAC256",
    ):
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.signing_key = signing_key

    def _derive_encryption_key(self, salt: bytes) -> bytes:
        # Deterministic HKDF/PBKDF2 style key derivation from signing key and salt
        return hashlib.pbkdf2_hmac("sha256", self.signing_key, salt, iterations=100000, dklen=32)

    def _xor_cipher(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        # Stream-based authenticated masking primitive
        keystream = bytearray()
        counter = 0
        while len(keystream) < len(data):
            counter_bytes = counter.to_bytes(4, "big")
            block = hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest()
            keystream.extend(block)
            counter += 1
        return bytes(a ^ b for a, b in zip(data, keystream[:len(data)]))

    def stage_artifact(self, artifact_id: str, content: bytes) -> QuarantinePackage:
        """Encrypts raw artifact bytes and saves only encrypted package to quarantine storage."""
        artifact_digest = hashlib.sha256(content).hexdigest()
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_encryption_key(salt)

        ciphertext = self._xor_cipher(content, key, nonce)

        package = QuarantinePackage(
            package_id=f"pkg-{artifact_id}",
            artifact_id=artifact_id,
            ciphertext_hex=ciphertext.hex(),
            nonce_hex=nonce.hex(),
            salt_hex=salt.hex(),
            artifact_digest=artifact_digest,
            staged_at=datetime.now(timezone.utc).isoformat(),
        )

        package_path = self.quarantine_dir / f"{package.package_id}.json"
        package_path.write_text(json.dumps(asdict(package), indent=2), encoding="utf-8")
        return package

    def sign_release_token(
        self,
        token_id: str,
        artifact_id: str,
        artifact_digest: str,
        target_destination: str,
        operator_principal: str,
        expires_at: str,
    ) -> SignedReleaseToken:
        """Authors and cryptographically signs a release token."""
        issued_at = datetime.now(timezone.utc).isoformat()
        token = SignedReleaseToken(
            token_id=token_id,
            artifact_id=artifact_id,
            artifact_digest=artifact_digest,
            target_destination=target_destination,
            operator_principal=operator_principal,
            issued_at=issued_at,
            expires_at=expires_at,
            signature="",
        )

        signature = hmac.new(
            self.signing_key, token.canonical_bytes(), hashlib.sha256
        ).hexdigest()

        return SignedReleaseToken(
            token_id=token.token_id,
            artifact_id=token.artifact_id,
            artifact_digest=token.artifact_digest,
            target_destination=token.target_destination,
            operator_principal=token.operator_principal,
            issued_at=token.issued_at,
            expires_at=token.expires_at,
            signature=signature,
        )

    def verify_and_release(
        self, package: QuarantinePackage, token: SignedReleaseToken
    ) -> bytes:
        """Verifies release token against policy and decrypts quarantined artifact."""
        # Check 1: Operator principal authorization
        if token.operator_principal != "soc-operator":
            raise PermissionError(
                f"Release token rejected: author '{token.operator_principal}' is not authorized. Must be 'soc-operator'."
            )

        # Check 2: Expiration check
        exp_dt = datetime.fromisoformat(token.expires_at)
        now_dt = datetime.now(timezone.utc)
        if now_dt > exp_dt:
            raise ValueError(f"Release token expired at {token.expires_at}")

        # Check 3: Artifact ID and digest matching
        if token.artifact_id != package.artifact_id:
            raise ValueError("Release token artifact_id mismatch")
        if token.artifact_digest != package.artifact_digest:
            raise ValueError("Release token artifact_digest mismatch")

        # Check 4: Cryptographic signature verification
        expected_sig = hmac.new(
            self.signing_key, token.canonical_bytes(), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_sig, token.signature):
            raise PermissionError("Release token signature verification failed: invalid or forged signature")

        # Check 5: Decrypt and assert plaintext integrity
        key = self._derive_encryption_key(bytes.fromhex(package.salt_hex))
        plaintext = self._xor_cipher(
            bytes.fromhex(package.ciphertext_hex),
            key,
            bytes.fromhex(package.nonce_hex),
        )

        computed_digest = hashlib.sha256(plaintext).hexdigest()
        if computed_digest != package.artifact_digest:
            raise ValueError("Decrypted artifact integrity compromised")

        return plaintext
