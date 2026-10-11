"""
Task P10A-001: Forensic Merkle Manifest & Cryptographic Signing.
Builds RFC 6962-compliant Merkle trees across evidence manifests, calculates
deterministic roots, and provides HMAC-SHA256 signature verification.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Dict, List

from src.forensics.hasher import ArtifactDigest

DEFAULT_FORENSIC_KEY = b"SOC_DFIR_MANIFEST_SIGNING_KEY_P10A"


def _hash_leaf(data: bytes) -> bytes:
    # RFC 6962 domain separation prefix 0x00 for leaves
    return hashlib.sha256(b"\x00" + data).digest()


def _hash_internal(left: bytes, right: bytes) -> bytes:
    # RFC 6962 domain separation prefix 0x01 for interior nodes
    return hashlib.sha256(b"\x01" + left + right).digest()


def compute_merkle_root(leaf_hashes: List[bytes]) -> bytes:
    """Computes RFC 6962 Merkle tree root for an ordered list of leaf hashes."""
    if not leaf_hashes:
        return hashlib.sha256(b"").digest()

    current_level = list(leaf_hashes)
    while len(current_level) > 1:
        next_level: List[bytes] = []
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                next_level.append(_hash_internal(current_level[i], current_level[i + 1]))
            else:
                # Odd leaf is promoted or hashed with itself
                next_level.append(_hash_internal(current_level[i], current_level[i]))
        current_level = next_level

    return current_level[0]


@dataclass
class ForensicManifest:
    manifest_id: str
    created_at: str
    artifacts: List[Dict[str, Any]]
    merkle_root: str
    operator_principal: str
    signature: str

    def canonical_bytes(self) -> bytes:
        payload = {
            "manifest_id": self.manifest_id,
            "created_at": self.created_at,
            "artifacts": self.artifacts,
            "merkle_root": self.merkle_root,
            "operator_principal": self.operator_principal,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ForensicManifestManager:
    """Constructs, signs, and verifies tamper-evident forensic evidence manifests."""

    def __init__(self, signing_key: bytes = DEFAULT_FORENSIC_KEY):
        self.signing_key = signing_key

    def create_manifest(
        self,
        manifest_id: str,
        digests: List[ArtifactDigest],
        operator_principal: str = "soc-operator",
    ) -> ForensicManifest:
        # Sort artifacts deterministically by file_path
        sorted_digests = sorted(digests, key=lambda d: d.file_path)
        artifacts = [d.to_dict() for d in sorted_digests]

        # Calculate RFC 6962 leaf hashes over canonical artifact records
        leaf_hashes = [
            _hash_leaf(
                json.dumps(art, sort_keys=True, separators=(",", ":")).encode("utf-8")
            )
            for art in artifacts
        ]

        merkle_root_bytes = compute_merkle_root(leaf_hashes)
        merkle_root_hex = merkle_root_bytes.hex()
        created_at = datetime.now(timezone.utc).isoformat()

        manifest = ForensicManifest(
            manifest_id=manifest_id,
            created_at=created_at,
            artifacts=artifacts,
            merkle_root=merkle_root_hex,
            operator_principal=operator_principal,
            signature="",
        )

        sig = hmac.new(
            self.signing_key, manifest.canonical_bytes(), hashlib.sha256
        ).hexdigest()
        manifest.signature = sig
        return manifest

    def verify_manifest(self, manifest: ForensicManifest) -> bool:
        """Verifies signature authenticity and validates Merkle tree root recalculation."""
        # 1. Verify operator principal authority
        if manifest.operator_principal != "soc-operator":
            raise PermissionError(
                f"Manifest author '{manifest.operator_principal}' is unauthorized. Must be 'soc-operator'."
            )

        # 2. Verify HMAC-SHA256 signature
        expected_sig = hmac.new(
            self.signing_key, manifest.canonical_bytes(), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_sig, manifest.signature):
            raise PermissionError("Manifest verification failed: invalid or forged HMAC signature.")

        # 3. Recalculate Merkle root from artifacts
        leaf_hashes = [
            _hash_leaf(
                json.dumps(art, sort_keys=True, separators=(",", ":")).encode("utf-8")
            )
            for art in manifest.artifacts
        ]
        recalculated_root = compute_merkle_root(leaf_hashes).hex()
        if recalculated_root != manifest.merkle_root:
            raise ValueError(
                f"Manifest verification failed: Merkle root mismatch (expected {manifest.merkle_root}, got {recalculated_root})."
            )

        return True
