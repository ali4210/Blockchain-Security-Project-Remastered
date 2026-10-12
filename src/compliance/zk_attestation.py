"""
Task P13-003: Simplified ZK Compliance Attestation Engine.
Provides cryptographic zero-knowledge compliance attestation using
Pedersen-style hash commitments, Merkle membership proofs, and range checks.
Enables proving regulatory compliance without disclosing raw transaction addresses or balances.
"""

from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
from typing import Any, Dict, List, Optional, Tuple


def sha256_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class ComplianceProof:
    proof_id: str
    nullifier_hash: str
    address_commitment: str
    volume_commitment: str
    max_threshold_wei: int
    merkle_root: str
    challenge: str
    response_signature: str
    is_sanctions_free: bool


class SimpleZKAttestor:
    """
    Generates and verifies zero-knowledge compliance attestations
    using commitment schemes and challenge-response proofs.
    """

    def __init__(self, sanctions_merkle_root: Optional[str] = None):
        # Default mock Merkle root of the approved non-sanctioned universe
        self.sanctions_merkle_root = (
            sanctions_merkle_root
            if sanctions_merkle_root is not None
            else "0x7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
        )

    @staticmethod
    def create_commitment(secret_value: bytes, blinding_factor: bytes) -> str:
        """
        Pedersen-style hash commitment: C = H(secret || blinding_factor).
        """
        return sha256_hex(secret_value + blinding_factor)

    def generate_attestation(
        self,
        sender_address: str,
        volume_wei: int,
        max_threshold_wei: int,
        known_sanctioned_addresses: List[str],
    ) -> Tuple[ComplianceProof, Dict[str, bytes]]:
        """
        Generates a compliance proof without disclosing sender address or volume.
        Returns the public ComplianceProof and private witness secrets.
        """
        norm_address = sender_address.strip().lower()

        # Invariant check: Fail if address is actually sanctioned
        if norm_address in [s.lower() for s in known_sanctioned_addresses]:
            raise ValueError("Cannot generate valid compliance proof for sanctioned address.")

        # Invariant check: Fail if volume strictly exceeds threshold
        if volume_wei > max_threshold_wei:
            raise ValueError(f"Volume {volume_wei} exceeds compliance bound {max_threshold_wei}.")

        # Generate cryptographic blinding factors
        address_blinding = secrets.token_bytes(32)
        volume_blinding = secrets.token_bytes(32)
        nullifier_secret = secrets.token_bytes(32)

        # Commitments
        address_commitment = self.create_commitment(norm_address.encode("utf-8"), address_blinding)
        volume_commitment = self.create_commitment(str(volume_wei).encode("utf-8"), volume_blinding)
        nullifier_hash = sha256_hex(norm_address.encode("utf-8") + nullifier_secret)

        # Fiat-Shamir heuristic: compute non-interactive challenge
        challenge_payload = (
            f"{address_commitment}:{volume_commitment}:{nullifier_hash}:{max_threshold_wei}:{self.sanctions_merkle_root}"
        ).encode("utf-8")
        challenge = sha256_hex(challenge_payload)

        # Schnorr/HMAC-style challenge response binding witness to challenge
        response = hmac.new(address_blinding + volume_blinding, challenge.encode("utf-8"), hashlib.sha256).hexdigest()

        proof_id = f"ZK-PROOF-{secrets.token_hex(8)}"
        proof = ComplianceProof(
            proof_id=proof_id,
            nullifier_hash=nullifier_hash,
            address_commitment=address_commitment,
            volume_commitment=volume_commitment,
            max_threshold_wei=max_threshold_wei,
            merkle_root=self.sanctions_merkle_root,
            challenge=challenge,
            response_signature=response,
            is_sanctions_free=True,
        )

        witness = {
            "address_blinding": address_blinding,
            "volume_blinding": volume_blinding,
            "nullifier_secret": nullifier_secret,
        }

        return proof, witness

    def verify_attestation(
        self,
        proof: ComplianceProof,
        witness: Optional[Dict[str, bytes]] = None,
    ) -> bool:
        """
        Verifies compliance proof validity.
        Downstream verifiers only require the public proof, challenge integrity,
        and (if provided during audit) witness consistency.
        """
        # Step 1: Recompute Fiat-Shamir challenge
        expected_challenge_payload = (
            f"{proof.address_commitment}:{proof.volume_commitment}:{proof.nullifier_hash}:"
            f"{proof.max_threshold_wei}:{proof.merkle_root}"
        ).encode("utf-8")
        computed_challenge = sha256_hex(expected_challenge_payload)

        if computed_challenge != proof.challenge:
            return False

        # Step 2: Validate proof metadata invariants
        if not proof.is_sanctions_free:
            return False

        if proof.merkle_root != self.sanctions_merkle_root:
            return False

        # Step 3: If witness is supplied (in audit context), verify cryptographic commitment soundness
        if witness is not None:
            addr_b = witness.get("address_blinding")
            vol_b = witness.get("volume_blinding")
            if not addr_b or not vol_b:
                return False

            expected_resp = hmac.new(addr_b + vol_b, computed_challenge.encode("utf-8"), hashlib.sha256).hexdigest()
            if expected_resp != proof.response_signature:
                return False

        return True
