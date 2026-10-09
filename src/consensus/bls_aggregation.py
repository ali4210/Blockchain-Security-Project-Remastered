"""
Task P06-005: Threshold BLS / Multisignature-Hash-Agreement Aggregation Module.
Implements cryptographic multi-validator signature aggregation into a canonical
QuorumCertificate, enforcing strict BFT supermajority thresholds, tamper detection,
and binding to finding attestation digests and execution receipts.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass(frozen=True)
class QuorumCertificate:
    attestation_id: str
    finding_digest: str
    participating_validators: List[str]
    individual_signatures: Dict[str, str]
    aggregate_signature: str
    threshold_fraction: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attestation_id": self.attestation_id,
            "finding_digest": self.finding_digest,
            "participating_validators": self.participating_validators,
            "individual_signatures": self.individual_signatures,
            "aggregate_signature": self.aggregate_signature,
            "threshold_fraction": self.threshold_fraction,
            "created_at": self.created_at,
        }


class ValidatorKeyring:
    """
    Manages cryptographic keys for AVS validators.
    Uses deterministic HMAC-SHA256 stand-ins for educational simulation.
    """

    def __init__(self, seed: str = "bsp-avs-seed"):
        self.seed = seed
        self._private_keys: Dict[str, str] = {}
        self._public_keys: Dict[str, str] = {}

    def register_validator(self, validator_id: str) -> str:
        """Derives and registers public key for a validator."""
        priv = hashlib.sha256(f"{self.seed}:{validator_id}:priv".encode("utf-8")).hexdigest()
        pub = hashlib.sha256(f"{priv}:pub".encode("utf-8")).hexdigest()
        self._private_keys[validator_id] = priv
        self._public_keys[validator_id] = pub
        return pub

    def get_public_key(self, validator_id: str) -> Optional[str]:
        return self._public_keys.get(validator_id)

    def sign(self, validator_id: str, message: str) -> str:
        priv = self._private_keys.get(validator_id)
        if not priv:
            raise KeyError(f"Validator '{validator_id}' not found in keyring.")
        sig = hmac.new(priv.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
        return sig

    def verify(self, validator_id: str, message: str, signature: str) -> bool:
        priv = self._private_keys.get(validator_id)
        if not priv:
            return False
        expected = hmac.new(priv.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


class BLSAggregator:
    """
    Aggregates individual validator signatures into a threshold QuorumCertificate.
    """

    def __init__(self, registered_validators: List[str], keyring: Optional[ValidatorKeyring] = None):
        self.registered_validators = sorted(list(set(registered_validators)))
        self.total_validators = len(self.registered_validators)
        self.keyring = keyring or ValidatorKeyring()

        for v_id in self.registered_validators:
            if not self.keyring.get_public_key(v_id):
                self.keyring.register_validator(v_id)

    def compute_message_digest(self, attestation_id: str, finding_digest: str, receipt_hash: str) -> str:
        payload = f"{attestation_id}:{finding_digest}:{receipt_hash}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def aggregate_signatures(
        self,
        attestation_id: str,
        finding_digest: str,
        receipt_hash: str,
        votes: Dict[str, str],  # validator_id -> signature
    ) -> QuorumCertificate:
        """
        Validates individual signatures and aggregates them into a QuorumCertificate.
        Enforces strict >66.7% BFT supermajority (3 * V > 2 * N).
        """
        message_digest = self.compute_message_digest(attestation_id, finding_digest, receipt_hash)
        valid_signers: List[str] = []
        valid_signatures: Dict[str, str] = {}

        for v_id, sig in votes.items():
            if v_id not in self.registered_validators:
                continue
            if self.keyring.verify(v_id, message_digest, sig):
                valid_signers.append(v_id)
                valid_signatures[v_id] = sig

        valid_count = len(valid_signers)
        # Strict BFT supermajority integer comparison
        if (3 * valid_count) <= (2 * self.total_validators):
            raise ValueError(
                f"Quorum threshold not met: {valid_count}/{self.total_validators} valid signatures "
                f"is insufficient for >66.7% BFT supermajority."
            )

        sorted_signers = sorted(valid_signers)
        sig_bundle = [f"{s}:{valid_signatures[s]}" for s in sorted_signers]
        agg_payload = f"{attestation_id}:{finding_digest}:{','.join(sig_bundle)}".encode("utf-8")
        aggregate_signature = hashlib.sha256(agg_payload).hexdigest()

        return QuorumCertificate(
            attestation_id=attestation_id,
            finding_digest=finding_digest,
            participating_validators=sorted_signers,
            individual_signatures=valid_signatures,
            aggregate_signature=aggregate_signature,
            threshold_fraction=f"{valid_count}/{self.total_validators}",
        )

    def verify_quorum_certificate(
        self,
        certificate: QuorumCertificate,
        receipt_hash: str,
    ) -> bool:
        """
        Verifies complete cryptographic integrity of a QuorumCertificate.
        Asserts supermajority, individual signature fidelity, and aggregate digest.
        """
        signers = certificate.participating_validators
        valid_count = len(signers)

        if (3 * valid_count) <= (2 * self.total_validators):
            return False

        message_digest = self.compute_message_digest(
            certificate.attestation_id, certificate.finding_digest, receipt_hash
        )

        for v_id in signers:
            if v_id not in self.registered_validators:
                return False
            sig = certificate.individual_signatures.get(v_id)
            if not sig or not self.keyring.verify(v_id, message_digest, sig):
                return False

        sorted_signers = sorted(signers)
        sig_bundle = [f"{s}:{certificate.individual_signatures[s]}" for s in sorted_signers]
        expected_agg = hashlib.sha256(
            f"{certificate.attestation_id}:{certificate.finding_digest}:{','.join(sig_bundle)}".encode("utf-8")
        ).hexdigest()

        return hmac.compare_digest(expected_agg, certificate.aggregate_signature)
