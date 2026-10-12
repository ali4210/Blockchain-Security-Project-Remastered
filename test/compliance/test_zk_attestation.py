"""
Task P13-003: Unit tests for Simplified ZK Compliance Attestation.
Validates:
1. Generation of valid zero-knowledge compliance proof.
2. Complete verification without revealing underlying address or volume.
3. Strict rejection of sanctioned addresses at generation.
4. Strict rejection of volume exceeding threshold.
5. Challenge tampering detection and fail-closed verification.
"""

import unittest

from src.compliance.zk_attestation import (
    SimpleZKAttestor,
    ComplianceProof,
)


class TestZKAttestation(unittest.TestCase):
    def setUp(self):
        self.attestor = SimpleZKAttestor()
        self.sanctioned_list = [
            "0x098B716B8Aaf21512996dC57EB0615e2383E2f96",  # Ronin
            "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",  # Tornado
        ]

    def test_generate_and_verify_valid_attestation(self):
        clean_sender = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        volume_wei = 5 * 10**18  # 5 ETH
        max_cap = 10**19  # 10 ETH

        proof, witness = self.attestor.generate_attestation(
            sender_address=clean_sender,
            volume_wei=volume_wei,
            max_threshold_wei=max_cap,
            known_sanctioned_addresses=self.sanctioned_list,
        )

        # Public proof must not contain clean_sender or volume in plaintext
        self.assertNotIn(clean_sender.lower(), proof.address_commitment.lower())
        self.assertNotIn(str(volume_wei), proof.volume_commitment)

        # Verification succeeds with public proof only
        self.assertTrue(self.attestor.verify_attestation(proof))

        # Verification succeeds with full witness
        self.assertTrue(self.attestor.verify_attestation(proof, witness=witness))

    def test_sanctioned_address_rejected_at_generation(self):
        sanctioned_sender = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
        with self.assertRaises(ValueError) as ctx:
            self.attestor.generate_attestation(
                sender_address=sanctioned_sender,
                volume_wei=10**18,
                max_threshold_wei=10**19,
                known_sanctioned_addresses=self.sanctioned_list,
            )
        self.assertIn("sanctioned address", str(ctx.exception).lower())

    def test_excessive_volume_rejected_at_generation(self):
        clean_sender = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        excessive_volume = 15 * 10**18  # 15 ETH
        max_cap = 10**19  # 10 ETH

        with self.assertRaises(ValueError) as ctx:
            self.attestor.generate_attestation(
                sender_address=clean_sender,
                volume_wei=excessive_volume,
                max_threshold_wei=max_cap,
                known_sanctioned_addresses=self.sanctioned_list,
            )
        self.assertIn("exceeds compliance bound", str(ctx.exception).lower())

    def test_tampered_challenge_fails_verification(self):
        clean_sender = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        proof, _ = self.attestor.generate_attestation(
            sender_address=clean_sender,
            volume_wei=10**18,
            max_threshold_wei=10**19,
            known_sanctioned_addresses=self.sanctioned_list,
        )

        tampered_proof = ComplianceProof(
            proof_id=proof.proof_id,
            nullifier_hash=proof.nullifier_hash,
            address_commitment=proof.address_commitment,
            volume_commitment=proof.volume_commitment,
            max_threshold_wei=proof.max_threshold_wei,
            merkle_root=proof.merkle_root,
            challenge="0xdeadbeef" * 8,  # Forged challenge
            response_signature=proof.response_signature,
            is_sanctions_free=proof.is_sanctions_free,
        )

        self.assertFalse(self.attestor.verify_attestation(tampered_proof))

    def test_mismatched_merkle_root_fails_verification(self):
        clean_sender = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        proof, _ = self.attestor.generate_attestation(
            sender_address=clean_sender,
            volume_wei=10**18,
            max_threshold_wei=10**19,
            known_sanctioned_addresses=self.sanctioned_list,
        )

        tampered_proof = ComplianceProof(
            proof_id=proof.proof_id,
            nullifier_hash=proof.nullifier_hash,
            address_commitment=proof.address_commitment,
            volume_commitment=proof.volume_commitment,
            max_threshold_wei=proof.max_threshold_wei,
            merkle_root="0xwrongroot" * 6,
            challenge=proof.challenge,
            response_signature=proof.response_signature,
            is_sanctions_free=proof.is_sanctions_free,
        )

        self.assertFalse(self.attestor.verify_attestation(tampered_proof))


if __name__ == "__main__":
    unittest.main()
