"""
Task P13-011: Incident Drill - ZK Attestation Verification Without Transaction Disclosure.
Simulates an end-to-end zero-knowledge compliance verification drill:
1. Generate valid zero-knowledge compliance proof for clean private transactions.
2. Verify regulatory compliance without disclosing raw sender addresses or volume amounts.
3. Validate fail-closed rejection of proofs for sanctioned actors.
4. Validate fail-closed rejection of proofs exceeding volume caps.
5. Validate tamper-proofing of challenge, commitments, and Merkle root.
"""

import unittest

from src.compliance.zk_attestation import (
    SimpleZKAttestor,
    ComplianceProof,
)
from src.compliance.compliance_mcp import ComplianceMCPRegistry


class TestDrillZKAttestation(unittest.TestCase):
    def setUp(self):
        self.attestor = SimpleZKAttestor()
        self.mcp = ComplianceMCPRegistry()

        self.sanctioned_addresses = [
            "0x098B716B8Aaf21512996dC57EB0615e2383E2f96",  # Ronin Bridge Exploiter
            "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",  # Tornado Cash Router
        ]

        self.clean_private_sender = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        self.transfer_volume_wei = 7 * 10**18  # 7 ETH
        self.max_compliance_bound_wei = 10 * 10**18  # 10 ETH

    def test_end_to_end_zk_attestation_drill_success(self):
        # Step 1: Prover generates compliance proof with private inputs
        proof, witness = self.attestor.generate_attestation(
            sender_address=self.clean_private_sender,
            volume_wei=self.transfer_volume_wei,
            max_threshold_wei=self.max_compliance_bound_wei,
            known_sanctioned_addresses=self.sanctioned_addresses,
        )

        # Invariant 1: Assert zero raw leakage in public proof object
        self.assertNotIn(self.clean_private_sender.lower(), proof.address_commitment.lower())
        self.assertNotIn(str(self.transfer_volume_wei), proof.volume_commitment)
        self.assertTrue(proof.is_sanctions_free)

        # Step 2: External verifier evaluates proof using only public metadata
        is_valid = self.attestor.verify_attestation(proof)
        self.assertTrue(is_valid)

        # Step 3: Verifier evaluates proof via MCP tool endpoint
        mcp_res = self.mcp.call_tool(
            "compliance_verify_zk_attestation",
            {
                "proof": {
                    "proof_id": proof.proof_id,
                    "nullifier_hash": proof.nullifier_hash,
                    "address_commitment": proof.address_commitment,
                    "volume_commitment": proof.volume_commitment,
                    "max_threshold_wei": proof.max_threshold_wei,
                    "merkle_root": proof.merkle_root,
                    "challenge": proof.challenge,
                    "response_signature": proof.response_signature,
                    "is_sanctions_free": proof.is_sanctions_free,
                }
            },
        )
        self.assertEqual(mcp_res["status"], "success")
        self.assertTrue(mcp_res["result"]["is_valid"])

    def test_zk_drill_rejects_sanctioned_actor_at_generation(self):
        sanctioned_actor = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
        with self.assertRaises(ValueError) as ctx:
            self.attestor.generate_attestation(
                sender_address=sanctioned_actor,
                volume_wei=10**18,
                max_threshold_wei=10**19,
                known_sanctioned_addresses=self.sanctioned_addresses,
            )
        self.assertIn("sanctioned address", str(ctx.exception).lower())

    def test_zk_drill_rejects_over_cap_volume_at_generation(self):
        excessive_volume = 25 * 10**18  # 25 ETH > 10 ETH bound
        with self.assertRaises(ValueError) as ctx:
            self.attestor.generate_attestation(
                sender_address=self.clean_private_sender,
                volume_wei=excessive_volume,
                max_threshold_wei=self.max_compliance_bound_wei,
                known_sanctioned_addresses=self.sanctioned_addresses,
            )
        self.assertIn("exceeds compliance bound", str(ctx.exception).lower())

    def test_zk_drill_fails_closed_on_tampered_challenge(self):
        proof, _ = self.attestor.generate_attestation(
            sender_address=self.clean_private_sender,
            volume_wei=self.transfer_volume_wei,
            max_threshold_wei=self.max_compliance_bound_wei,
            known_sanctioned_addresses=self.sanctioned_addresses,
        )

        # Adversary attempts to forge challenge
        tampered_proof = ComplianceProof(
            proof_id=proof.proof_id,
            nullifier_hash=proof.nullifier_hash,
            address_commitment=proof.address_commitment,
            volume_commitment=proof.volume_commitment,
            max_threshold_wei=proof.max_threshold_wei,
            merkle_root=proof.merkle_root,
            challenge="0xbadchallenge00000000000000000000000000000000000000000000000000000",
            response_signature=proof.response_signature,
            is_sanctions_free=proof.is_sanctions_free,
        )

        self.assertFalse(self.attestor.verify_attestation(tampered_proof))

    def test_zk_drill_fails_closed_on_tampered_threshold(self):
        proof, _ = self.attestor.generate_attestation(
            sender_address=self.clean_private_sender,
            volume_wei=self.transfer_volume_wei,
            max_threshold_wei=self.max_compliance_bound_wei,
            known_sanctioned_addresses=self.sanctioned_addresses,
        )

        # Adversary attempts to claim lower compliance bound post-hoc
        tampered_proof = ComplianceProof(
            proof_id=proof.proof_id,
            nullifier_hash=proof.nullifier_hash,
            address_commitment=proof.address_commitment,
            volume_commitment=proof.volume_commitment,
            max_threshold_wei=10**17,  # Altered threshold
            merkle_root=proof.merkle_root,
            challenge=proof.challenge,
            response_signature=proof.response_signature,
            is_sanctions_free=proof.is_sanctions_free,
        )

        self.assertFalse(self.attestor.verify_attestation(tampered_proof))


if __name__ == "__main__":
    unittest.main()
