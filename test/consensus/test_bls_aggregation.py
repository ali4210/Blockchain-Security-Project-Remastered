"""
Task P06-005: Comprehensive Unit Tests for Threshold BLS / Multisig Aggregator.
Validates key generation, signature emission, threshold quorum certificate creation,
verification, and rejection of tampered or sub-threshold certificates.
"""

import unittest
from src.consensus.bls_aggregation import ValidatorKeyring, BLSAggregator, QuorumCertificate


class TestBLSAggregation(unittest.TestCase):
    def setUp(self):
        self.validators = ["validator-1", "validator-2", "validator-3"]
        self.keyring = ValidatorKeyring(seed="test-bls-seed")
        self.aggregator = BLSAggregator(self.validators, keyring=self.keyring)
        self.attestation_id = "ATT-FINDING-001-A1B2C3D4"
        self.finding_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.receipt_hash = "f4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afb"

    def test_keyring_registration_and_signature_verification(self):
        msg = "canonical-test-message"
        sig1 = self.keyring.sign("validator-1", msg)
        self.assertTrue(self.keyring.verify("validator-1", msg, sig1))
        self.assertFalse(self.keyring.verify("validator-2", msg, sig1))
        self.assertFalse(self.keyring.verify("validator-1", "altered-message", sig1))

    def test_full_quorum_aggregation_and_verification_success(self):
        msg_digest = self.aggregator.compute_message_digest(
            self.attestation_id, self.finding_digest, self.receipt_hash
        )
        votes = {
            v: self.keyring.sign(v, msg_digest)
            for v in self.validators
        }

        cert = self.aggregator.aggregate_signatures(
            self.attestation_id, self.finding_digest, self.receipt_hash, votes
        )
        self.assertIsInstance(cert, QuorumCertificate)
        self.assertEqual(len(cert.participating_validators), 3)
        self.assertEqual(cert.threshold_fraction, "3/3")
        self.assertTrue(self.aggregator.verify_quorum_certificate(cert, self.receipt_hash))

    def test_sub_threshold_aggregation_rejection(self):
        # N=3: 2 votes = 66.67% (fails >66.7% BFT supermajority)
        msg_digest = self.aggregator.compute_message_digest(
            self.attestation_id, self.finding_digest, self.receipt_hash
        )
        votes = {
            "validator-1": self.keyring.sign("validator-1", msg_digest),
            "validator-2": self.keyring.sign("validator-2", msg_digest),
        }

        with self.assertRaises(ValueError) as ctx:
            self.aggregator.aggregate_signatures(
                self.attestation_id, self.finding_digest, self.receipt_hash, votes
            )
        self.assertIn("Quorum threshold not met", str(ctx.exception))

    def test_tampered_payload_fails_certificate_verification(self):
        msg_digest = self.aggregator.compute_message_digest(
            self.attestation_id, self.finding_digest, self.receipt_hash
        )
        votes = {v: self.keyring.sign(v, msg_digest) for v in self.validators}
        cert = self.aggregator.aggregate_signatures(
            self.attestation_id, self.finding_digest, self.receipt_hash, votes
        )

        # Alter receipt hash during verification
        self.assertFalse(self.aggregator.verify_quorum_certificate(cert, "altered-receipt-hash"))

    def test_tampered_aggregate_signature_fails(self):
        msg_digest = self.aggregator.compute_message_digest(
            self.attestation_id, self.finding_digest, self.receipt_hash
        )
        votes = {v: self.keyring.sign(v, msg_digest) for v in self.validators}
        cert = self.aggregator.aggregate_signatures(
            self.attestation_id, self.finding_digest, self.receipt_hash, votes
        )

        tampered_cert = QuorumCertificate(
            attestation_id=cert.attestation_id,
            finding_digest=cert.finding_digest,
            participating_validators=cert.participating_validators,
            individual_signatures=cert.individual_signatures,
            aggregate_signature="bad0000000000000000000000000000000000000000000000000000000000000",
            threshold_fraction=cert.threshold_fraction,
        )
        self.assertFalse(self.aggregator.verify_quorum_certificate(tampered_cert, self.receipt_hash))

    def test_four_node_quorum_scaling(self):
        # N=4: 3/4 = 75% (>66.7%) passes
        v4 = ["v-1", "v-2", "v-3", "v-4"]
        agg4 = BLSAggregator(v4, keyring=ValidatorKeyring(seed="seed-4"))
        msg_digest = agg4.compute_message_digest(
            self.attestation_id, self.finding_digest, self.receipt_hash
        )
        votes = {
            "v-1": agg4.keyring.sign("v-1", msg_digest),
            "v-2": agg4.keyring.sign("v-2", msg_digest),
            "v-3": agg4.keyring.sign("v-3", msg_digest),
        }
        cert = agg4.aggregate_signatures(
            self.attestation_id, self.finding_digest, self.receipt_hash, votes
        )
        self.assertEqual(cert.threshold_fraction, "3/4")
        self.assertTrue(agg4.verify_quorum_certificate(cert, self.receipt_hash))


if __name__ == "__main__":
    unittest.main()
