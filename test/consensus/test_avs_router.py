"""
Task P11-008: Unit tests for Consensus Finding AVS Router.
Validates exemption of non-AVS findings, mandatory quorum routing for
high/critical findings, digest mismatch rejection, signature forgery
rejection, and replay prevention.
"""

import hashlib
import unittest

from src.consensus.avs_router import ConsensusAvsRouter, RoutingVerdict
from src.consensus.bls_aggregation import BLSAggregator, QuorumCertificate, ValidatorKeyring
from src.consensus.graph_enricher import ConsensusFinding


class TestConsensusAvsRouter(unittest.TestCase):
    def setUp(self):
        self.validators = ["val-1", "val-2", "val-3", "val-4"]
        self.keyring = ValidatorKeyring()
        for v in self.validators:
            self.keyring.register_validator(v)

        self.aggregator = BLSAggregator(
            registered_validators=self.validators,
            keyring=self.keyring,
        )
        self.router = ConsensusAvsRouter(bls_aggregator=self.aggregator)

    def _create_finding(self, severity: str, requires_avs: bool, digest: str) -> ConsensusFinding:
        return ConsensusFinding(
            finding_id=f"finding-{digest[:8]}",
            finding_type="CHAIN_REORGANIZATION",
            severity=severity,
            zone="ZONE_6_CONSENSUS",
            layer="CONSENSUS",
            title=f"Test Finding {severity}",
            description="Testing AVS routing",
            crypto_digest=digest,
            requires_avs=requires_avs,
            nodes=[],
            edges=[],
            timestamp=1700000000.0,
        )

    def _sign_votes(self, attestation_id: str, finding_digest: str, receipt_hash: str, signer_ids: list):
        msg_digest = self.aggregator.compute_message_digest(attestation_id, finding_digest, receipt_hash)
        return {v_id: self.keyring.sign(v_id, msg_digest) for v_id in signer_ids}

    def test_low_severity_exempt_from_avs(self):
        digest = "a" * 64
        finding = self._create_finding("LOW", requires_avs=False, digest=digest)
        payload = self.router.route_finding(finding)

        self.assertEqual(payload.routing_verdict, RoutingVerdict.EXEMPT)
        self.assertIsNone(payload.quorum_certificate)
        self.assertEqual(payload.crypto_digest, digest)

    def test_high_severity_missing_certificate_raises_permission_error(self):
        digest = "b" * 64
        finding = self._create_finding("HIGH", requires_avs=True, digest=digest)
        with self.assertRaises(PermissionError) as ctx:
            self.router.route_finding(finding, quorum_certificate=None)
        self.assertIn("requires AVS quorum certification", str(ctx.exception))

    def test_valid_quorum_certificate_approves_critical_finding(self):
        digest = "c" * 64
        receipt_hash = hashlib.sha256(b"receipt-001").hexdigest()
        finding = self._create_finding("CRITICAL", requires_avs=True, digest=digest)

        # 3 validators vote (3/4 = 75% > 66.7% supermajority)
        votes = self._sign_votes("attest-001", digest, receipt_hash, ["val-1", "val-2", "val-3"])
        cert = self.aggregator.aggregate_signatures(
            attestation_id="attest-001",
            finding_digest=digest,
            receipt_hash=receipt_hash,
            votes=votes,
        )

        payload = self.router.route_finding(finding, quorum_certificate=cert, receipt_hash=receipt_hash)
        self.assertEqual(payload.routing_verdict, RoutingVerdict.APPROVED)
        self.assertIsNotNone(payload.quorum_certificate)
        self.assertEqual(payload.quorum_certificate["attestation_id"], "attest-001")

    def test_digest_mismatch_raises_value_error(self):
        digest_finding = "d" * 64
        digest_other = "e" * 64
        receipt_hash = hashlib.sha256(b"receipt-002").hexdigest()
        finding = self._create_finding("HIGH", requires_avs=True, digest=digest_finding)

        votes = self._sign_votes("attest-002", digest_other, receipt_hash, ["val-1", "val-2", "val-3"])
        cert = self.aggregator.aggregate_signatures(
            attestation_id="attest-002",
            finding_digest=digest_other,
            receipt_hash=receipt_hash,
            votes=votes,
        )

        with self.assertRaises(ValueError) as ctx:
            self.router.route_finding(finding, quorum_certificate=cert, receipt_hash=receipt_hash)
        self.assertIn("Certificate digest mismatch", str(ctx.exception))

    def test_replay_attack_rejected(self):
        digest = "f" * 64
        receipt_hash = hashlib.sha256(b"receipt-003").hexdigest()
        finding = self._create_finding("HIGH", requires_avs=True, digest=digest)

        votes = self._sign_votes("attest-replay", digest, receipt_hash, ["val-1", "val-2", "val-3"])
        cert = self.aggregator.aggregate_signatures(
            attestation_id="attest-replay",
            finding_digest=digest,
            receipt_hash=receipt_hash,
            votes=votes,
        )

        # First routing succeeds
        self.router.route_finding(finding, quorum_certificate=cert, receipt_hash=receipt_hash)

        # Replay attempt fails
        with self.assertRaises(ValueError) as ctx:
            self.router.route_finding(finding, quorum_certificate=cert, receipt_hash=receipt_hash)
        self.assertIn("Replay attack detected", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
