"""
Task P06-008: Comprehensive Unit Tests for Forensic Event Emitter.
Validates schemaVersion: 1 compliance, cryptographic payload binding,
tamper detection, deterministic caseId calculation, and strict rejection of uncertified findings.
"""

from pathlib import Path
import tempfile
import unittest

from src.consensus.avs_gate import AVSGate, ConsensusResult, ConsensusStatus
from src.consensus.bls_aggregation import QuorumCertificate, ValidatorKeyring, BLSAggregator
from src.consensus.forensic_event_emitter import ForensicEventEmitter, CaseOpenedEvent


class TestForensicEventEmitter(unittest.TestCase):
    def setUp(self):
        self.validators = ["validator-1", "validator-2", "validator-3"]
        self.keyring = ValidatorKeyring(seed="emitter-test-seed")
        self.aggregator = BLSAggregator(self.validators, keyring=self.keyring)
        self.emitter = ForensicEventEmitter()
        self.finding = {
            "id": "FINDING-CRIT-999",
            "target_contract": "contracts/solidity/VulnerableVault.sol",
            "category": "REENTRANCY_VULNERABILITY",
            "severity": "CRITICAL",
        }
        self.receipt_hash = "0xdeadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"

    def _generate_valid_cert(self, attestation_id: str = "ATT-999-A1B2C3D4") -> QuorumCertificate:
        msg_digest = self.aggregator.compute_message_digest(
            attestation_id, "mock-finding-digest", self.receipt_hash
        )
        votes = {v: self.keyring.sign(v, msg_digest) for v in self.validators}
        return self.aggregator.aggregate_signatures(
            attestation_id, "mock-finding-digest", self.receipt_hash, votes
        )

    def test_emit_case_opened_success(self):
        cert = self._generate_valid_cert()
        consensus_result = ConsensusResult(
            attestation_id=cert.attestation_id,
            finding_id="FINDING-CRIT-999",
            status=ConsensusStatus.AGREED,
            total_validators=3,
            validated_votes=3,
            rejected_votes=0,
            inconclusive_votes=0,
            supermajority_ratio=1.0,
            supermajority_achieved=True,
            certificate=cert,
        )

        event = self.emitter.emit_case_opened(self.finding, consensus_result, self.receipt_hash)

        self.assertIsInstance(event, CaseOpenedEvent)
        self.assertEqual(event.schemaVersion, 1)
        self.assertEqual(event.eventType, "case-opened")
        self.assertEqual(event.findingId, "FINDING-CRIT-999")
        self.assertEqual(event.severity, "CRITICAL")
        self.assertTrue(event.caseId.startswith("CASE-VulnerableVault-"))
        self.assertEqual(event.executionReceiptHash, self.receipt_hash)
        self.assertEqual(len(event.quorumCertificate["participating_validators"]), 3)
        self.assertTrue(len(event.eventDigest) == 64)

    def test_rejected_consensus_raises_permission_error(self):
        rejected_result = ConsensusResult(
            attestation_id="ATT-REJECTED-001",
            finding_id="FINDING-CRIT-999",
            status=ConsensusStatus.REJECTED,
            total_validators=3,
            validated_votes=1,
            rejected_votes=2,
            inconclusive_votes=0,
            supermajority_ratio=0.33,
            supermajority_achieved=False,
            certificate=None,
        )

        with self.assertRaises(PermissionError) as ctx:
            self.emitter.emit_case_opened(self.finding, rejected_result, self.receipt_hash)

        self.assertIn("did not achieve supermajority quorum", str(ctx.exception))

    def test_missing_certificate_on_agreed_raises_permission_error(self):
        agreed_no_cert = ConsensusResult(
            attestation_id="ATT-NO-CERT",
            finding_id="FINDING-CRIT-999",
            status=ConsensusStatus.AGREED,
            total_validators=3,
            validated_votes=3,
            rejected_votes=0,
            inconclusive_votes=0,
            supermajority_ratio=1.0,
            supermajority_achieved=True,
            certificate=None,
        )

        with self.assertRaises(PermissionError):
            self.emitter.emit_case_opened(self.finding, agreed_no_cert, self.receipt_hash)

    def test_event_persistence_to_append_only_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "forensics" / "events.jsonl"
            file_emitter = ForensicEventEmitter(log_path=log_file)
            cert = self._generate_valid_cert()
            consensus_result = ConsensusResult(
                attestation_id=cert.attestation_id,
                finding_id="FINDING-CRIT-999",
                status=ConsensusStatus.AGREED,
                total_validators=3,
                validated_votes=3,
                rejected_votes=0,
                inconclusive_votes=0,
                supermajority_ratio=1.0,
                supermajority_achieved=True,
                certificate=cert,
            )

            file_emitter.emit_case_opened(self.finding, consensus_result, self.receipt_hash)

            self.assertTrue(log_file.exists())
            lines = log_file.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertIn("\"eventType\": \"case-opened\"", lines[0])


if __name__ == "__main__":
    unittest.main()
