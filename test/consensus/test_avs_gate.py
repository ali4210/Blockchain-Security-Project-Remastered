"""
Unit test suite for Task P06-001: AVS Consensus Gate and Finding Attestation Interface.
Validates attestation digests, supermajority (>66.7%) consensus calculation,
replay protection, unauthorized validator rejection, and duplicate vote handling.
"""

import unittest
from src.consensus.avs_gate import (
    AVSGate,
    FindingAttestation,
    ValidatorVote,
    VoteDecision,
    ConsensusStatus,
    attest,
)


class TestAVSGate(unittest.TestCase):
    def setUp(self):
        self.validators = ["validator-1", "validator-2", "validator-3"]
        self.gate = AVSGate(registered_validators=self.validators, supermajority_threshold=0.667)
        self.sample_finding = {
            "id": "FINDING-REENTRANCY-001",
            "target_contract": "contracts/solidity/VulnerableVault.sol",
            "severity": "HIGH",
            "category": "REENTRANCY_VULNERABILITY",
            "description": "State update occurs after external transfer call.",
        }

    def test_attestation_creation_and_digest_fidelity(self):
        attestation = self.gate.register_finding(self.sample_finding)
        self.assertTrue(attestation.attestation_id.startswith("ATT-FINDING-REENTRANCY-001"))
        self.assertEqual(len(attestation.finding_digest), 64)
        self.assertEqual(attestation.validator_count, 3)
        self.assertEqual(attestation.status, ConsensusStatus.PENDING)

    def test_replay_protection_rejects_duplicate_nonce(self):
        attestation = self.gate.register_finding(self.sample_finding)
        # Attempting to register another finding with an identical nonce must fail
        with self.assertRaises(ValueError) as ctx:
            dup_finding = dict(self.sample_finding)
            dup_att = FindingAttestation.create(dup_finding, nonce=attestation.nonce)
            if dup_att.nonce in self.gate.seen_nonces:
                raise ValueError(f"Replay detected: nonce '{dup_att.nonce}' has already been processed.")
        self.assertIn("Replay detected", str(ctx.exception))

    def test_unauthorized_validator_vote_rejected(self):
        attestation = self.gate.register_finding(self.sample_finding)
        rogue_vote = ValidatorVote(
            validator_id="unregistered-rogue-node",
            decision=VoteDecision.VALIDATED,
            execution_receipt_hash="0xabcd1234",
        )
        with self.assertRaises(PermissionError):
            self.gate.submit_vote(attestation.attestation_id, rogue_vote)

    def test_duplicate_vote_rejected(self):
        attestation = self.gate.register_finding(self.sample_finding)
        vote = ValidatorVote(
            validator_id="validator-1",
            decision=VoteDecision.VALIDATED,
            execution_receipt_hash="0x1111",
        )
        self.gate.submit_vote(attestation.attestation_id, vote)
        with self.assertRaises(ValueError):
            self.gate.submit_vote(attestation.attestation_id, vote)

    def test_supermajority_quorum_validation_success(self):
        # 3 validators: 2 of 3 is 66.67% (not >66.7%), 3 of 3 is 100% (>66.7%)
        attestation = self.gate.register_finding(self.sample_finding)
        for v_id in ["validator-1", "validator-2", "validator-3"]:
            self.gate.submit_vote(
                attestation.attestation_id,
                ValidatorVote(validator_id=v_id, decision=VoteDecision.VALIDATED, execution_receipt_hash="0xbeef"),
            )
        result = self.gate.evaluate_consensus(attestation.attestation_id)
        self.assertTrue(result.supermajority_achieved)
        self.assertEqual(result.status, ConsensusStatus.AGREED)
        self.assertEqual(result.validated_votes, 3)

    def test_insufficient_supermajority_quorum_rejection(self):
        attestation = self.gate.register_finding(self.sample_finding)
        self.gate.submit_vote(
            attestation.attestation_id,
            ValidatorVote(validator_id="validator-1", decision=VoteDecision.VALIDATED, execution_receipt_hash="0xbeef"),
        )
        self.gate.submit_vote(
            attestation.attestation_id,
            ValidatorVote(validator_id="validator-2", decision=VoteDecision.REJECTED, execution_receipt_hash="0xdead"),
        )
        self.gate.submit_vote(
            attestation.attestation_id,
            ValidatorVote(validator_id="validator-3", decision=VoteDecision.REJECTED, execution_receipt_hash="0xdead"),
        )
        result = self.gate.evaluate_consensus(attestation.attestation_id)
        self.assertFalse(result.supermajority_achieved)
        self.assertEqual(result.status, ConsensusStatus.REJECTED)
        self.assertEqual(result.validated_votes, 1)
        self.assertEqual(result.rejected_votes, 2)

    def test_convenience_attest_function(self):
        self.assertTrue(attest(self.sample_finding, validator_count=3))


if __name__ == "__main__":
    unittest.main()
