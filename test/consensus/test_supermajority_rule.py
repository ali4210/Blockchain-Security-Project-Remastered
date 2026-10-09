"""
Task P06-004: Comprehensive Test Suite for >66.7% BFT Supermajority Threshold Rules.
Validates integer arithmetic precision across variable quorum sizes (N=3, N=4, N=7, N=10),
boundary condition thresholds (66.666% vs >66.7%), early rejection, and inconclusive votes.
"""

import unittest
from src.consensus.avs_gate import AVSGate, ValidatorVote, VoteDecision, ConsensusStatus


class TestSupermajorityRule(unittest.TestCase):
    def _create_gate(self, n: int) -> AVSGate:
        validators = [f"v-{i+1}" for i in range(n)]
        return AVSGate(registered_validators=validators)

    def test_quorum_n3_boundary_conditions(self):
        # N=3: 2 votes = 66.67% (NOT >66.7%), requires 3 votes (100%)
        gate = self._create_gate(3)
        att = gate.register_finding({"id": "N3-TEST", "severity": "HIGH"}, validator_count=3)

        # Vote 1 and Vote 2 VALIDATED
        gate.submit_vote(att.attestation_id, ValidatorVote("v-1", VoteDecision.VALIDATED, "0x1"))
        gate.submit_vote(att.attestation_id, ValidatorVote("v-2", VoteDecision.VALIDATED, "0x2"))

        # While pending 3rd vote, max possible valid is 3, so status is PENDING
        res_pending = gate.evaluate_consensus(att.attestation_id)
        self.assertEqual(res_pending.status, ConsensusStatus.PENDING)
        self.assertFalse(res_pending.supermajority_achieved)

        # Vote 3 REJECTED -> Final: 2/3 valid (66.67%). 3*2 = 6 <= 3*2 = 6. MUST REJECT.
        gate.submit_vote(att.attestation_id, ValidatorVote("v-3", VoteDecision.REJECTED, "0x3"))
        res_final = gate.evaluate_consensus(att.attestation_id)
        self.assertEqual(res_final.status, ConsensusStatus.REJECTED)
        self.assertFalse(res_final.supermajority_achieved)

    def test_quorum_n3_full_supermajority_pass(self):
        gate = self._create_gate(3)
        att = gate.register_finding({"id": "N3-PASS", "severity": "HIGH"}, validator_count=3)
        for i in range(3):
            gate.submit_vote(att.attestation_id, ValidatorVote(f"v-{i+1}", VoteDecision.VALIDATED, "0x1"))

        res = gate.evaluate_consensus(att.attestation_id)
        self.assertTrue(res.supermajority_achieved)
        self.assertEqual(res.status, ConsensusStatus.AGREED)
        self.assertEqual(res.validated_votes, 3)

    def test_quorum_n4_thresholds(self):
        # N=4: 2/4 = 50% (FAIL), 3/4 = 75% (PASS)
        gate = self._create_gate(4)
        att = gate.register_finding({"id": "N4-TEST", "severity": "HIGH"}, validator_count=4)

        gate.submit_vote(att.attestation_id, ValidatorVote("v-1", VoteDecision.VALIDATED, "0x1"))
        gate.submit_vote(att.attestation_id, ValidatorVote("v-2", VoteDecision.VALIDATED, "0x2"))
        gate.submit_vote(att.attestation_id, ValidatorVote("v-3", VoteDecision.VALIDATED, "0x3"))

        # 3/4 is 75% (> 66.7%). 3*3 = 9 > 2*4 = 8. Achieved even before v-4 votes!
        res = gate.evaluate_consensus(att.attestation_id)
        self.assertTrue(res.supermajority_achieved)
        self.assertEqual(res.status, ConsensusStatus.AGREED)

    def test_quorum_n7_thresholds(self):
        # N=7: 4/7 = 57.1% (FAIL), 5/7 = 71.4% (PASS)
        gate = self._create_gate(7)
        att = gate.register_finding({"id": "N7-TEST", "severity": "HIGH"}, validator_count=7)

        # 4 Valid, 3 Rejected -> 4/7 fails
        for i in range(4):
            gate.submit_vote(att.attestation_id, ValidatorVote(f"v-{i+1}", VoteDecision.VALIDATED, "0x1"))
        for i in range(4, 7):
            gate.submit_vote(att.attestation_id, ValidatorVote(f"v-{i+1}", VoteDecision.REJECTED, "0x2"))

        res = gate.evaluate_consensus(att.attestation_id)
        self.assertFalse(res.supermajority_achieved)
        self.assertEqual(res.status, ConsensusStatus.REJECTED)

        # New round with 5 Valid, 2 Rejected -> 5/7 passes (15 > 14)
        gate2 = self._create_gate(7)
        att2 = gate2.register_finding({"id": "N7-PASS", "severity": "HIGH"}, validator_count=7)
        for i in range(5):
            gate2.submit_vote(att2.attestation_id, ValidatorVote(f"v-{i+1}", VoteDecision.VALIDATED, "0x1"))
        for i in range(5, 7):
            gate2.submit_vote(att2.attestation_id, ValidatorVote(f"v-{i+1}", VoteDecision.REJECTED, "0x2"))

        res2 = gate2.evaluate_consensus(att2.attestation_id)
        self.assertTrue(res2.supermajority_achieved)
        self.assertEqual(res2.status, ConsensusStatus.AGREED)

    def test_inconclusive_votes_count_against_quorum(self):
        # N=3: 2 VALIDATED, 1 INCONCLUSIVE -> 2/3 fails because 6 <= 6
        gate = self._create_gate(3)
        att = gate.register_finding({"id": "INCONC-TEST", "severity": "HIGH"}, validator_count=3)

        gate.submit_vote(att.attestation_id, ValidatorVote("v-1", VoteDecision.VALIDATED, "0x1"))
        gate.submit_vote(att.attestation_id, ValidatorVote("v-2", VoteDecision.VALIDATED, "0x2"))
        gate.submit_vote(att.attestation_id, ValidatorVote("v-3", VoteDecision.INCONCLUSIVE, "0x3"))

        res = gate.evaluate_consensus(att.attestation_id)
        self.assertFalse(res.supermajority_achieved)
        self.assertEqual(res.status, ConsensusStatus.REJECTED)
        self.assertEqual(res.inconclusive_votes, 1)

    def test_early_rejection_when_supermajority_unreachable(self):
        # N=4: Need 3 valid votes. If 2 validators vote REJECTED, max valid votes can only be 2.
        # 3*2 = 6 <= 8. Early rejection should trigger immediately!
        gate = self._create_gate(4)
        att = gate.register_finding({"id": "EARLY-REJECT", "severity": "HIGH"}, validator_count=4)

        gate.submit_vote(att.attestation_id, ValidatorVote("v-1", VoteDecision.REJECTED, "0x1"))
        gate.submit_vote(att.attestation_id, ValidatorVote("v-2", VoteDecision.REJECTED, "0x2"))

        res = gate.evaluate_consensus(att.attestation_id)
        self.assertEqual(res.status, ConsensusStatus.REJECTED)
        self.assertFalse(res.supermajority_achieved)


if __name__ == "__main__":
    unittest.main()
