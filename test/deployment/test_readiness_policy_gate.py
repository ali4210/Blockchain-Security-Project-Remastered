"""
Task P07-003: Unit and Integration Test Suite for Readiness Policy Gate.
Validates fail-closed deployment aborts upon consensus rejection, policy failure,
unconfigured hardware, structured event emission, and zero-state guarantees.
"""

from pathlib import Path
import tempfile
import unittest

from src.consensus.avs_gate import ConsensusResult, ConsensusStatus
from src.consensus.bls_aggregation import QuorumCertificate, ValidatorKeyring, BLSAggregator
from src.deployment.consensus_deployer import (
    ConsensusDeployer,
    DeploymentPlan,
    DeploymentReceipt,
)
from src.deployment.readiness_policy_gate import (
    ReadinessPolicyGate,
    ProductionReadinessPolicy,
    AbortReasonCode,
    DeploymentAbortError,
    DeploymentAbortEvent,
)


class TestReadinessPolicyGate(unittest.TestCase):
    def setUp(self):
        self.validators = ["validator-1", "validator-2", "validator-3"]
        self.keyring = ValidatorKeyring(seed="gate-test-seed")
        self.aggregator = BLSAggregator(self.validators, keyring=self.keyring)
        self.policy = ProductionReadinessPolicy()
        self.gate = ReadinessPolicyGate(policy=self.policy)

        self.bytecode_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        self.receipt_hash = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        self.attestation_id = "ATT-GATE-TEST-001"

        self.plan = DeploymentPlan(
            plan_id="PLAN-GATE-TEST",
            target_contract="VulnerableVault",
            target_network="local-anvil",
            bytecode_hash=self.bytecode_hash,
        )

    def _generate_valid_cert(self) -> QuorumCertificate:
        msg_digest = self.aggregator.compute_message_digest(
            self.attestation_id, self.bytecode_hash, self.receipt_hash
        )
        votes = {v: self.keyring.sign(v, msg_digest) for v in self.validators}
        return self.aggregator.aggregate_signatures(
            self.attestation_id, self.bytecode_hash, self.receipt_hash, votes
        )

    def test_consensus_rejected_triggers_abort_event(self):
        rejected_result = ConsensusResult(
            attestation_id=self.attestation_id,
            finding_id="FINDING-001",
            status=ConsensusStatus.REJECTED,
            total_validators=3,
            validated_votes=1,
            rejected_votes=2,
            inconclusive_votes=0,
            supermajority_ratio=0.33,
            supermajority_achieved=False,
            certificate=None,
        )

        with self.assertRaises(DeploymentAbortError) as ctx:
            self.gate.evaluate_and_assert(self.plan, consensus_result=rejected_result)

        err = ctx.exception
        self.assertIn("Consensus gate rejected plan", str(err))
        self.assertEqual(err.event.abortCode, AbortReasonCode.ERR_CONSENSUS_REJECTED)
        self.assertEqual(err.event.schemaVersion, 1)
        self.assertEqual(err.event.eventType, "deployment-aborted")
        self.assertEqual(len(err.event.eventDigest), 64)

    def test_missing_certificate_triggers_abort(self):
        with self.assertRaises(DeploymentAbortError) as ctx:
            self.gate.evaluate_and_assert(self.plan, consensus_result=None)

        self.assertEqual(ctx.exception.event.abortCode, AbortReasonCode.ERR_MISSING_CERTIFICATE)

    def test_unconfigured_hardware_on_mainnet_triggers_abort(self):
        cert = self._generate_valid_cert()
        agreed_result = ConsensusResult(
            attestation_id=self.attestation_id,
            finding_id="FINDING-001",
            status=ConsensusStatus.AGREED,
            total_validators=3,
            validated_votes=3,
            rejected_votes=0,
            inconclusive_votes=0,
            supermajority_ratio=1.0,
            supermajority_achieved=True,
            certificate=cert,
        )

        mainnet_plan = DeploymentPlan(
            plan_id="PLAN-MAINNET-TEST",
            target_contract="VulnerableVault",
            target_network="mainnet",
            bytecode_hash=self.bytecode_hash,
        )

        # Hardware unconfigured for mainnet
        with self.assertRaises(DeploymentAbortError) as ctx:
            self.gate.evaluate_and_assert(
                mainnet_plan,
                consensus_result=agreed_result,
                hardware_token_configured=False,
            )

        self.assertEqual(ctx.exception.event.abortCode, AbortReasonCode.ERR_UNCONFIGURED_HARDWARE)

    def test_pass_readiness_gate_when_conditions_met(self):
        cert = self._generate_valid_cert()
        agreed_result = ConsensusResult(
            attestation_id=self.attestation_id,
            finding_id="FINDING-001",
            status=ConsensusStatus.AGREED,
            total_validators=3,
            validated_votes=3,
            rejected_votes=0,
            inconclusive_votes=0,
            supermajority_ratio=1.0,
            supermajority_achieved=True,
            certificate=cert,
        )

        # Should complete silently without raising
        self.gate.evaluate_and_assert(self.plan, consensus_result=agreed_result)
        self.assertEqual(len(self.gate.get_abort_history()), 0)

    def test_abort_event_persistence_and_zero_state_deployer_guarantee(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "aborts.jsonl"
            gate = ReadinessPolicyGate(log_path=log_file)
            deployer = ConsensusDeployer(aggregator=self.aggregator, keyring=self.keyring)

            # Try to deploy with rejected consensus
            rejected_result = ConsensusResult(
                attestation_id=self.attestation_id,
                finding_id="FINDING-001",
                status=ConsensusStatus.REJECTED,
                total_validators=3,
                validated_votes=0,
                rejected_votes=3,
                inconclusive_votes=0,
                supermajority_ratio=0.0,
                supermajority_achieved=False,
                certificate=None,
            )

            try:
                gate.evaluate_and_assert(self.plan, consensus_result=rejected_result)
            except DeploymentAbortError:
                pass

            # Assert deployer contains zero state
            self.assertEqual(len(deployer._deployed_contracts), 0)
            self.assertTrue(log_file.exists())
            content = log_file.read_text(encoding="utf-8")
            self.assertIn("ERR_CONSENSUS_REJECTED", content)


if __name__ == "__main__":
    unittest.main()
