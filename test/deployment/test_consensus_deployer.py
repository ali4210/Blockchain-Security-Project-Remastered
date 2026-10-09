"""
Task P07-001: Comprehensive Unit Tests for Consensus-Gated Deployer.
Validates cryptographic verification of QuorumCertificates, bytecode binding,
hard rejection of uncertified plans, and deterministic deployment receipt generation.
"""

import unittest
from src.consensus.bls_aggregation import BLSAggregator, ValidatorKeyring, QuorumCertificate
from src.deployment.consensus_deployer import (
    ConsensusDeployer,
    DeploymentPlan,
    DeploymentReceipt,
    DeploymentStatus,
)


class TestConsensusDeployer(unittest.TestCase):
    def setUp(self):
        self.validators = ["validator-1", "validator-2", "validator-3"]
        self.keyring = ValidatorKeyring(seed="deploy-test-seed")
        self.aggregator = BLSAggregator(self.validators, keyring=self.keyring)
        self.deployer = ConsensusDeployer(aggregator=self.aggregator, keyring=self.keyring)

        self.bytecode_hash = "a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef"
        self.receipt_hash = "beefdead1234567890abcdef1234567890abcdef1234567890abcdef12345678"
        self.attestation_id = "ATT-DEPLOY-PLAN-001"

        self.plan = DeploymentPlan(
            plan_id="PLAN-VAULT-V2",
            target_contract="VulnerableVault",
            target_network="local-anvil",
            bytecode_hash=self.bytecode_hash,
            constructor_args=["0x1000"],
        )

    def _generate_certificate(self, finding_digest: str, receipt_hash: str) -> QuorumCertificate:
        msg_digest = self.aggregator.compute_message_digest(
            self.attestation_id, finding_digest, receipt_hash
        )
        votes = {v: self.keyring.sign(v, msg_digest) for v in self.validators}
        return self.aggregator.aggregate_signatures(
            self.attestation_id, finding_digest, receipt_hash, votes
        )

    def test_consensus_confirmed_deployment_success(self):
        cert = self._generate_certificate(self.bytecode_hash, self.receipt_hash)
        receipt = self.deployer.deploy(self.plan, cert, self.receipt_hash)

        self.assertIsInstance(receipt, DeploymentReceipt)
        self.assertEqual(receipt.status, DeploymentStatus.DEPLOYED)
        self.assertEqual(receipt.plan_id, "PLAN-VAULT-V2")
        self.assertTrue(receipt.contract_address.startswith("0x"))
        self.assertEqual(len(receipt.contract_address), 42)
        self.assertTrue(receipt.tx_hash.startswith("0x"))
        self.assertEqual(receipt.certificate_attestation_id, self.attestation_id)

    def test_missing_certificate_raises_permission_error(self):
        with self.assertRaises(PermissionError) as ctx:
            self.deployer.deploy(self.plan, None, self.receipt_hash)
        self.assertIn("lacks a required QuorumCertificate", str(ctx.exception))

    def test_tampered_certificate_raises_permission_error(self):
        cert = self._generate_certificate(self.bytecode_hash, self.receipt_hash)
        # Verify fails when receipt_hash does not match
        with self.assertRaises(PermissionError) as ctx:
            self.deployer.deploy(self.plan, cert, "altered-receipt-hash")
        self.assertIn("cryptographically invalid or tampered", str(ctx.exception))

    def test_bytecode_digest_mismatch_raises_value_error(self):
        # Certificate was generated for different bytecode
        different_bytecode = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        cert = self._generate_certificate(different_bytecode, self.receipt_hash)

        with self.assertRaises(ValueError) as ctx:
            self.deployer.deploy(self.plan, cert, self.receipt_hash)
        self.assertIn("Bytecode digest mismatch", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
