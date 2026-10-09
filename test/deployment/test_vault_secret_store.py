"""
Task P07-002: Unit Tests for Vault Secret Store Integration.
Validates zero-leakage properties, memory zeroization, lease revocation,
and integration with ConsensusDeployer.
"""

import unittest
from src.deployment.vault_secret_store import VaultSecretStore, VaultSecret
from src.deployment.consensus_deployer import (
    ConsensusDeployer,
    DeploymentPlan,
    DeploymentStatus,
)
from src.consensus.bls_aggregation import BLSAggregator, ValidatorKeyring, QuorumCertificate


class TestVaultSecretStore(unittest.TestCase):
    def setUp(self):
        self.store = VaultSecretStore(use_fallback=True)

    def tearDown(self):
        self.store.close()

    def test_secret_retrieval_and_redaction(self):
        secret = self.store.get_deployer_key("local-anvil", "admin")
        self.assertIsInstance(secret, VaultSecret)

        # Check __repr__ and __str__ do not leak key content
        self.assertNotIn("0xac0974", repr(secret))
        self.assertNotIn("0xac0974", str(secret))
        self.assertIn("REDACTED", repr(secret))

        # Check value retrieval
        raw_val = secret.get_raw_value()
        self.assertTrue(raw_val.startswith("0xac0974"))

    def test_memory_zeroization(self):
        secret = self.store.get_deployer_key("local-anvil", "admin")
        secret.zeroize()

        with self.assertRaises(ValueError) as ctx:
            secret.get_raw_value()
        self.assertIn("zeroized or invalidated", str(ctx.exception))

    def test_lease_revocation(self):
        secret = self.store.get_deployer_key("local-anvil", "operator")
        lease_id = secret.lease_id

        revoked = self.store.revoke_lease(lease_id)
        self.assertTrue(revoked)

        # Assert secret buffer zeroized upon lease revocation
        with self.assertRaises(ValueError):
            secret.get_raw_value()

    def test_deployer_vault_integration_lifecycle(self):
        keyring = ValidatorKeyring(seed="vault-deploy-test-seed")
        validators = ["validator-1", "validator-2", "validator-3"]
        aggregator = BLSAggregator(validators, keyring=keyring)
        deployer = ConsensusDeployer(aggregator=aggregator, keyring=keyring, secret_store=self.store)

        bytecode_hash = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
        receipt_hash = "ffaabbccddee11223344556677889900aabbccddee11223344556677889900aa"
        attestation_id = "ATT-VAULT-DEPLOY-001"

        plan = DeploymentPlan(
            plan_id="PLAN-VAULT-MANAGED",
            target_contract="SecureVault",
            target_network="local-anvil",
            bytecode_hash=bytecode_hash,
        )

        msg_digest = aggregator.compute_message_digest(attestation_id, bytecode_hash, receipt_hash)
        votes = {v: keyring.sign(v, msg_digest) for v in validators}
        cert = aggregator.aggregate_signatures(attestation_id, bytecode_hash, receipt_hash, votes)

        receipt = deployer.deploy(plan, cert, receipt_hash)
        self.assertEqual(receipt.status, DeploymentStatus.DEPLOYED)
        self.assertTrue(receipt.deployer_address.startswith("0x"))
        self.assertEqual(len(receipt.deployer_address), 42)


if __name__ == "__main__":
    unittest.main()
