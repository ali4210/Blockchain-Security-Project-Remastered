"""
Task P12-006: Unit tests for Joint-Signature Relayer Interface.
Validates 2-party distributed signing, canonical 65-byte packing,
signature verification against cluster public key, and proof of non-retention.
"""

import hashlib
import os
import unittest

from src.wallet.mpc_joint_signer import MpcJointSigner
from src.wallet.mpc_relayer_cluster import MpcRelayerCluster


class TestMpcJointSigner(unittest.TestCase):
    def setUp(self):
        self.cluster = MpcRelayerCluster("test-relayer-cluster")
        self.cluster.provision_relayer_key()
        self.signer = MpcJointSigner(self.cluster)

    def test_distributed_joint_signing_and_verification(self):
        tx_digest = hashlib.sha256(b"relayer_forwarded_transaction_payload").digest()
        packed_sig = self.signer.sign_transaction_digest(tx_digest)

        # Must be 65 bytes: 32 bytes r, 32 bytes s, 1 byte v
        self.assertEqual(len(packed_sig), 65)
        v = packed_sig[64]
        self.assertIn(v, [27, 28])

        # Verify against MPC cluster joint public key
        valid = self.signer.verify_joint_signature(tx_digest, packed_sig)
        self.assertTrue(valid)

        # Altered digest fails verification
        tampered_digest = hashlib.sha256(b"tampered_payload").digest()
        self.assertFalse(self.signer.verify_joint_signature(tampered_digest, packed_sig))

    def test_non_retention_audit_proof(self):
        audit = self.signer.audit_non_retention_proof()
        self.assertFalse(audit["orchestrator_has_master_key"])
        self.assertFalse(audit["replica_1_knows_share_2"])
        self.assertFalse(audit["replica_2_knows_share_1"])
        self.assertTrue(audit["shares_distinct"])
        self.assertTrue(audit["additive_relation_holds"])
        self.assertTrue(audit["cluster_address"].startswith("0x"))

    def test_invalid_digest_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.signer.sign_transaction_digest(b"short_bytes")
        self.assertIn("exactly 32 bytes", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
