"""
Task P12-005: Unit tests for 2-Party MPC Relayer Cluster.
Validates additive 2-of-2 key partitioning, inter-replica handshake,
public key derivation, and proof of key material isolation.
"""

import unittest

from src.wallet.hsm_emulator import _point_mul, _G_X, _G_Y, _N
from src.wallet.mpc_relayer_cluster import (
    MpcAuthenticationError,
    MpcClusterPublicKey,
    MpcRelayerCluster,
    MpcReplica,
)


class TestMpcRelayerCluster(unittest.TestCase):
    def setUp(self):
        self.cluster = MpcRelayerCluster("test-relayer-cluster")

    def test_cluster_provisioning_and_isolation(self):
        # Master key to be split additively
        master_key = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0
        cluster_pub = self.cluster.provision_relayer_key(full_key=master_key)

        self.assertIsInstance(cluster_pub, MpcClusterPublicKey)
        self.assertTrue(cluster_pub.public_key_hex.startswith("04"))
        self.assertTrue(cluster_pub.ethereum_address.startswith("0x"))

        # Verify against ground-truth curve point Q = master_key * G
        expected_pt = _point_mul(master_key, (_G_X, _G_Y))
        self.assertIsNotNone(expected_pt)
        self.assertEqual(cluster_pub.pub_x, expected_pt[0])
        self.assertEqual(cluster_pub.pub_y, expected_pt[1])

        # Mathematical audit proof of key separation
        audit = self.cluster.verify_key_material_isolation()
        self.assertTrue(audit["isolated"])
        self.assertEqual(audit["cluster_address"], cluster_pub.ethereum_address)

        # Confirm additive relation: x_1 + x_2 == master_key (mod N)
        s1 = self.cluster.replica_1.export_private_share()
        s2 = self.cluster.replica_2.export_private_share()
        self.assertNotEqual(s1, master_key)
        self.assertNotEqual(s2, master_key)
        self.assertEqual((s1 + s2) % _N, master_key)

    def test_random_key_provisioning(self):
        pub = self.cluster.provision_relayer_key()
        self.assertIsInstance(pub, MpcClusterPublicKey)
        audit = self.cluster.verify_key_material_isolation()
        self.assertTrue(audit["isolated"])

    def test_inter_replica_authentication_rejection(self):
        # Peer authentication fails with forged HMAC token
        replica = MpcReplica("rogue-replica", b"secret-a")
        with self.assertRaises(MpcAuthenticationError):
            replica.authenticate_peer("peer-replica", "invalid_token_hash", "nonce_123")


if __name__ == "__main__":
    unittest.main()
