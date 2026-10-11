"""
Task P12-002: Unit tests for Shamir Secret Sharing Engine.
Validates round-trip splitting and reconstruction, arbitrary threshold sets,
sub-threshold rejection, tampered share detection, and memory zeroing.
"""

import os
import unittest

from src.wallet.shamir_engine import (
    PRIME_256,
    ShamirSecretSharing,
    ShamirShare,
    zero_buffer,
)


class TestShamirEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ShamirSecretSharing()
        # 32-byte realistic private key / entropy seed
        self.secret = os.urandom(32)

    def test_round_trip_3_of_5_threshold(self):
        shares = self.engine.split_secret(self.secret, threshold=3, total_shares=5)
        self.assertEqual(len(shares), 5)

        # Any subset of 3 shares must reconstruct the identical secret
        subset_1 = [shares[0], shares[1], shares[2]]
        subset_2 = [shares[1], shares[3], shares[4]]
        subset_3 = [shares[0], shares[2], shares[4]]

        self.assertEqual(self.engine.reconstruct_secret(subset_1), self.secret)
        self.assertEqual(self.engine.reconstruct_secret(subset_2), self.secret)
        self.assertEqual(self.engine.reconstruct_secret(subset_3), self.secret)

    def test_round_trip_arbitrary_thresholds(self):
        for k, n in [(2, 3), (4, 7), (5, 9)]:
            shares = self.engine.split_secret(self.secret, threshold=k, total_shares=n)
            self.assertEqual(len(shares), n)
            chosen_subset = shares[:k]
            reconstructed = self.engine.reconstruct_secret(chosen_subset)
            self.assertEqual(reconstructed, self.secret)

    def test_sub_threshold_fails_closed(self):
        shares = self.engine.split_secret(self.secret, threshold=3, total_shares=5)
        # Supplying only 2 shares when 3 are required
        with self.assertRaises(ValueError) as ctx:
            self.engine.reconstruct_secret([shares[0], shares[1]])
        self.assertIn("Insufficient shares", str(ctx.exception))

    def test_tampered_share_checksum_rejected(self):
        shares = self.engine.split_secret(self.secret, threshold=3, total_shares=5)
        # Tamper with share value
        tampered_share = ShamirShare(
            index=shares[0].index,
            value=shares[0].value + 1,
            threshold=shares[0].threshold,
            total_shares=shares[0].total_shares,
            checksum=shares[0].checksum,
        )
        with self.assertRaises(ValueError) as ctx:
            self.engine.reconstruct_secret([tampered_share, shares[1], shares[2]])
        self.assertIn("Tampered or invalid checksum", str(ctx.exception))

    def test_duplicate_shares_rejected(self):
        shares = self.engine.split_secret(self.secret, threshold=3, total_shares=5)
        # Pass share 0 twice to meet length 3
        with self.assertRaises(ValueError) as ctx:
            self.engine.reconstruct_secret([shares[0], shares[0], shares[1]])
        self.assertIn("Duplicate share index detected", str(ctx.exception))

    def test_mismatched_threshold_parameters_rejected(self):
        shares_3_5 = self.engine.split_secret(self.secret, threshold=3, total_shares=5)
        shares_2_3 = self.engine.split_secret(self.secret, threshold=2, total_shares=3)
        # Mix share from different polynomial
        with self.assertRaises(ValueError) as ctx:
            self.engine.reconstruct_secret([shares_3_5[0], shares_3_5[1], shares_2_3[0]])
        self.assertIn("Mismatched threshold parameter", str(ctx.exception))

    def test_zero_buffer_wipes_sensitive_memory(self):
        sensitive_data = bytearray(b"super_secret_master_private_key!")
        self.assertNotEqual(sensitive_data, bytearray(len(sensitive_data)))
        zero_buffer(sensitive_data)
        self.assertEqual(sensitive_data, bytearray(len(sensitive_data)))
        self.assertEqual(sum(sensitive_data), 0)


if __name__ == "__main__":
    unittest.main()
