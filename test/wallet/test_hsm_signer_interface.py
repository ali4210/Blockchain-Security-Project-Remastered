"""
Task P12-004: Unit tests for HSM Signer Interface.
Validates zero-raw-key-export invariants, Safe transaction signing,
packed signature format (65 bytes), multi-signer ascending sorting, and verification.
"""

import hashlib
import os
import unittest

from src.wallet.hsm_emulator import HsmEmulator
from src.wallet.hsm_signer_interface import (
    HsmSignerInterface,
    SafeTransactionData,
    aggregate_safe_signatures,
)


class TestHsmSignerInterface(unittest.TestCase):
    def setUp(self):
        self.emulator = HsmEmulator(slot_id=0, user_pin="4321", so_pin="87654321")
        self.emulator.login("4321")
        self.handle_a = self.emulator.generate_key_pair("owner-a")
        self.handle_b = self.emulator.generate_key_pair("owner-b")

        self.signer_a = HsmSignerInterface(self.emulator, self.handle_a)
        self.signer_b = HsmSignerInterface(self.emulator, self.handle_b)

    def test_strict_zero_export_invariants(self):
        # Attribute reflection blocks
        blocked_names = [
            "export_private_key",
            "get_private_key",
            "dump_private_key",
            "private_key",
            "raw_private_key",
            "secret_bytes",
        ]
        for name in blocked_names:
            with self.assertRaises(AttributeError):
                getattr(self.signer_a, name)

        # Confirm neither signer nor handle stores private key fields
        self.assertNotIn("private_key", dir(self.signer_a))
        self.assertNotIn("private_key_int", dir(self.signer_a))
        self.assertNotIn("secret", dir(self.signer_a))
        self.assertNotIn("private_key", self.signer_a.__dict__)

    def test_sign_hash_packed_65_bytes(self):
        digest = hashlib.sha256(b"dummy_gnosis_tx_hash").digest()
        packed_sig = self.signer_a.sign_hash(digest)

        self.assertEqual(len(packed_sig), 65)
        # v must be 27 or 28
        v = packed_sig[64]
        self.assertIn(v, [27, 28])

        # Verify through interface
        self.assertTrue(self.signer_a.verify_signature(digest, packed_sig))

        # Tampered digest fails
        tampered = hashlib.sha256(b"tampered").digest()
        self.assertFalse(self.signer_a.verify_signature(tampered, packed_sig))

    def test_sign_safe_transaction_flow(self):
        tx = SafeTransactionData(
            to="0x1111111111111111111111111111111111111111",
            value=1000000000000000000,
            data=b"",
            operation=0,
            safe_tx_gas=50000,
            base_gas=0,
            gas_price=0,
            gas_token="0x0000000000000000000000000000000000000000",
            refund_receiver="0x0000000000000000000000000000000000000000",
            nonce=1,
        )
        safe_address = "0xSafeVaultContract1234567890abcdef123456"
        tx_hash = tx.compute_tx_hash(safe_address, chain_id=1)

        sig = self.signer_a.sign_safe_transaction(tx, safe_address, chain_id=1)
        self.assertEqual(len(sig), 65)
        self.assertTrue(self.signer_a.verify_signature(tx_hash, sig))

    def test_aggregate_safe_signatures_orders_ascending(self):
        digest = hashlib.sha256(b"test_quorum_signing").digest()
        sig_a = self.signer_a.sign_hash(digest)
        sig_b = self.signer_b.sign_hash(digest)

        addr_a = self.signer_a.ethereum_address
        addr_b = self.signer_b.ethereum_address

        # Intentionally order in reverse
        if addr_a.lower() < addr_b.lower():
            input_pairs = [(addr_b, sig_b), (addr_a, sig_a)]
            expected_combined = sig_a + sig_b
        else:
            input_pairs = [(addr_a, sig_a), (addr_b, sig_b)]
            expected_combined = sig_b + sig_a

        combined = aggregate_safe_signatures(input_pairs)
        self.assertEqual(len(combined), 130)  # 65 * 2
        self.assertEqual(combined, expected_combined)

    def test_aggregate_rejects_duplicate_signers(self):
        digest = hashlib.sha256(b"dup_test").digest()
        sig_a = self.signer_a.sign_hash(digest)
        addr_a = self.signer_a.ethereum_address

        with self.assertRaises(ValueError) as ctx:
            aggregate_safe_signatures([(addr_a, sig_a), (addr_a, sig_a)])
        self.assertIn("Duplicate signer address", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
