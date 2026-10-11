"""
Task P12-003: Unit tests for HSM Emulator.
Validates slot authentication, PIN lockouts, key pair generation,
non-exportability, ECDSA secp256k1 signing, and signature verification.
"""

import hashlib
import os
import unittest

from src.wallet.hsm_emulator import (
    HsmAuthenticationError,
    HsmEmulator,
    HsmKeyNotFoundError,
    HsmPinLockedError,
    KeyHandle,
)


class TestHsmEmulator(unittest.TestCase):
    def setUp(self):
        self.hsm = HsmEmulator(slot_id=1, user_pin="5678", so_pin="99887766")

    def test_unauthenticated_operations_fail(self):
        with self.assertRaises(HsmAuthenticationError):
            self.hsm.generate_key_pair("gnosis-safe-signer-0")

        with self.assertRaises(HsmAuthenticationError):
            self.hsm.sign_digest("nonexistent-key", os.urandom(32))

    def test_successful_login_and_key_generation(self):
        self.assertTrue(self.hsm.login("5678"))
        handle = self.hsm.generate_key_pair("gnosis-safe-signer-0")

        self.assertIsInstance(handle, KeyHandle)
        self.assertEqual(handle.slot_id, 1)
        self.assertEqual(handle.label, "gnosis-safe-signer-0")
        self.assertTrue(handle.public_key_hex.startswith("04"))
        self.assertTrue(handle.ethereum_address.startswith("0x"))

        # Invariant: KeyHandle contains NO private key attribute
        self.assertFalse(hasattr(handle, "private_key"))
        self.assertFalse(hasattr(handle, "private_key_int"))
        self.assertFalse(hasattr(handle, "secret"))

    def test_sign_and_verify_digest(self):
        self.hsm.login("5678")
        handle = self.hsm.generate_key_pair("safe-owner-1")

        # 32-byte transaction hash (Gnosis Safe hash)
        tx_hash = hashlib.sha256(b"gnosis_safe_tx_payload").digest()
        sig = self.hsm.sign_digest(handle.key_id, tx_hash)

        self.assertEqual(sig.key_id, handle.key_id)
        self.assertIn(sig.v, [27, 28])
        self.assertEqual(len(sig.signature_hex), 130)  # 64 + 64 + 2

        # Verify signature against public key
        valid = self.hsm.verify_signature(handle.public_key_hex, tx_hash, sig)
        self.assertTrue(valid)

        # Corrupted digest fails verification
        tampered_hash = hashlib.sha256(b"tampered_payload").digest()
        self.assertFalse(self.hsm.verify_signature(handle.public_key_hex, tampered_hash, sig))

    def test_pin_lockout_after_three_attempts_and_so_reset(self):
        # 2 failed attempts
        with self.assertRaises(HsmAuthenticationError):
            self.hsm.login("wrong-1")
        with self.assertRaises(HsmAuthenticationError):
            self.hsm.login("wrong-2")

        # 3rd attempt triggers permanent lock
        with self.assertRaises(HsmPinLockedError):
            self.hsm.login("wrong-3")

        # Further attempts immediately raise HsmPinLockedError even with right PIN
        with self.assertRaises(HsmPinLockedError):
            self.hsm.login("5678")

        # SO unlocks slot with new PIN
        self.assertTrue(self.hsm.reset_lock(so_pin="99887766", new_user_pin="1111"))
        self.assertTrue(self.hsm.login("1111"))

    def test_invalid_digest_length_rejected(self):
        self.hsm.login("5678")
        handle = self.hsm.generate_key_pair("test-key")
        with self.assertRaises(ValueError) as ctx:
            self.hsm.sign_digest(handle.key_id, b"short")
        self.assertIn("exactly 32 bytes", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
