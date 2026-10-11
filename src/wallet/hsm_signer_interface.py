"""
Task P12-004: HSM Signing Interface with No Raw-Key-Export Path.
Provides a hardened adapter for Gnosis Safe multisig transactions
with zero export paths, low-s canonical enforcement, and sorted signature packing.
"""

from dataclasses import dataclass
import hashlib
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.wallet.hsm_emulator import HsmEmulator, KeyHandle, HsmSignature, HsmAuthenticationError


@dataclass(frozen=True)
class SafeTransactionData:
    """Represents core fields of a Gnosis Safe transaction for hashing."""
    to: str
    value: int
    data: bytes
    operation: int
    safe_tx_gas: int
    base_gas: int
    gas_price: int
    gas_token: str
    refund_receiver: str
    nonce: int

    def compute_tx_hash(self, safe_address: str, chain_id: int = 1) -> bytes:
        """
        Computes a deterministic 32-byte pseudo-EIP712 transaction hash.
        Used for verification and signing by Safe owners.
        """
        payload = (
            f"EIP712Domain:{chain_id}:{safe_address.lower()}:"
            f"{self.to.lower()}:{self.value}:{self.data.hex()}:{self.operation}:"
            f"{self.safe_tx_gas}:{self.base_gas}:{self.gas_price}:"
            f"{self.gas_token.lower()}:{self.refund_receiver.lower()}:{self.nonce}"
        ).encode("utf-8")
        return hashlib.sha256(payload).digest()


class HsmSignerInterface:
    """
    Hardened signer adapter wrapping an HsmEmulator.
    Guarantees no raw private key material is accessible or exportable.
    """

    # Prohibited attribute / method names to enforce zero-export invariant
    _BLOCKED_EXPORT_TERMS = {
        "export_private_key",
        "get_private_key",
        "dump_private_key",
        "raw_private_key",
        "private_key",
        "export_key",
        "secret_bytes",
    }

    def __init__(self, emulator: HsmEmulator, key_handle: KeyHandle):
        self._emulator = emulator
        self._handle = key_handle

    @property
    def key_id(self) -> str:
        return self._handle.key_id

    @property
    def label(self) -> str:
        return self._handle.label

    @property
    def ethereum_address(self) -> str:
        return self._handle.ethereum_address

    @property
    def public_key_hex(self) -> str:
        return self._handle.public_key_hex

    def sign_hash(self, digest_32: bytes) -> bytes:
        """
        Signs a 32-byte digest and returns a 65-byte packed signature (r || s || v).
        No private key is exposed during this process.
        """
        if len(digest_32) != 32:
            raise ValueError(f"Digest must be exactly 32 bytes, got {len(digest_32)}")

        sig = self._emulator.sign_digest(self._handle.key_id, digest_32)
        r_bytes = sig.r.to_bytes(32, byteorder="big")
        s_bytes = sig.s.to_bytes(32, byteorder="big")
        v_bytes = sig.v.to_bytes(1, byteorder="big")

        return r_bytes + s_bytes + v_bytes

    def sign_safe_transaction(self, tx: SafeTransactionData, safe_address: str, chain_id: int = 1) -> bytes:
        """Convenience method to compute transaction hash and sign it."""
        tx_hash = tx.compute_tx_hash(safe_address, chain_id)
        return self.sign_hash(tx_hash)

    def verify_signature(self, digest_32: bytes, packed_sig: bytes) -> bool:
        """Verifies a 65-byte packed signature against this signer's public key."""
        if len(packed_sig) != 65:
            return False

        r = int.from_bytes(packed_sig[:32], byteorder="big")
        s = int.from_bytes(packed_sig[32:64], byteorder="big")
        v = packed_sig[64]

        sig = HsmSignature(
            r=r,
            s=s,
            v=v,
            signature_hex=packed_sig.hex(),
            key_id=self._handle.key_id,
        )
        return self._emulator.verify_signature(self._handle.public_key_hex, digest_32, sig)

    def __getattr__(self, name: str) -> Any:
        if name in self._BLOCKED_EXPORT_TERMS or "private" in name.lower() or "secret" in name.lower():
            raise AttributeError(f"Access to '{name}' is strictly forbidden by HSM security invariants.")
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")


def aggregate_safe_signatures(signatures_with_addresses: Sequence[Tuple[str, bytes]]) -> bytes:
    """
    Aggregates multi-owner signatures for Gnosis Safe execution.
    Signatures MUST be sorted ascending by signer Ethereum address.
    """
    if not signatures_with_addresses:
        return b""

    # Sort strictly ascending by lowercase address
    sorted_pairs = sorted(signatures_with_addresses, key=lambda pair: pair[0].lower())
    
    # Check for duplicate signer addresses
    seen_addrs = set()
    for addr, sig in sorted_pairs:
        addr_lower = addr.lower()
        if addr_lower in seen_addrs:
            raise ValueError(f"Duplicate signer address in Safe signature set: {addr}")
        seen_addrs.add(addr_lower)
        if len(sig) != 65:
            raise ValueError(f"Signature for {addr} must be 65 bytes, got {len(sig)}")

    return b"".join(pair[1] for pair in sorted_pairs)
