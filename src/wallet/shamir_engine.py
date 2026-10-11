"""
Task P12-002: Audited Shamir Secret Sharing Engine.
Provides threshold secret splitting and Lagrange interpolation reconstruction
over a 256-bit prime Galois field with share integrity checksums and in-memory wiping.
"""

from dataclasses import asdict, dataclass
import gc
import hashlib
import secrets
from typing import Any, Dict, List, Sequence, Tuple


# Safe 256-bit prime: 2^256 - 189
PRIME_256: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43


@dataclass(frozen=True)
class ShamirShare:
    index: int
    value: int
    threshold: int
    total_shares: int
    checksum: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "value_hex": hex(self.value),
            "threshold": self.threshold,
            "total_shares": self.total_shares,
            "checksum": self.checksum,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ShamirShare":
        val = int(data["value_hex"], 16) if isinstance(data["value_hex"], str) else int(data["value_hex"])
        return cls(
            index=int(data["index"]),
            value=val,
            threshold=int(data["threshold"]),
            total_shares=int(data["total_shares"]),
            checksum=str(data["checksum"]),
        )


def _compute_checksum(index: int, value: int, threshold: int, total_shares: int) -> str:
    payload = f"{index}:{hex(value)}:{threshold}:{total_shares}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def zero_buffer(buf: bytearray) -> None:
    """Overwrites a sensitive bytearray with zeros in-place."""
    for i in range(len(buf)):
        buf[i] = 0
    gc.collect()


class ShamirSecretSharing:
    """Mathematical engine for Shamir secret splitting and Lagrange reconstruction."""

    def __init__(self, prime: int = PRIME_256):
        self.prime = prime

    def split_secret(self, secret_bytes: bytes, threshold: int, total_shares: int) -> List[ShamirShare]:
        """
        Splits a secret (up to 32 bytes) into n shares with a k-of-n threshold.
        """
        if threshold < 2:
            raise ValueError(f"Threshold must be >= 2, got {threshold}")
        if threshold > total_shares:
            raise ValueError(f"Threshold ({threshold}) cannot exceed total shares ({total_shares})")
        if total_shares >= self.prime:
            raise ValueError(f"Total shares must be less than field prime")

        secret_int = int.from_bytes(secret_bytes, byteorder="big")
        if secret_int >= self.prime:
            raise ValueError("Secret exceeds finite field modulus size")

        # Coefficients for polynomial f(x) = S + a_1*x + ... + a_{k-1}*x^{k-1}
        # a_0 = secret_int
        coefficients = [secret_int] + [
            secrets.randbelow(self.prime - 1) + 1 for _ in range(threshold - 1)
        ]

        shares: List[ShamirShare] = []
        for x in range(1, total_shares + 1):
            # Evaluate polynomial at x
            y = 0
            for power, coeff in enumerate(coefficients):
                y = (y + coeff * pow(x, power, self.prime)) % self.prime

            chk = _compute_checksum(x, y, threshold, total_shares)
            shares.append(
                ShamirShare(
                    index=x,
                    value=y,
                    threshold=threshold,
                    total_shares=total_shares,
                    checksum=chk,
                )
            )

        return shares

    def reconstruct_secret(self, shares: Sequence[ShamirShare]) -> bytes:
        """
        Reconstructs the original secret bytes from at least k valid shares
        using Lagrange interpolation evaluated at x = 0.
        """
        if not shares:
            raise ValueError("No shares provided for reconstruction")

        threshold = shares[0].threshold
        if len(shares) < threshold:
            raise ValueError(
                f"Insufficient shares: got {len(shares)}, threshold requires {threshold}"
            )

        # Validate share consistency, checksums, and duplicates
        seen_indices = set()
        validated_shares: List[ShamirShare] = []

        for s in shares:
            if s.threshold != threshold:
                raise ValueError(f"Mismatched threshold parameter across shares ({s.threshold} vs {threshold})")
            if s.index in seen_indices:
                raise ValueError(f"Duplicate share index detected: {s.index}")
            seen_indices.add(s.index)

            expected_chk = _compute_checksum(s.index, s.value, s.threshold, s.total_shares)
            if s.checksum != expected_chk:
                raise ValueError(f"Tampered or invalid checksum on share index {s.index}")

            validated_shares.append(s)

        # Use exactly threshold number of shares for Lagrange interpolation
        k_shares = validated_shares[:threshold]
        x_coords = [s.index for s in k_shares]
        y_coords = [s.value for s in k_shares]

        secret_int = 0
        for j in range(threshold):
            # Lagrange basis polynomial l_j(0) = product_{m != j} (-x_m) / (x_j - x_m) mod p
            numerator = 1
            denominator = 1
            for m in range(threshold):
                if m == j:
                    continue
                numerator = (numerator * (-x_coords[m])) % self.prime
                denominator = (denominator * (x_coords[j] - x_coords[m])) % self.prime

            # Modular inverse via Fermat's Little Theorem
            inv_denominator = pow(denominator % self.prime, self.prime - 2, self.prime)
            basis = (numerator * inv_denominator) % self.prime
            secret_int = (secret_int + y_coords[j] * basis) % self.prime

        # Convert back to 32 bytes
        length = (secret_int.bit_length() + 7) // 8
        length = max(length, 32)
        return secret_int.to_bytes(length, byteorder="big")
