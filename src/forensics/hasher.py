"""
Task P10A-001 / P10C-003: Streaming Dual-Digest Hasher and RFC 6962 Merkle Tree.
Computes streaming SHA-256 and SHA-512 digests and provides RFC 6962 Merkle tree
root computation with standard domain separation prefixes.
"""

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Union

CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks


@dataclass(frozen=True)
class ArtifactDigest:
    file_path: str
    byte_size: int
    sha256: str
    sha512: str

    def to_dict(self) -> Dict[str, Any]:
        """Serializes digest record to structured dictionary."""
        return asdict(self)


class StreamingEvidenceHasher:
    """Computes streaming dual cryptographic digests and RFC 6962 Merkle roots."""

    def __init__(self, chunk_size: int = CHUNK_SIZE):
        self.chunk_size = chunk_size

    def hash_stream(self, stream: BinaryIO, path_label: str = "") -> ArtifactDigest:
        """Streams bytes through SHA-256 and SHA-512 simultaneously."""
        h256 = hashlib.sha256()
        h512 = hashlib.sha512()
        total_bytes = 0

        while True:
            chunk = stream.read(self.chunk_size)
            if not chunk:
                break
            h256.update(chunk)
            h512.update(chunk)
            total_bytes += len(chunk)

        return ArtifactDigest(
            file_path=path_label,
            byte_size=total_bytes,
            sha256=h256.hexdigest(),
            sha512=h512.hexdigest(),
        )

    def hash_file(self, path: Union[str, Path]) -> ArtifactDigest:
        """Streams an on-disk file through the dual-digest hasher."""
        file_path = Path(path)
        if not file_path.is_file():
            raise FileNotFoundError(f"Artifact not found: {file_path}")

        with file_path.open("rb") as f:
            return self.hash_stream(f, path_label=str(file_path))

    @staticmethod
    def _leaf_hash(data: bytes) -> bytes:
        """RFC 6962 leaf hash: SHA-256(0x00 || data)."""
        return hashlib.sha256(b"\x00" + data).digest()

    @staticmethod
    def _node_hash(left: bytes, right: bytes) -> bytes:
        """RFC 6962 interior node hash: SHA-256(0x01 || left || right)."""
        return hashlib.sha256(b"\x01" + left + right).digest()

    def build_rfc6962_merkle_tree(self, leaf_digests: List[str]) -> str:
        """
        Builds RFC 6962 Merkle tree from a list of artifact hex digests.
        Returns the hex-encoded root digest.
        """
        if not leaf_digests:
            return hashlib.sha256(b"").hexdigest()

        # Step 1: Hash leaves with 0x00 prefix
        current_layer = [
            self._leaf_hash(bytes.fromhex(d) if len(d) == 64 else d.encode("utf-8"))
            for d in leaf_digests
        ]

        # Step 2: Combine nodes pairwise with 0x01 prefix until single root
        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                if i + 1 < len(current_layer):
                    next_layer.append(self._node_hash(current_layer[i], current_layer[i + 1]))
                else:
                    # Odd leaf promoted directly
                    next_layer.append(current_layer[i])
            current_layer = next_layer

        return current_layer[0].hex()
