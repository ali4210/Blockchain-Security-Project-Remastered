"""
Task P10A-001: Streaming Evidence Hasher.
Computes dual streaming cryptographic digests (SHA-256 and SHA-512) for large
evidence artifacts using fixed memory buffers to preserve forensic integrity.
"""

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import BinaryIO, Dict, Union

CHUNK_SIZE = 64 * 1024  # 64 KB fixed buffer


@dataclass(frozen=True)
class ArtifactDigest:
    file_path: str
    byte_size: int
    sha256: str
    sha512: str

    def to_dict(self) -> Dict[str, Union[str, int]]:
        return {
            "file_path": self.file_path,
            "byte_size": self.byte_size,
            "sha256": self.sha256,
            "sha512": self.sha512,
        }


class StreamingEvidenceHasher:
    """Constant-memory streaming hasher for digital forensic evidence artifacts."""

    def __init__(self, chunk_size: int = CHUNK_SIZE):
        self.chunk_size = chunk_size

    def hash_stream(self, stream: BinaryIO, path_label: str = "stream") -> ArtifactDigest:
        """Hashes an open binary stream and returns dual SHA-256 and SHA-512 digests."""
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

    def hash_file(self, target_path: Union[str, Path]) -> ArtifactDigest:
        """Safely opens and hashes a file on disk using streaming buffers."""
        path = Path(target_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Forensic target file not found: {path}")

        with path.open("rb") as f:
            return self.hash_stream(f, path_label=str(path))
