"""
Task P10A-001: Unit tests for DFIR Streaming Hasher and Merkle Manifest.
Validates streaming hash calculations, RFC 6962 Merkle tree construction,
HMAC-SHA256 manifest signing, and tamper detection.
"""

import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from src.forensics.hasher import ArtifactDigest, StreamingEvidenceHasher
from src.forensics.merkle_manifest import (
    ForensicManifest,
    ForensicManifestManager,
    compute_merkle_root,
)


class TestIntegrityHasherAndManifest(unittest.TestCase):
    def setUp(self):
        self.hasher = StreamingEvidenceHasher(chunk_size=1024)
        self.manager = ForensicManifestManager()

    def test_streaming_hash_matches_hashlib(self):
        # 50 KB pseudo payload spanning multiple chunks
        payload = b"FORENSIC_ARTIFACT_BLOCK_TEST_SAMPLE\x00\xff" * 1500
        expected_256 = hashlib.sha256(payload).hexdigest()
        expected_512 = hashlib.sha512(payload).hexdigest()

        stream = io.BytesIO(payload)
        digest = self.hasher.hash_stream(stream, path_label="/evidence/mem.raw")

        self.assertEqual(digest.file_path, "/evidence/mem.raw")
        self.assertEqual(digest.byte_size, len(payload))
        self.assertEqual(digest.sha256, expected_256)
        self.assertEqual(digest.sha512, expected_512)

    def test_file_hashing_on_disk(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
            tf.write(b"DISK_ARTIFACT_DATA_TEST_123456789")
            temp_path = tf.name

        try:
            digest = self.hasher.hash_file(temp_path)
            self.assertEqual(digest.byte_size, 33)
            self.assertEqual(
                digest.sha256,
                hashlib.sha256(b"DISK_ARTIFACT_DATA_TEST_123456789").hexdigest(),
            )
        finally:
            Path(temp_path).unlink()

    def test_merkle_manifest_creation_and_verification(self):
        d1 = ArtifactDigest(
            file_path="/evidence/core.dmp",
            byte_size=1048576,
            sha256="aaa111" * 10 + "0000",
            sha512="bbb111" * 21 + "0",
        )
        d2 = ArtifactDigest(
            file_path="/evidence/network.pcap",
            byte_size=2097152,
            sha256="ccc222" * 10 + "0000",
            sha512="ddd222" * 21 + "0",
        )

        manifest = self.manager.create_manifest(
            manifest_id="mn-2026-10-001",
            digests=[d1, d2],
            operator_principal="soc-operator",
        )

        # Verification succeeds
        self.assertTrue(self.manager.verify_manifest(manifest))
        self.assertEqual(len(manifest.artifacts), 2)
        self.assertTrue(len(manifest.merkle_root) == 64)

    def test_detects_tampered_artifact_in_manifest(self):
        d1 = ArtifactDigest(
            file_path="/evidence/disk.img",
            byte_size=4096,
            sha256="1111" * 16,
            sha512="2222" * 32,
        )
        manifest = self.manager.create_manifest(
            manifest_id="mn-2026-10-002",
            digests=[d1],
            operator_principal="soc-operator",
        )

        # Tamper with artifact sha256
        tampered_manifest = ForensicManifest(
            manifest_id=manifest.manifest_id,
            created_at=manifest.created_at,
            artifacts=[{**manifest.artifacts[0], "sha256": "deadbeef" * 8}],
            merkle_root=manifest.merkle_root,
            operator_principal=manifest.operator_principal,
            signature=manifest.signature,
        )

        with self.assertRaises(PermissionError) as ctx:
            self.manager.verify_manifest(tampered_manifest)
        self.assertIn("invalid or forged HMAC signature", str(ctx.exception))

    def test_rejects_unauthorized_operator_principal(self):
        d1 = ArtifactDigest(
            file_path="/evidence/disk.img",
            byte_size=4096,
            sha256="1111" * 16,
            sha512="2222" * 32,
        )
        manifest = self.manager.create_manifest(
            manifest_id="mn-2026-10-003",
            digests=[d1],
            operator_principal="agent_g",  # Agent cannot sign evidence manifest
        )

        with self.assertRaises(PermissionError) as ctx:
            self.manager.verify_manifest(manifest)
        self.assertIn("Must be 'soc-operator'", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
