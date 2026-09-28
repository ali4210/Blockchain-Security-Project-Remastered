"""
TODO(phase-10a): Evidence integrity core — build this FIRST, before acquisition.
- Streaming SHA-256 and SHA-512 of an artifact in a single pass
- Merkle root over a manifest of {artifact_id, size, hashes, source, tool,
  tool_version, acquired_utc, acquired_by}
- Sign the manifest with the soc-operator's key (GPG or minisign/ed25519)
- verify_manifest() re-hashes and checks the signature
See blueprint Section 4.5.
"""


def hash_artifact(_path: str) -> dict:
    raise NotImplementedError("not implemented — see checklist Phase 10a")


def build_manifest(_entries: list) -> dict:
    raise NotImplementedError("not implemented — see checklist Phase 10a")


def sign_manifest(_manifest: dict, _key_path: str) -> str:
    raise NotImplementedError("not implemented — see checklist Phase 10a")


def verify_manifest(_manifest: dict, _signature: str) -> bool:
    raise NotImplementedError("not implemented — see checklist Phase 10a")
