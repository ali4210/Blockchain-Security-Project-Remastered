"""
TODO(phase-10a): Write-once evidence vault.
- seal(): write artifact read-only (bind mount + chattr +i, or MinIO Object
  Lock compliance mode), record it via integrity.py + chain_of_custody.py
- verify(): re-hash on every access before returning a working copy
- Vault service account must be separate from the agent service account —
  no agent or tool may open the vault for writing.
"""


def seal(_artifact_path: str, _case_id: str, _acquired_by: str, _tool: str,
          _tool_version: str) -> str:
    raise NotImplementedError("not implemented — see checklist Phase 10a")


def verify(_evidence_id: str) -> bool:
    raise NotImplementedError("not implemented — see checklist Phase 10a")


def open_working_copy(_evidence_id: str) -> str:
    raise NotImplementedError("not implemented — see checklist Phase 10a")
