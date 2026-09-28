"""
TODO(phase-10d): mcp-tool-host-forensics (disk half).
Sleuth Kit CLI wrapper: mmls, fls, icat, istat, tsk_recover, mactime.
Operates ONLY on a verified working copy from evidence_vault, never the
sealed original. Returns structured JSON, not raw tool text.
"""


def list_partitions(_image_path: str) -> list:
    raise NotImplementedError("not implemented — see checklist Phase 10d")


def file_timeline(_image_path: str) -> list:
    raise NotImplementedError("not implemented — see checklist Phase 10d")
