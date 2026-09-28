"""
TODO(phase-10a): Hash-chained, append-only chain-of-custody log (forensics.db),
separate from the Zone 3 broker store. See blueprint Section 4.5 for the
`evidence` and `custody_log` table schema and the append-only triggers.
entry_hash = SHA256(prev_hash || evidence_id || action || principal || role
                     || ts_utc || detail)
"""


def init_db(_path: str = "forensics.db") -> None:
    raise NotImplementedError("not implemented — see checklist Phase 10a")


def append_entry(_evidence_id: str, _action: str, _principal: str, _role: str,
                  _detail: str = "") -> str:
    raise NotImplementedError("not implemented — see checklist Phase 10a")


def verify_chain(_evidence_id: str) -> bool:
    raise NotImplementedError("not implemented — see checklist Phase 10a")
