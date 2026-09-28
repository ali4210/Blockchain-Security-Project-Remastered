"""
TODO(phase-4): Zone 3 — local broker store.
Embedded SQLite (exclusive WAL locking) / Redis state cache, with automated
WAL snapshotting prior to every agent swarm execution.
"""


def snapshot() -> None:
    raise NotImplementedError("not implemented — see checklist Phase 4")


def write_finding(_finding: dict) -> None:
    raise NotImplementedError("not implemented — see checklist Phase 4")
