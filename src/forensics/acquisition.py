"""
TODO(phase-10c): Evidence acquisition, in RFC 3227 order of volatility:
memory -> network -> processes -> disk -> logs -> archives.
Requires a soc-operator principal (agents may only plan, not acquire).
Every collector must route its output through evidence_vault.seal().
See blueprint Section 4.3 for tools per evidence class.
"""


def acquire_memory(_target_vm: str) -> str:
    raise NotImplementedError("not implemented — see checklist Phase 10c")


def acquire_disk(_target: str) -> str:
    raise NotImplementedError("not implemented — see checklist Phase 10c")


def acquire_network(_iface: str, _duration_s: int) -> str:
    raise NotImplementedError("not implemented — see checklist Phase 10c")


def acquire_container(_container_id: str) -> str:
    raise NotImplementedError("not implemented — see checklist Phase 10c")


def acquire_pipeline_state(_case_id: str) -> str:
    raise NotImplementedError("not implemented — see checklist Phase 10c")
