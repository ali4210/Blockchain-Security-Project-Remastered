"""
TODO(phase-12): HSM-backed custody for the Zone 4 Gnosis Safe signer keys.
Request-a-signature interface only — no code path may export the raw key
from the device. A documented HSM-emulator stand-in is acceptable for
coursework; note the simplification if used.
"""


def request_signature(_key_id: str, _payload: bytes) -> bytes:
    raise NotImplementedError("not implemented — see checklist Phase 12")
