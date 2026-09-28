"""
TODO(phase-12): Shamir Secret Sharing for the soc-operator's evidence-
manifest signing key (Zone 5). Split into N-of-M shares distributed to
named trusted holders; reconstruct only to sign a release or manifest.
Wrap an audited existing implementation — do not hand-roll the
cryptography. Only a soc-operator principal may call reconstruct().
"""


def split_key(_secret_key: bytes, _n: int, _m: int) -> list:
    raise NotImplementedError("not implemented — see checklist Phase 12")


def reconstruct(_shares: list) -> bytes:
    raise NotImplementedError("not implemented — see checklist Phase 12")
