"""
TODO(phase-13): Zero-Knowledge Compliance Attestations.
Generate a ZK proof attesting to a specific compliance fact (e.g.
"cumulative volume this period is under threshold X", "address is not on
the sanctions list") WITHOUT revealing the underlying transaction data.
A documented simplified circuit (e.g. an existing ZK library's range-proof
primitive) is acceptable coursework scope — note the simplification.
"""


def generate_under_threshold_proof(_address: str, _threshold: float) -> bytes:
    raise NotImplementedError("not implemented — see checklist Phase 13")


def verify_proof(_proof: bytes) -> bool:
    raise NotImplementedError("not implemented — see checklist Phase 13")
