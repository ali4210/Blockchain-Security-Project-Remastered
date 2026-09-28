"""
TODO(phase-12): MPC signing for the Defender Relayer's operating key,
split across at least 2 replicas. No single replica's local state may
ever contain the complete key, even during signing.
"""


def joint_sign(_payload: bytes, _replica_ids: list) -> bytes:
    raise NotImplementedError("not implemented — see checklist Phase 12")
