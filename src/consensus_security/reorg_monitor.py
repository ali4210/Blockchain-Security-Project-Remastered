"""
TODO(phase-11): Reorg Depth Monitor.
Track chain reorganizations on every new block; alert when depth exceeds
the chain's configured finality window (chain-specific — configure per
deployment, e.g. > 2 blocks on a fast-finality chain).
"""


def check_reorg_depth(_new_block) -> int:
    raise NotImplementedError("not implemented — see checklist Phase 11")
