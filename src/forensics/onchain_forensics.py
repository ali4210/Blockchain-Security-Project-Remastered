"""
TODO(phase-10c/10d): mcp-tool-onchain-forensics.
Trace replay on a pinned-block Anvil fork, state-diff extraction, address
clustering and fund-flow queries (Web3.py, Foundry `cast`, GraphSense API).
"""


def replay_transaction(_tx_hash: str, _fork_block: int) -> dict:
    raise NotImplementedError("not implemented — see checklist Phase 10c/10d")


def trace_funds(_address: str) -> dict:
    raise NotImplementedError("not implemented — see checklist Phase 10c/10d")
