"""
TODO(phase-3, activated in phase-11): Upgrade 5 — DeFi-Specific Attack
Detection. See blueprint Section 2 (Upgrade 5).

- front_running_detector(): reads mcp-tool-consensus-monitor's mempool
  feed (src/mcp_middleware/consensus_monitor.py, built in Phase 11) for
  calldata-copying / gas-outbidding patterns. Stub the structure in
  Phase 3; the actual mempool feed does not exist until Phase 11.
- rug_pull_scanner(): Agent A extension — unrestricted mint functions,
  non-time-locked LP tokens, non-renounced/non-multi-sig ownership,
  hidden post-launch fee functions.
- flash_loan_invariant_generator(): Agent D extension — auto-generates
  Foundry invariants simulating a maximum flash-loan draw (Aave/dYdX
  scale) against the target protocol in one Anvil-forked transaction.
"""


def front_running_detector(_mempool_snapshot) -> list:
    raise NotImplementedError("not implemented — see checklist Phase 3/11")


def rug_pull_scanner(_contract_ast) -> list:
    raise NotImplementedError("not implemented — see checklist Phase 3")


def flash_loan_invariant_generator(_contract_path: str) -> list:
    raise NotImplementedError("not implemented — see checklist Phase 3")
