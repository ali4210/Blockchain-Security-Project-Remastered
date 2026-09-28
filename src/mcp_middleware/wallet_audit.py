"""
TODO(phase-12): Register mcp-tool-wallet-audit on the MCP middleware pool.
Runs Slither/Mythril/Certora (from Phase 3) with a wallet-specific rule
set: signature replay, missing nonce checks, incorrect multi-sig
threshold logic, unprotected upgrade functions. Returns structured
findings into the Zone 3 pipeline like a standard contract audit.
"""


def register_wallet_audit_tool(_mcp_server) -> None:
    raise NotImplementedError("not implemented — see checklist Phase 12")


def audit_wallet_contract(_contract_path: str) -> dict:
    raise NotImplementedError("not implemented — see checklist Phase 12")
