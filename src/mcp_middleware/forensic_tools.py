"""
TODO(phase-10d): Register the Zone 5 forensic tools on the MCP middleware
pool. Every call must go through opa_guardrail.evaluate() against
config/opa/forensics_policy.rego before it runs. [NEW V10.1]

Tools to register:
  mcp-tool-host-forensics     -> src/forensics/disk_forensics.py
  mcp-tool-memory-forensics   -> src/forensics/memory_forensics.py
  mcp-tool-evidence-vault     -> src/forensics/evidence_vault.py
  mcp-tool-timeline           -> src/forensics/timeline.py
  mcp-tool-onchain-forensics  -> src/forensics/onchain_forensics.py
"""


def register_forensic_tools(_mcp_server) -> None:
    raise NotImplementedError("not implemented — see checklist Phase 10d")
