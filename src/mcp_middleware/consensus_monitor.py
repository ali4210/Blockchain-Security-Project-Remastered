"""
TODO(phase-11): Register mcp-tool-consensus-monitor on the MCP middleware
pool. Every call must go through opa_guardrail.evaluate() against
config/opa/consensus_policy.rego. [NEW V10.2]

Exposes: getReorgHistory(), getConcentrationReport(),
         getPeerDiversityScore(), getMempoolAnomalies()
Consumed by: Agent B (correlate), Agent E (trigger Zone 4 mitigation),
             Agent G (rate-limit/validate)
"""


def register_consensus_tools(_mcp_server) -> None:
    raise NotImplementedError("not implemented — see checklist Phase 11")
