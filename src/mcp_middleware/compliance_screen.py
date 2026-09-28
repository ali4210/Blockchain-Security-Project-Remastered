"""
TODO(phase-13): Register mcp-tool-compliance-screen on the MCP middleware
pool. Every call must go through opa_guardrail.evaluate() against
config/opa/compliance_policy.rego. [NEW V10.2]

Exposes: screenAddress(), getAMLFindings(), generateZKAttestation(),
         draftSAR()
"""


def register_compliance_tools(_mcp_server) -> None:
    raise NotImplementedError("not implemented — see checklist Phase 13")
