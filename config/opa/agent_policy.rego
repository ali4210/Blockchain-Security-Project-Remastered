# Task P09-002: Policy-as-Code guardrails for Zone 4 MCP middleware and agent swarm.
# Encodes least-privilege role boundaries:
#   - principal "agent" / "agent_*" -> Read-only operations only (listAttackPaths, planRemediation, telemetry)
#   - principal "soc-operator"       -> Human authorized for write/execute (writeRemediationPlan, isolateHost, pause)
#   - principal "compliance-officer" -> Read compliance, draft reports (no active execution)
package soc.guardrails

import future.keywords.in

# Strict default deny
default allow = false

# Allowlist of read-only tools accessible by autonomous agents
agent_allowed_tools := {
    "listAttackPaths",
    "planRemediation",
    "queryWeb3Rpc",
    "queryTelemetry",
    "getAstMasked",
    "readStorage",
    "readAuditLogs",
    "simulateNetworkPolicy",
    "evaluateDreadScore"
}

# Allowlist of sensitive tools restricted strictly to human operators
operator_exclusive_tools := {
    "writeRemediationPlan",
    "isolateHost",
    "applyNetworkPolicy",
    "pauseCircuitBreaker",
    "sealEvidenceVault",
    "signReleaseToken",
    "triggerPublicMirror",
    "modifyBrokerStore"
}

# Rule 1: Human soc-operator can execute both read tools and authorized operational tools
allow {
    input.principal == "soc-operator"
    is_valid_operator_tool(input.tool)
}

# Rule 2: Autonomous agent principal can execute only designated read-only tools
allow {
    is_agent_principal(input.principal)
    input.action == "read"
    input.tool in agent_allowed_tools
}

# Helper: Match autonomous agent principal variants
is_agent_principal(principal) {
    principal == "agent"
}

is_agent_principal(principal) {
    startswith(principal, "agent_")
}

# Helper: Valid operator tools
is_valid_operator_tool(tool) {
    tool in agent_allowed_tools
}

is_valid_operator_tool(tool) {
    tool in operator_exclusive_tools
}

# Audit & Denial Explanations
deny_reason["Autonomous agent is prohibited from executing mutation or active remediation tools"] {
    is_agent_principal(input.principal)
    input.tool in operator_exclusive_tools
}

deny_reason["Autonomous agent action must be read-only"] {
    is_agent_principal(input.principal)
    input.action != "read"
}

deny_reason["Unknown or unauthorized principal"] {
    not is_agent_principal(input.principal)
    input.principal != "soc-operator"
    input.principal != "compliance-officer"
}

deny_reason["Tool not recognized in system capability registry"] {
    not input.tool in agent_allowed_tools
    not input.tool in operator_exclusive_tools
}
