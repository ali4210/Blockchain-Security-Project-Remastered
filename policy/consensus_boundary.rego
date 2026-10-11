package consensus.boundary

# Default deny
default allow = false
default reason = "Default deny: unauthorized principal or action"

# Authorized roles and categories
agent_principals := {"agent_a", "agent_b", "agent_c", "agent_d", "agent_e", "agent_f", "agent_g"}
operator_principals := {"operator", "soc_lead", "soc_operator"}
compliance_principals := {"compliance_officer"}

# Action classifications
read_actions := {
    "read",
    "observe",
    "correlate",
    "get_mempool_telemetry",
    "get_topology_summary",
    "get_reorg_history",
    "get_concentration_metrics",
    "evaluate_selfish_mining",
    "evaluate_eclipse_status"
}

mitigation_actions := {
    "mitigate",
    "evict_peer",
    "slash_validator",
    "override_gate",
    "quarantine_node",
    "isolate_network",
    "execute_action"
}

# Rule 1: Agents are permitted read and correlation actions
allow {
    agent_principals[input.principal]
    read_actions[input.action]
}

reason = "Agent authorized for read-only consensus telemetry inspection" {
    agent_principals[input.principal]
    read_actions[input.action]
}

# Rule 2: Agents are strictly denied mitigation and override actions
reason = "Autonomous agents are prohibited from executing consensus mitigations or overrides" {
    agent_principals[input.principal]
    mitigation_actions[input.action]
}

# Rule 3: Operator is permitted all valid actions
allow {
    operator_principals[input.principal]
    input.token_valid == true
}

reason = "Human operator authorized with valid credentials" {
    operator_principals[input.principal]
    input.token_valid == true
}

reason = "Human operator denied: missing or invalid credentials" {
    operator_principals[input.principal]
    not input.token_valid
}

# Rule 4: Compliance officer is permitted read-only audit inspection
allow {
    compliance_principals[input.principal]
    read_actions[input.action]
}

reason = "Compliance officer authorized for read-only consensus audit inspection" {
    compliance_principals[input.principal]
    read_actions[input.action]
}

reason = "Compliance officer prohibited from executing mutations or mitigations" {
    compliance_principals[input.principal]
    mitigation_actions[input.action]
}
