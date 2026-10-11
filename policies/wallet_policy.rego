package wallet.authz

import future.keywords.in

default allow = false
default reason = "DENIED_BY_DEFAULT"

# Set of allowed read-only operations accessible by autonomous agents
allowed_agent_actions := {
    "read",
    "audit",
    "simulate",
    "observe",
    "evaluate_status",
    "query_telemetry"
}

# Operations strictly blocked for autonomous agents under all conditions
forbidden_agent_actions := {
    "export_private_key",
    "shamir_reconstruct",
    "hsm_sign",
    "broadcast_transaction",
    "drain_balance",
    "rotate_master_key"
}

# Operations requiring authenticated human operator tokens
authorized_operator_actions := {
    "emergency_pause",
    "hsm_sign",
    "shamir_reconstruct",
    "dispatch_mitigation",
    "rotate_master_key"
}

# Rule 1: Autonomous agents permitted strictly for read and simulation workflows
allow {
    input.principal in ["Agent-A", "Agent-B", "Agent-C", "Agent-D", "Agent-E", "Agent-F", "Agent-G"]
    input.action in allowed_agent_actions
    not input.action in forbidden_agent_actions
}

# Rule 2: Authorized SOC operators allowed with valid non-expired release token
allow {
    input.principal in ["soc_operator", "lead_incident_commander"]
    input.action in authorized_operator_actions
    valid_operator_token(input.token)
}

# Helper: Validates bearer operator token structure and expiration
valid_operator_token(token) {
    token != null
    token.valid == true
    token.expires_at > input.current_time
    token.role in ["soc_operator", "lead_incident_commander"]
}

# Rule 3: Compliance officers permitted for read and audit
allow {
    input.principal == "compliance_officer"
    input.action in allowed_agent_actions
}
