package compliance_policy

import future.keywords.in

# Default deny
default allow := false

# Actions permitted for autonomous agents and operators (Read / Screen / Draft)
allowed_read_actions := {
    "screen_address",
    "evaluate_aml",
    "verify_zk_attestation",
    "read_draft_sar"
}

# Drafting is permitted for compliance officer, soc operator, and Agent C
allowed_draft_actions := {
    "generate_draft_sar"
}

# Actions strictly reserved for Human Compliance Officer with cryptographic token
officer_exclusive_actions := {
    "approve_sar_report",
    "file_sar_report",
    "export_sar_report"
}

# All recognized autonomous agents
autonomous_agents := {
    "agent_a_auditor",
    "agent_b_threat_hunter",
    "agent_c_compliance_judge",
    "agent_d_red_teamer",
    "agent_e_incident_commander",
    "agent_f_logic_analyzer",
    "agent_g_guardrail"
}

# Rule 1: Allow read and screening actions for known agents and human operators
allow {
    input.action in allowed_read_actions
    is_authorized_reader
}

# Rule 2: Allow draft generation for authorized drafters
allow {
    input.action in allowed_draft_actions
    is_authorized_drafter
}

# Rule 3: Allow approval and filing ONLY for human compliance_officer with valid token
allow {
    input.action in officer_exclusive_actions
    input.principal == "compliance_officer"
    valid_officer_token
}

# Helper: Authorized reader
is_authorized_reader {
    input.principal in autonomous_agents
}

is_authorized_reader {
    input.principal in {"compliance_officer", "soc_operator"}
}

# Helper: Authorized drafter
is_authorized_drafter {
    input.principal in {"compliance_officer", "soc_operator", "agent_c_compliance_judge"}
}

# Helper: Valid officer token validation
valid_officer_token {
    token := input.token
    token != null
    token.role == "compliance_officer"
    token.expires_at > input.current_timestamp
    token.signature != null
    token.signature != ""
}
