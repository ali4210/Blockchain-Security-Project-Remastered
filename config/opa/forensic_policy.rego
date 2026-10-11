package soc.forensics

import future.keywords.in

# Fail-closed default: deny all requests
default allow = false

# Set of recognized autonomous swarm agent roles
agent_roles := {
    "agent",
    "agent_a",
    "agent_b",
    "agent_c",
    "agent_d",
    "agent_e",
    "agent_f",
    "agent_g"
}

# 1. UNIVERSAL PROHIBITION: No principal may mutate or delete sealed originals
is_destructive_action {
    input.action in ["delete", "update", "modify", "truncate", "overwrite"]
}

is_destructive_action {
    input.tool in ["deleteEvidence", "updateEvidence", "truncateLog", "dropTrigger"]
}

# 2. SOC Operator Permissions: Authorized for acquisition, sealing, and dispatching
allow {
    not is_destructive_action
    input.principal == "soc-operator"
    input.action in ["acquire", "seal", "dispatch_working_copy", "verify_vault", "read_derived", "read_custody"]
}

# 3. Compliance Officer Permissions: Read custody audit trails and derived reports
allow {
    not is_destructive_action
    input.principal == "compliance-officer"
    input.action in ["read_custody", "read_derived", "verify_vault"]
}

# 4. Autonomous Agent Permissions: Read-only access strictly to derived/sanitized artifacts
allow {
    not is_destructive_action
    input.principal in agent_roles
    input.action == "read_derived"
    input.target in ["working_copy", "sanitized_artifact", "derived_report"]
}

# Structured Deny Reasons for Audit Logging
deny_reason := "Destructive operations on sealed evidence are strictly forbidden for all principals" {
    is_destructive_action
}

deny_reason := "Autonomous agents are strictly forbidden from acquiring or modifying raw forensic evidence" {
    input.principal in agent_roles
    not input.action == "read_derived"
}

deny_reason := "Unauthorized principal or action not permitted under DFIR policy" {
    not allow
    not is_destructive_action
    not (input.principal in agent_roles)
}
