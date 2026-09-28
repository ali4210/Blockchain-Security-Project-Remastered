# TODO(phase-13): Policy-as-Code guardrails for Zone 8 compliance. [NEW V10.2]
# See blueprint Section 4C.6. New "compliance-officer" principal, parallel
# to soc-operator — agents may screen/detect/draft, only a compliance
# officer may approve or file a report.
package soc.compliance

default allow := false

agent_actions := {
  "compliance.screen_address", "compliance.detect_pattern",
  "compliance.generate_zk_attestation", "compliance.draft_report"
}

officer_actions := {
  "compliance.approve_report", "compliance.file_report"
}

# TODO: implement allow rules per blueprint Section 4C.6
# allow if { input.principal.role == "agent"; input.action in agent_actions }
# allow if { input.principal.role == "compliance-officer"; input.principal.authenticated == true; input.action in officer_actions }
