# TODO(phase-12): Policy-as-Code guardrails for Zone 7 wallet/key security. [NEW V10.2]
# See blueprint Section 4B.6. Agents never touch a real key — only
# soc-operator may reconstruct a Shamir share, request an HSM/MPC
# signature, or rotate a key.
package soc.wallet

default allow := false

agent_actions := {
  "wallet.audit_contract", "wallet.simulate_transaction", "wallet.read_key_metadata"
}

operator_actions := {
  "wallet.reconstruct_shamir_share", "wallet.request_hsm_signature", "wallet.rotate_key"
}

# TODO: implement allow rules per blueprint Section 4B.6
# allow if { input.principal.role == "agent"; input.action in agent_actions }
# allow if { input.principal.role == "soc-operator"; input.principal.authenticated == true; input.action in operator_actions }
