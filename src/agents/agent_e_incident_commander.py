"""
Agent E: Incident Commander (Task P05-010, P12-010).
Triages findings from Agents A-D, determines SEV levels, and synthesizes containment
playbooks using Qwen 2.5 (32B/14B, 8K context) under deterministic Ephemeral VRAM lifecycle management.
Enforces mandatory Anvil pre-sign simulation gating before authorizing mitigation transactions.
"""

from typing import Any, Dict, List, Optional
import json
import re

from src.llm_client.ollama_client import chat, agent_stage
from src.agents.state import SwarmState
from src.wallet.presign_simulator import (
    PresignSimulator,
    RelayerTxIntent,
    SimulationError,
)


def parse_incident_commander_report(response_text: str, target_name: str) -> Dict[str, Any]:
    """Parses model response into structured incident triage and containment report."""
    if "[OFFLINE_FALLBACK]" in response_text:
        return {
            "finding_id": "FINDING-E-SIM-001",
            "category": "INCIDENT_TRIAGE",
            "severity_level": "SEV-1",
            "target": target_name,
            "containment_status": "IMMEDIATE_ACTION_REQUIRED",
            "playbook_actions": [
                "TRIGGER_PAUSE_CIRCUIT_BREAKER",
                "NOTIFY_SECURITY_MULTISIG",
                "ISOLATE_RPC_INGEST_NODE",
            ],
            "rationale": "Simulated incident containment triage triggered in offline mode due to critical exploit vector.",
            "escalation_required": True,
        }

    json_match = re.search(r"```json\s*(.*?)\s*```", response_text, re.DOTALL)
    if json_match:
        try:
            parsed = json.loads(json_match.group(1))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    try:
        parsed = json.loads(response_text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    return {
        "finding_id": "FINDING-E-RAW-001",
        "category": "INCIDENT_TRIAGE",
        "severity_level": "SEV-2",
        "target": target_name,
        "containment_status": "MONITORING",
        "playbook_actions": ["LOG_INCIDENT_REPORT"],
        "rationale": response_text[:200] if response_text else "No analysis available.",
        "escalation_required": False,
    }


def run_agent_e(state: SwarmState) -> SwarmState:
    """
    LangGraph execution node for Agent E (Incident Commander).
    Triages findings and executes mandatory pre-sign simulation for proposed mitigation actions.
    """
    target = state.get("target_contract") or state.get("contract_path", "VulnerableVault")
    findings = state.get("findings", [])

    prompt = (
        "You are an expert blockchain incident commander responsible for emergency response.\n\n"
        f"Target System: {target}\n"
        f"Aggregated Findings:\n{json.dumps(findings, indent=2)}\n\n"
        "Render an incident triage assessment. Emit findings in JSON format: "
        "{\"finding_id\": \"FINDING-E-001\", \"category\": \"INCIDENT_TRIAGE\", "
        "\"severity_level\": \"SEV-1/SEV-2/SEV-3/SEV-4\", \"target\": \"" + str(target) + "\", "
        "\"containment_status\": \"IMMEDIATE_ACTION_REQUIRED/MONITORING/STABLE\", "
        "\"playbook_actions\": [\"ACTION_1\", \"ACTION_2\"], "
        "\"rationale\": \"...\", \"escalation_required\": true}"
    )

    messages = [
        {"role": "system", "content": "You are Agent E, Lead Blockchain Incident Commander."},
        {"role": "user", "content": prompt},
    ]

    with agent_stage("E") as stage_ctx:
        response = chat(
            messages=messages,
            model=stage_ctx["model"],
            force_agent="E",
            timeout=stage_ctx["timeout"],
        )

    triage_report = parse_incident_commander_report(response, str(target))
    escalation = triage_report.get("escalation_required", False) or (
        triage_report.get("severity_level") in ["SEV-1", "SEV-2"]
    )

    metadata = dict(state.get("metadata", {}))
    metadata["agent_e_executed"] = True
    metadata["agent_e_model"] = stage_ctx["model"]
    metadata["severity_level"] = triage_report.get("severity_level", "SEV-2")
    metadata["containment_status"] = triage_report.get("containment_status", "STABLE")

    # Zone 7 Mandatory Pre-Sign Simulation Gate
    has_wallet_flaws = any(
        f.get("rule_id", "").startswith("RULE-WLT-") for f in findings
    )
    if has_wallet_flaws or escalation:
        emergency_target = "0xPauseTarget0000000000000000000000000000"
        simulator = PresignSimulator(
            allowed_recipients={emergency_target},
            max_drain_wei=10**17,  # Max 0.1 ETH
            max_gas=150_000,
        )
        mitigation_intent = RelayerTxIntent(
            sender="0xIncidentCommanderRelayer0000000000000000",
            target=emergency_target,
            value_wei=0,
            data=b"\x84\x56\xcb\x23",  # pause()
            nonce=1,
            gas_limit=100_000,
        )

        should_fail_sim = metadata.get("mock_simulation_failure", False)
        try:
            receipt = simulator.simulate_and_validate(
                intent=mitigation_intent,
                mock_revert=should_fail_sim,
                simulated_gas_used=35_000,
                simulated_drain_wei=0,
            )
            metadata["presign_simulation_passed"] = True
            metadata["simulation_receipt_digest"] = receipt.receipt_digest
        except SimulationError as err:
            metadata["presign_simulation_passed"] = False
            metadata["containment_status"] = "BLOCKED_SIMULATION_FAILURE"
            metadata["simulation_error"] = str(err)
            triage_report["containment_status"] = "BLOCKED_SIMULATION_FAILURE"
            triage_report["playbook_actions"] = ["HALT_DISPATCH_SIMULATION_REVERTED"]

    updated_findings = list(findings) + [triage_report]

    new_state = SwarmState(
        target_contract=state.get("target_contract", ""),
        findings=updated_findings,
        current_stage="agent_e_completed",
        escalation_needed=escalation,
        errors=list(state.get("errors", [])),
        metadata=metadata,
    )
    new_state["current_step"] = "agent_e_completed"
    return new_state

# Backward compatibility alias for LangGraph pipeline
incident_commander_node = run_agent_e
