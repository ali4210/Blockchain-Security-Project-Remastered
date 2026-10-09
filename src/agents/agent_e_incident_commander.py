"""
Agent E: Incident Commander (Task P05-010).
Triages findings from Agents A-D, determines SEV levels, and synthesizes containment
playbooks using Qwen 2.5 (32B/14B, 8K context) under deterministic Ephemeral VRAM lifecycle management.
"""

from typing import Any, Dict, List, Optional
import json
import re

from src.llm_client.ollama_client import chat, agent_stage
from src.agents.state import SwarmState


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
            if isinstance(parsed, dict) and "severity_level" in parsed:
                return parsed
        except json.JSONDecodeError:
            pass

    return {
        "finding_id": "FINDING-E-001",
        "category": "INCIDENT_TRIAGE",
        "severity_level": "SEV-2",
        "target": target_name,
        "containment_status": "IMMEDIATE_ACTION_REQUIRED",
        "playbook_actions": ["TRIGGER_CIRCUIT_BREAKER", "ALERT_MULTISIG"],
        "rationale": response_text[:250].strip(),
        "escalation_required": True,
    }


def incident_commander_node(state: SwarmState) -> SwarmState:
    """
    LangGraph execution node for Agent E (Incident Commander).
    Wraps inference in agent_stage('E') to enforce immediate VRAM eviction.
    """
    findings = state.get("findings", [])
    target = state.get("target_contract") or state.get("contract_path", "VulnerableVault")

    prompt = (
        "You are the Lead Incident Commander for an autonomous blockchain Security Operations Center. "
        "Review the aggregated findings from the static auditor, SIEM threat hunter, compliance judge, and red teamer.\n\n"
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

    updated_findings = list(findings) + [triage_report]
    metadata = dict(state.get("metadata", {}))
    metadata["agent_e_executed"] = True
    metadata["agent_e_model"] = stage_ctx["model"]
    metadata["severity_level"] = triage_report.get("severity_level", "SEV-2")
    metadata["containment_status"] = triage_report.get("containment_status", "STABLE")

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
