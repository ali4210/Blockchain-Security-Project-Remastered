"""
Agent B: SIEM Threat Hunter (Task P05-007).
Dispatches log-correlation and telemetry analysis prompts to DeepSeek R1 (32B/14B, 16K context)
under deterministic Ephemeral VRAM lifecycle management.
"""

from typing import Any, Dict, List, Optional
from pathlib import Path
import json
import re

from src.llm_client.ollama_client import chat, agent_stage
from src.agents.state import SwarmState


def extract_telemetry_logs(state: SwarmState) -> str:
    """Retrieves SIEM telemetry or log records from state, files, or defaults."""
    telemetry_raw = state.get("telemetry_logs") or state.get("siem_logs")
    if telemetry_raw:
        if isinstance(telemetry_raw, list):
            return json.dumps(telemetry_raw, indent=2)
        return str(telemetry_raw)

    log_path_str = state.get("log_path")
    if log_path_str:
        p = Path(log_path_str)
        if p.is_file():
            return p.read_text(encoding="utf-8")

    # Default synthetic telemetry sample for offline / test environments
    return (
        "TIMESTAMP=2026-10-08T12:00:00Z EVENT=TRANSACTION_EXECUTION "
        "METHOD=withdraw() STATUS=REVERT_FLAG_CLEARED GAS_USED=142000 "
        "ORIGIN=0x70997970C51812dc3A010C7d01b50e0d17dc79C8 "
        "TARGET=VulnerableVault VALUE=10.0_ETH ANOMALY_SCORE=0.92"
    )


def parse_threat_findings(response_text: str, target_name: str) -> List[Dict[str, Any]]:
    """Parses model response into structured threat correlation findings."""
    findings: List[Dict[str, Any]] = []

    if "[OFFLINE_FALLBACK]" in response_text:
        findings.append({
            "finding_id": "FINDING-B-SIM-001",
            "threat_type": "Telemetry / Log Correlation Anomaly",
            "severity": "HIGH",
            "target": target_name,
            "correlated_indicators": ["TRANSACTION_EXECUTION", "ANOMALY_SCORE=0.92"],
            "details": "Simulated SIEM threat hunter finding in offline headless mode.",
            "confidence": 0.88,
        })
        return findings

    json_match = re.search(r"```json\s*(.*?)\s*```", response_text, re.DOTALL)
    if json_match:
        try:
            parsed = json.loads(json_match.group(1))
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict) and "threats" in parsed:
                return parsed["threats"]
            if isinstance(parsed, dict) and "findings" in parsed:
                return parsed["findings"]
        except json.JSONDecodeError:
            pass

    findings.append({
        "finding_id": "FINDING-B-001",
        "threat_type": "Runtime SIEM Correlation Summary",
        "severity": "MEDIUM",
        "target": target_name,
        "correlated_indicators": ["RAW_TELEMETRY"],
        "details": response_text[:250].strip(),
        "confidence": 0.75,
    })
    return findings


def threat_hunter_node(state: SwarmState) -> SwarmState:
    """
    LangGraph execution node for Agent B (SIEM Threat Hunter).
    Wraps inference in agent_stage('B') to enforce immediate VRAM eviction.
    """
    telemetry = extract_telemetry_logs(state)
    target = state.get("target_contract") or state.get("contract_path", "VulnerableVault")
    prior_findings = state.get("findings", [])

    prompt = (
        "You are an expert blockchain SOC analyst and SIEM threat hunter specializing in "
        "mempool analysis, on-chain anomaly correlation, and smart-contract exploit telemetry.\n\n"
        f"Target Contract / System: {target}\n"
        f"Prior Static Audit Findings: {json.dumps(prior_findings, indent=2)}\n\n"
        f"Runtime Telemetry Logs:\n```\n{telemetry}\n```\n\n"
        "Correlate the runtime telemetry with the contract context. "
        "Emit findings in JSON format: [{\"finding_id\": \"...\", \"threat_type\": \"...\", "
        "\"severity\": \"HIGH/MEDIUM/LOW\", \"target\": \"...\", "
        "\"correlated_indicators\": [\"...\"], \"details\": \"...\", \"confidence\": 0.9}]"
    )

    messages = [
        {"role": "system", "content": "You are Agent B, Lead SIEM Threat Hunter."},
        {"role": "user", "content": prompt},
    ]

    with agent_stage("B") as stage_ctx:
        response = chat(
            messages=messages,
            model=stage_ctx["model"],
            force_agent="B",
            timeout=stage_ctx["timeout"],
        )

    parsed_threats = parse_threat_findings(response, str(target))

    updated_findings = list(prior_findings) + parsed_threats
    metadata = dict(state.get("metadata", {}))
    metadata["agent_b_executed"] = True
    metadata["agent_b_model"] = stage_ctx["model"]

    new_state = SwarmState(
        target_contract=state.get("target_contract", ""),
        findings=updated_findings,
        current_stage="agent_b_completed",
        escalation_needed=state.get("escalation_needed", False),
        errors=list(state.get("errors", [])),
        metadata=metadata,
    )
    new_state["current_step"] = "agent_b_completed"
    return new_state
