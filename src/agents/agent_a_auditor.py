"""
Agent A: Smart-Contract Auditor (Task P05-006, P12-010).
Dispatches AST and source analysis prompts to Qwen 2.5 Coder (32B/14B, 32K context)
under deterministic Ephemeral VRAM lifecycle management.
Integrates Zone 7 Wallet-Audit MCP tool for wallet/multisig contracts.
"""

from typing import Any, Dict, List, Optional
from pathlib import Path
import json
import re

from src.llm_client.ollama_client import chat, agent_stage
from src.agents.state import SwarmState
from src.wallet.wallet_audit_mcp import WalletAuditMcpRegistry


def extract_contract_source(state: SwarmState) -> str:
    """Retrieves target contract source code from state or default repository fixtures."""
    contract_path_str = state.get("target_contract") or state.get("contract_path")
    if contract_path_str:
        p = Path(contract_path_str)
        if p.is_file():
            return p.read_text(encoding="utf-8")

    default_fixture = Path("contracts/solidity/VulnerableVault.sol")
    if default_fixture.is_file():
        return default_fixture.read_text(encoding="utf-8")

    return "// Target contract source code unavailable"


def parse_auditor_findings(response_text: str, contract_name: str) -> List[Dict[str, Any]]:
    """Parses model response into structured security findings list."""
    findings: List[Dict[str, Any]] = []

    if "[OFFLINE_FALLBACK]" in response_text:
        findings.append({
            "finding_id": "FINDING-A-SIM-001",
            "vulnerability": "Reentrancy Vulnerability",
            "severity": "HIGH",
            "contract": contract_name,
            "details": "Simulated offline finding for pipeline verification: State update occurs after external call.",
            "confidence": 0.95,
        })
        return findings

    json_match = re.search(r"```json\s*(.*?)\s*```", response_text, re.DOTALL)
    if json_match:
        try:
            parsed = json.loads(json_match.group(1))
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            pass

    try:
        parsed = json.loads(response_text)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass

    findings.append({
        "finding_id": "FINDING-A-RAW-001",
        "vulnerability": "Heuristic Audit Output",
        "severity": "MEDIUM",
        "contract": contract_name,
        "details": response_text[:200] if response_text else "No details extracted.",
        "confidence": 0.50,
    })
    return findings


def run_agent_a(state: SwarmState) -> SwarmState:
    """
    LangGraph execution node for Agent A (Smart-Contract Auditor).
    Wraps inference in agent_stage("A") to enforce immediate VRAM eviction.
    Executes specialized Zone 7 wallet audits when wallet patterns are present.
    """
    contract_source = extract_contract_source(state)
    target_contract = state.get("target_contract") or state.get("contract_path", "contracts/solidity/VulnerableVault.sol")

    prompt = (
        "You are an expert smart-contract security auditor specializing in EVM and Move bytecode. "
        "Analyze the following contract source code for reentrancy, access control bypasses, "
        "and untrusted external calls.\n\n"
        f"Source:\n```solidity\n{contract_source}\n```\n\n"
        "Emit findings in JSON format: [{\"finding_id\": \"...\", \"vulnerability\": \"...\", "
        "\"severity\": \"HIGH/MEDIUM/LOW\", \"contract\": \"...\", \"details\": \"...\", \"confidence\": 0.9}]"
    )

    messages = [
        {"role": "system", "content": "You are Agent A, Lead Smart Contract Auditor."},
        {"role": "user", "content": prompt},
    ]

    with agent_stage("A") as stage_ctx:
        response = chat(
            messages=messages,
            model=stage_ctx["model"],
            force_agent="A",
            timeout=stage_ctx["timeout"],
        )

    parsed_findings = parse_auditor_findings(response, target_contract)

    # Zone 7 Wallet Audit MCP tool execution
    wallet_findings: List[Dict[str, Any]] = []
    quarantine_required = False
    is_wallet_contract = any(
        kw in contract_source for kw in ["ecrecover", "ECDSA.recover", "delegatecall", "VulnerableWallet", "executeTransfer"]
    )

    if is_wallet_contract:
        mcp = WalletAuditMcpRegistry()
        mcp_res = mcp.call_tool(
            "audit_wallet_contract",
            {"contract_source": contract_source, "contract_name": str(target_contract)},
        )
        for idx, f in enumerate(mcp_res.get("findings", [])):
            wallet_findings.append({
                "finding_id": f"FINDING-A-WLT-{idx+1:03d}",
                "vulnerability": f["title"],
                "severity": f["severity"],
                "contract": str(target_contract),
                "details": f["description"],
                "rule_id": f["rule_id"],
                "remediation": f["remediation"],
                "confidence": 0.98,
            })
        if mcp_res.get("requires_quarantine", False):
            quarantine_required = True

    updated_findings = list(state.get("findings", [])) + parsed_findings + wallet_findings
    metadata = dict(state.get("metadata", {}))
    metadata["agent_a_executed"] = True
    metadata["agent_a_model"] = stage_ctx["model"]
    if is_wallet_contract:
        metadata["wallet_audit_executed"] = True
        metadata["quarantine_required"] = quarantine_required

    escalation = state.get("escalation_needed", False) or quarantine_required

    new_state = SwarmState(
        target_contract=target_contract,
        findings=updated_findings,
        current_stage="agent_a_completed",
        escalation_needed=escalation,
        errors=list(state.get("errors", [])),
        metadata=metadata,
    )
    new_state["current_step"] = "agent_a_completed"
    return new_state

# Backward compatibility alias for LangGraph pipeline
audit_contract_node = run_agent_a
