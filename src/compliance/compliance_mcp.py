"""
Task P13-005: Compliance Model Context Protocol (MCP) Server Interface.
Registers and exposes compliance screening, AML telemetry evaluation,
and draft SAR generation tools to autonomous agents under strict HITL constraints.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
import json

from src.compliance.address_screener import AddressScreener, RiskTier
from src.compliance.aml_detector import AMLDetector, AMLTransaction
from src.compliance.sar_generator import SARReportGenerator, InvolvedSubject, RegulatoryJurisdiction
from src.compliance.zk_attestation import SimpleZKAttestor, ComplianceProof


@dataclass(frozen=True)
class MCPToolDefinition:
    name: str
    description: str
    parameters_schema: Dict[str, Any]
    handler: Callable[[Dict[str, Any]], Dict[str, Any]]


class ComplianceMCPRegistry:
    """
    Model Context Protocol registry exposing Zone 8 compliance capabilities.
    """

    def __init__(self, rate_limit_per_minute: int = 60, screener: AddressScreener = None):
        self.rate_limit_per_minute = rate_limit_per_minute
        # Injectable so tests use deterministic records instead of the live OFAC snapshot.
        self._screener = screener if screener is not None else AddressScreener()
        self._aml_detector = AMLDetector()
        self._sar_generator = SARReportGenerator()
        self._zk_attestor = SimpleZKAttestor()
        self._tools: Dict[str, MCPToolDefinition] = {}
        self._call_counter = 0
        self._register_tools()

    def _register_tools(self) -> None:
        # Tool 1: Address Screener
        self._tools["compliance_screen_address"] = MCPToolDefinition(
            name="compliance_screen_address",
            description="Screens an EVM address against deterministic sanctions snapshots.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "The EVM address to screen"}
                },
                "required": ["address"],
            },
            handler=self._handle_screen_address,
        )

        # Tool 2: AML Telemetry Evaluation
        self._tools["compliance_evaluate_aml_telemetry"] = MCPToolDefinition(
            name="compliance_evaluate_aml_telemetry",
            description="Evaluates transaction telemetry for structuring, layering, and mixer interactions.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "transactions": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "List of transactions with tx_hash, sender, recipient, value_wei, timestamp, block_number",
                    }
                },
                "required": ["transactions"],
            },
            handler=self._handle_evaluate_aml,
        )

        # Tool 3: Draft SAR Generator
        self._tools["compliance_generate_draft_sar"] = MCPToolDefinition(
            name="compliance_generate_draft_sar",
            description="Generates an immutable draft SAR report. Gated to local staging only.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "findings": {"type": "array", "items": {"type": "object"}},
                    "subjects": {"type": "array", "items": {"type": "object"}},
                    "transactions": {"type": "array", "items": {"type": "object"}},
                },
                "required": ["case_id", "findings", "subjects", "transactions"],
            },
            handler=self._handle_generate_sar,
        )

        # Tool 4: ZK Attestation Verification
        self._tools["compliance_verify_zk_attestation"] = MCPToolDefinition(
            name="compliance_verify_zk_attestation",
            description="Verifies a zero-knowledge compliance attestation proof.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "proof": {"type": "object", "description": "ComplianceProof dictionary"}
                },
                "required": ["proof"],
            },
            handler=self._handle_verify_zk,
        )

    def _check_rate_limit(self) -> None:
        self._call_counter += 1
        if self._call_counter > self.rate_limit_per_minute:
            raise RuntimeError(f"Rate limit exceeded: max {self.rate_limit_per_minute} calls/min.")

    def get_tool_metadata(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters_schema,
            }
            for t in self._tools.values()
        ]

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._check_rate_limit()
        if name not in self._tools:
            return {"status": "error", "error": f"Tool '{name}' not found."}

        tool = self._tools[name]
        # Basic validation
        for req in tool.parameters_schema.get("required", []):
            if req not in arguments:
                return {"status": "error", "error": f"Missing required parameter '{req}'."}

        try:
            return {"status": "success", "result": tool.handler(arguments)}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # Handlers
    def _handle_screen_address(self, args: Dict[str, Any]) -> Dict[str, Any]:
        match = self._screener.screen(args["address"])
        return {
            "is_flagged": match.is_flagged,
            "risk_tier": match.risk_tier.value,
            "risk_score": match.risk_score,
            "matched_address": match.matched_address,
            "reason": match.reason,
            "entity_name": match.matched_entry.entity_name if match.matched_entry else None,
            "category": match.matched_entry.category if match.matched_entry else None,
        }

    def _handle_evaluate_aml(self, args: Dict[str, Any]) -> Dict[str, Any]:
        raw_txs = args["transactions"]
        tx_objs = [
            AMLTransaction(
                tx_hash=t["tx_hash"],
                sender=t["sender"],
                recipient=t["recipient"],
                value_wei=int(t["value_wei"]),
                timestamp=float(t["timestamp"]),
                block_number=int(t.get("block_number", 0)),
            )
            for t in raw_txs
        ]
        findings = self._aml_detector.analyze_batch(tx_objs)
        return {
            "findings_count": len(findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "risk_type": f.risk_type.value,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "involved_addresses": f.involved_addresses,
                    "evidence_tx_hashes": f.evidence_tx_hashes,
                    "description": f.description,
                }
                for f in findings
            ],
        }

    def _handle_generate_sar(self, args: Dict[str, Any]) -> Dict[str, Any]:
        subjects = [
            InvolvedSubject(
                address=s["address"],
                role=s.get("role", "SENDER"),
                risk_tier=s.get("risk_tier", "HIGH_RISK"),
                sanction_category=s.get("sanction_category"),
            )
            for s in args["subjects"]
        ]
        draft = self._sar_generator.generate_draft(
            case_id=args["case_id"],
            findings=args["findings"],
            subjects=subjects,
            transactions=args["transactions"],
        )
        return {
            "report_id": draft.report_id,
            "status": draft.status.value,
            "jurisdiction": draft.jurisdiction.value,
            "draft_digest": draft.draft_digest,
            "requires_human_approval": draft.requires_human_approval,
            "filing_channel": draft.filing_channel,
            "case_summary": draft.case_summary,
            "narrative": draft.narrative,
        }

    def _handle_verify_zk(self, args: Dict[str, Any]) -> Dict[str, Any]:
        p = args["proof"]
        proof_obj = ComplianceProof(
            proof_id=p["proof_id"],
            nullifier_hash=p["nullifier_hash"],
            address_commitment=p["address_commitment"],
            volume_commitment=p["volume_commitment"],
            max_threshold_wei=int(p["max_threshold_wei"]),
            merkle_root=p["merkle_root"],
            challenge=p["challenge"],
            response_signature=p["response_signature"],
            is_sanctions_free=bool(p["is_sanctions_free"]),
        )
        valid = self._zk_attestor.verify_attestation(proof_obj)
        return {"is_valid": valid, "proof_id": proof_obj.proof_id}
