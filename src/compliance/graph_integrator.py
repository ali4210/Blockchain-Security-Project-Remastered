"""
Task P13-006: Compliance Graph Integrator for Zone 3 Swarm State.
Integrates address screening hits, AML typology findings, and ZK attestation
metadata into the LangGraph SwarmState without disrupting core graph flow.
"""

from typing import Any, Dict, List, Optional
import copy

from src.agents.state import SwarmState
from src.compliance.address_screener import ScreeningMatch, RiskTier
from src.compliance.aml_detector import AMLFinding, AMLRiskType


class ComplianceGraphIntegrator:
    """
    Enriches SwarmState with compliance findings tagged for Zone 8 regulatory governance.
    """

    def __init__(self, zone_tag: str = "ZONE_8_COMPLIANCE"):
        self.zone_tag = zone_tag

    def enrich_screening_matches(
        self,
        state: SwarmState,
        screening_matches: List[ScreeningMatch],
    ) -> SwarmState:
        """
        Translates screening matches into canonical SwarmState findings.
        """
        new_findings: List[Dict[str, Any]] = list(state.get("findings", []))
        flagged_count = 0

        for match in screening_matches:
            if not match.is_flagged:
                continue

            flagged_count += 1
            severity = (
                "CRITICAL"
                if match.risk_tier == RiskTier.CRITICAL_SANCTIONED
                else "HIGH"
                if match.risk_tier == RiskTier.HIGH_RISK
                else "MEDIUM"
            )

            category = match.matched_entry.category if match.matched_entry else "SANCTIONS_REGISTRY"
            entity_name = match.matched_entry.entity_name if match.matched_entry else "Unknown Entity"

            finding = {
                "finding_id": f"FINDING-COMPLIANCE-SCREEN-{match.matched_address[:10]}",
                "rule_id": "RULE-COMPLIANCE-001",
                "severity": severity,
                "zone": self.zone_tag,
                "compliance_category": "SANCTIONS_HIT",
                "target_address": match.matched_address,
                "risk_score": match.risk_score,
                "description": f"Address {match.matched_address} flagged: {match.reason} ({entity_name} - {category})",
                "details": {
                    "entity_name": entity_name,
                    "category": category,
                    "risk_tier": match.risk_tier.value,
                },
            }
            new_findings.append(finding)

        metadata = dict(state.get("metadata", {}))
        comp_summary = dict(metadata.get("compliance_summary", {}))
        comp_summary["sanctions_flagged_count"] = comp_summary.get("sanctions_flagged_count", 0) + flagged_count
        metadata["compliance_summary"] = comp_summary

        return {
            **state,
            "findings": new_findings,
            "metadata": metadata,
        }

    def enrich_aml_findings(
        self,
        state: SwarmState,
        aml_findings: List[AMLFinding],
    ) -> SwarmState:
        """
        Translates AML typology detections into canonical SwarmState findings.
        """
        new_findings: List[Dict[str, Any]] = list(state.get("findings", []))

        for aml in aml_findings:
            finding = {
                "finding_id": f"FINDING-COMPLIANCE-AML-{aml.rule_id}",
                "rule_id": aml.rule_id,
                "severity": aml.severity,
                "zone": self.zone_tag,
                "compliance_category": aml.risk_type.value,
                "target_addresses": aml.involved_addresses,
                "confidence": aml.confidence,
                "evidence_tx_hashes": aml.evidence_tx_hashes,
                "description": aml.description,
                "details": {
                    "risk_type": aml.risk_type.value,
                    "tx_count": len(aml.evidence_tx_hashes),
                },
            }
            new_findings.append(finding)

        metadata = dict(state.get("metadata", {}))
        comp_summary = dict(metadata.get("compliance_summary", {}))
        comp_summary["aml_findings_count"] = comp_summary.get("aml_findings_count", 0) + len(aml_findings)
        comp_summary["draft_sar_candidate"] = comp_summary.get("draft_sar_candidate", False) or (len(aml_findings) > 0)
        metadata["compliance_summary"] = comp_summary

        return {
            **state,
            "findings": new_findings,
            "metadata": metadata,
        }

    def enrich_zk_attestation_status(
        self,
        state: SwarmState,
        proof_id: str,
        is_valid: bool,
        merkle_root: str,
    ) -> SwarmState:
        """
        Enriches SwarmState with zero-knowledge attestation verification results.
        """
        metadata = dict(state.get("metadata", {}))
        comp_summary = dict(metadata.get("compliance_summary", {}))
        comp_summary["last_zk_proof_id"] = proof_id
        comp_summary["last_zk_verified"] = is_valid
        comp_summary["merkle_root"] = merkle_root
        metadata["compliance_summary"] = comp_summary

        return {
            **state,
            "metadata": metadata,
        }
