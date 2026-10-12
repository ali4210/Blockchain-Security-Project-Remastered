"""
Task P13-006: Unit tests for Compliance Graph Integrator.
Validates:
1. Screening matches mapped to canonical SwarmState findings.
2. AML findings integrated with Zone 8 tags and metadata summaries.
3. Clean/empty compliance inputs preserve existing state without mutation.
4. ZK attestation verification records populated in state metadata.
"""

import unittest

from src.agents.state import SwarmState
from src.compliance.graph_integrator import ComplianceGraphIntegrator
from src.compliance.address_screener import ScreeningMatch, RiskTier, SanctionEntry
from src.compliance.aml_detector import AMLFinding, AMLRiskType


class TestComplianceGraphIntegrator(unittest.TestCase):
    def setUp(self):
        self.integrator = ComplianceGraphIntegrator()
        self.initial_state = SwarmState(
            target_contract="0xTestContract",
            findings=[],
            current_stage="compliance_analysis",
            escalation_needed=False,
            errors=[],
            metadata={},
        )

    def test_enrich_screening_matches_adds_findings_and_metadata(self):
        match = ScreeningMatch(
            is_flagged=True,
            risk_tier=RiskTier.CRITICAL_SANCTIONED,
            risk_score=1.0,
            matched_address="0x098b716b8aaf21512996dc57eb0615e2383e2f96",
            matched_entry=SanctionEntry(
                address="0x098b716b8aaf21512996dc57eb0615e2383e2f96",
                entity_name="Ronin Bridge Exploiter",
                category="OFAC_SDN",
                source_list="OFAC_SPEC_DESIGNATED",
                added_date="2022-04-14",
                risk_score=1.0,
            ),
            reason="Sanctions match",
        )

        state = self.integrator.enrich_screening_matches(self.initial_state, [match])
        self.assertEqual(len(state["findings"]), 1)
        finding = state["findings"][0]
        self.assertEqual(finding["zone"], "ZONE_8_COMPLIANCE")
        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertEqual(finding["compliance_category"], "SANCTIONS_HIT")
        self.assertEqual(finding["target_address"], match.matched_address)

        summary = state["metadata"].get("compliance_summary", {})
        self.assertEqual(summary.get("sanctions_flagged_count"), 1)

    def test_clean_screening_match_does_not_add_findings(self):
        clean_match = ScreeningMatch(
            is_flagged=False,
            risk_tier=RiskTier.LOW_CLEAN,
            risk_score=0.0,
            matched_address="0x742d35cc6634c0532925a3b844bc454e4438f44e",
            reason="Clean",
        )

        state = self.integrator.enrich_screening_matches(self.initial_state, [clean_match])
        self.assertEqual(len(state["findings"]), 0)
        summary = state["metadata"].get("compliance_summary", {})
        self.assertEqual(summary.get("sanctions_flagged_count"), 0)

    def test_enrich_aml_findings_sets_sar_candidate_flag(self):
        aml = AMLFinding(
            rule_id="RULE-AML-001",
            risk_type=AMLRiskType.STRUCTURING,
            severity="HIGH",
            confidence=0.85,
            involved_addresses=["0xSmurfer"],
            evidence_tx_hashes=["0xTx1", "0xTx2"],
            description="Structuring detected",
        )

        state = self.integrator.enrich_aml_findings(self.initial_state, [aml])
        self.assertEqual(len(state["findings"]), 1)
        finding = state["findings"][0]
        self.assertEqual(finding["zone"], "ZONE_8_COMPLIANCE")
        self.assertEqual(finding["compliance_category"], "STRUCTURING")

        summary = state["metadata"].get("compliance_summary", {})
        self.assertEqual(summary.get("aml_findings_count"), 1)
        self.assertTrue(summary.get("draft_sar_candidate"))

    def test_enrich_zk_attestation_status_updates_metadata(self):
        state = self.integrator.enrich_zk_attestation_status(
            self.initial_state,
            proof_id="ZK-PROOF-001",
            is_valid=True,
            merkle_root="0xRoot123",
        )

        summary = state["metadata"].get("compliance_summary", {})
        self.assertEqual(summary.get("last_zk_proof_id"), "ZK-PROOF-001")
        self.assertTrue(summary.get("last_zk_verified"))
        self.assertEqual(summary.get("merkle_root"), "0xRoot123")


if __name__ == "__main__":
    unittest.main()
