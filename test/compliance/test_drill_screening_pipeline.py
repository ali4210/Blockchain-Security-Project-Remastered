"""
Task P13-010: Incident Drill - Continuous Address Screening and Draft Report Generation.
Simulates an end-to-end incident drill:
1. Ingest authorized public test-risk addresses and clean accounts.
2. Execute continuous screening and detect AML typologies.
3. Enrich Zone 3 SwarmState graph findings.
4. Generate deterministic draft SAR report with SHA-256 digest pinning.
5. Assert fail-closed containment (DRAFT_PENDING_REVIEW, LOCAL_STAGING_ONLY, zero egress).
"""

import time
import unittest

from src.agents.state import SwarmState
from src.compliance.address_screener import AddressScreener, RiskTier
from src.compliance.aml_detector import AMLDetector, AMLTransaction, AMLRiskType
from src.compliance.graph_integrator import ComplianceGraphIntegrator
from src.compliance.sar_generator import SARReportGenerator, InvolvedSubject, ReportStatus
from src.compliance.compliance_policy import CompliancePolicyEngine


class TestDrillScreeningPipeline(unittest.TestCase):
    def setUp(self):
        self.screener = AddressScreener()
        self.aml_detector = AMLDetector()
        self.graph_integrator = ComplianceGraphIntegrator()
        self.sar_generator = SARReportGenerator()
        self.policy_engine = CompliancePolicyEngine()
        self.now = time.time()

        # Authorized public test risk fixtures
        self.ronin_exploiter = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
        self.tornado_router = "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b"
        self.clean_user = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        self.intermediary_a = "0x1111111111111111111111111111111111111111"

    def test_full_compliance_drill_pipeline_end_to_end(self):
        # ---------------------------------------------------------
        # Phase 1: Ingestion & Continuous Screening
        # ---------------------------------------------------------
        batch_to_screen = [self.ronin_exploiter, self.clean_user, self.tornado_router]
        screen_results = self.screener.screen_batch(batch_to_screen)

        self.assertEqual(len(screen_results), 3)
        self.assertTrue(screen_results[0].is_flagged)
        self.assertEqual(screen_results[0].risk_tier, RiskTier.CRITICAL_SANCTIONED)
        self.assertFalse(screen_results[1].is_flagged)
        self.assertEqual(screen_results[1].risk_tier, RiskTier.LOW_CLEAN)
        self.assertTrue(screen_results[2].is_flagged)
        self.assertEqual(screen_results[2].risk_tier, RiskTier.CRITICAL_SANCTIONED)

        # ---------------------------------------------------------
        # Phase 2: Telemetry Correlation & AML Detection
        # ---------------------------------------------------------
        # Simulated telemetry: Infiltration -> Intermediary -> Tornado Router (Mixer hit + Layering)
        tx_telemetry = [
            AMLTransaction(
                tx_hash="0xDrillTx1",
                sender=self.ronin_exploiter,
                recipient=self.intermediary_a,
                value_wei=10**19,
                timestamp=self.now,
                block_number=5000,
            ),
            AMLTransaction(
                tx_hash="0xDrillTx2",
                sender=self.intermediary_a,
                recipient=self.tornado_router,
                value_wei=98 * 10**17,
                timestamp=self.now + 45,  # 45s holding time (rapid hop)
                block_number=5003,
            ),
        ]

        aml_findings = self.aml_detector.analyze_batch(tx_telemetry)
        # Should detect direct mixer interaction on tx2
        mixer_hits = [f for f in aml_findings if f.risk_type == AMLRiskType.MIXER_INTERACTION]
        self.assertGreaterEqual(len(mixer_hits), 1)
        self.assertEqual(mixer_hits[0].severity, "CRITICAL")

        # ---------------------------------------------------------
        # Phase 3: State Graph Enrichment
        # ---------------------------------------------------------
        initial_state = SwarmState(
            target_contract=self.ronin_exploiter,
            findings=[],
            current_stage="compliance_drill",
            escalation_needed=False,
            errors=[],
            metadata={},
        )

        state_after_screening = self.graph_integrator.enrich_screening_matches(
            initial_state, screen_results
        )
        state_after_aml = self.graph_integrator.enrich_aml_findings(
            state_after_screening, aml_findings
        )

        self.assertGreaterEqual(len(state_after_aml["findings"]), 2)
        compliance_zones = {f.get("zone") for f in state_after_aml["findings"]}
        self.assertIn("ZONE_8_COMPLIANCE", compliance_zones)

        comp_summary = state_after_aml["metadata"].get("compliance_summary", {})
        self.assertEqual(comp_summary.get("sanctions_flagged_count"), 2)
        self.assertTrue(comp_summary.get("draft_sar_candidate"))

        # ---------------------------------------------------------
        # Phase 4: Draft SAR Generation & Digest Pinning
        # ---------------------------------------------------------
        subjects = [
            InvolvedSubject(
                address=self.ronin_exploiter,
                role="SENDER",
                risk_tier="CRITICAL_SANCTIONED",
                sanction_category="OFAC_SDN",
            ),
            InvolvedSubject(
                address=self.tornado_router,
                role="RECIPIENT",
                risk_tier="CRITICAL_SANCTIONED",
                sanction_category="OFAC_SDN",
            ),
        ]
        raw_tx_dicts = [
            {"tx_hash": t.tx_hash, "value_wei": t.value_wei} for t in tx_telemetry
        ]

        draft_sar = self.sar_generator.generate_draft(
            case_id="DRILL-INCIDENT-001",
            findings=[
                {"rule_id": f.rule_id, "risk_type": f.risk_type.value, "description": f.description}
                for f in aml_findings
            ],
            subjects=subjects,
            transactions=raw_tx_dicts,
            created_at_override="2026-10-12T12:00:00Z",
        )

        # Assert cryptographic draft digest integrity
        self.assertTrue(SARReportGenerator.verify_draft_integrity(draft_sar))

        # ---------------------------------------------------------
        # Phase 5: Containment & Boundary Enforcements
        # ---------------------------------------------------------
        # 1. State pinned to draft
        self.assertEqual(draft_sar.status, ReportStatus.DRAFT_PENDING_REVIEW)
        # 2. Local staging only
        self.assertEqual(draft_sar.filing_channel, "LOCAL_STAGING_ONLY")
        self.assertTrue(draft_sar.requires_human_approval)

        # 3. Autonomous agents fail-closed on approval/filing
        for agent in ["agent_b_threat_hunter", "agent_c_compliance_judge", "agent_g_guardrail"]:
            eval_res = self.policy_engine.evaluate({
                "principal": agent,
                "action": "file_sar_report",
                "current_timestamp": self.now,
                "token": None,
            })
            self.assertFalse(eval_res["allow"])

        # 4. Universal denial of on-chain transaction inclusion blocking
        block_eval = self.policy_engine.evaluate({
            "principal": "agent_e_incident_commander",
            "action": "block_transaction_inclusion",
            "current_timestamp": self.now,
        })
        self.assertFalse(block_eval["allow"])


if __name__ == "__main__":
    unittest.main()
