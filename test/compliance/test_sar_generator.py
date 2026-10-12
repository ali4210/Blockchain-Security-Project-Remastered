"""
Task P13-004: Unit tests for Draft SAR Report Generator.
Validates:
1. Deterministic generation of draft SAR reports.
2. Invariant: Status pinned to DRAFT_PENDING_REVIEW with human approval required.
3. Invariant: Filing channel pinned to LOCAL_STAGING_ONLY.
4. Cryptographic draft digest verification and tamper detection.
5. Typology and narrative structuring accuracy.
"""

import unittest

from src.compliance.sar_generator import (
    SARReportGenerator,
    ReportStatus,
    RegulatoryJurisdiction,
    InvolvedSubject,
    DraftSAR,
)


class TestSARReportGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = SARReportGenerator(jurisdiction=RegulatoryJurisdiction.FINCEN_US)
        self.sample_subjects = [
            InvolvedSubject(
                address="0x098b716b8aaf21512996dc57eb0615e2383e2f96",
                role="RECIPIENT",
                risk_tier="CRITICAL_SANCTIONED",
                sanction_category="OFAC_SDN",
            ),
            InvolvedSubject(
                address="0xsmurfingactor00000000000000000000000001",
                role="SENDER",
                risk_tier="HIGH_RISK",
            ),
        ]
        self.sample_findings = [
            {
                "rule_id": "RULE-AML-001",
                "risk_type": "STRUCTURING",
                "description": "Detected 2 transactions just below reporting threshold within 600s.",
            },
            {
                "rule_id": "RULE-AML-002",
                "risk_type": "MIXER_INTERACTION",
                "description": "Direct interaction with sanctioned mixer contract.",
            },
        ]
        self.sample_txs = [
            {"tx_hash": "0x1111", "value_wei": 9 * 10**18},
            {"tx_hash": "0x2222", "value_wei": 95 * 10**17},
        ]

    def test_generate_draft_pins_status_and_hitl_invariants(self):
        draft = self.generator.generate_draft(
            case_id="CASE-2026-001",
            findings=self.sample_findings,
            subjects=self.sample_subjects,
            transactions=self.sample_txs,
            created_at_override="2026-10-12T12:00:00Z",
        )

        # Invariant checks
        self.assertEqual(draft.status, ReportStatus.DRAFT_PENDING_REVIEW)
        self.assertTrue(draft.requires_human_approval)
        self.assertEqual(draft.filing_channel, "LOCAL_STAGING_ONLY")
        self.assertEqual(draft.report_id, "SAR-DRAFT-CASE-2026-001")
        self.assertIn("GOVERNANCE NOTICE", draft.narrative)
        self.assertEqual(draft.total_suspicious_volume_wei, 185 * 10**17)

    def test_draft_integrity_verification_succeeds(self):
        draft = self.generator.generate_draft(
            case_id="CASE-2026-002",
            findings=self.sample_findings,
            subjects=self.sample_subjects,
            transactions=self.sample_txs,
            created_at_override="2026-10-12T12:00:00Z",
        )
        self.assertTrue(SARReportGenerator.verify_draft_integrity(draft))

    def test_tampered_draft_fails_integrity_verification(self):
        draft = self.generator.generate_draft(
            case_id="CASE-2026-003",
            findings=self.sample_findings,
            subjects=self.sample_subjects,
            transactions=self.sample_txs,
            created_at_override="2026-10-12T12:00:00Z",
        )

        tampered_draft = DraftSAR(
            report_id=draft.report_id,
            created_at_utc=draft.created_at_utc,
            status=draft.status,
            jurisdiction=draft.jurisdiction,
            case_summary=draft.case_summary,
            typologies_detected=draft.typologies_detected,
            subjects=draft.subjects,
            transaction_hashes=draft.transaction_hashes,
            total_suspicious_volume_wei=0,  # Tampered volume
            narrative=draft.narrative,
            draft_digest=draft.draft_digest,
            requires_human_approval=draft.requires_human_approval,
            filing_channel=draft.filing_channel,
        )

        self.assertFalse(SARReportGenerator.verify_draft_integrity(tampered_draft))

    def test_deterministic_reproducibility(self):
        draft1 = self.generator.generate_draft(
            case_id="CASE-REPEAT",
            findings=self.sample_findings,
            subjects=self.sample_subjects,
            transactions=self.sample_txs,
            created_at_override="2026-10-12T12:00:00Z",
        )
        draft2 = self.generator.generate_draft(
            case_id="CASE-REPEAT",
            findings=self.sample_findings,
            subjects=self.sample_subjects,
            transactions=self.sample_txs,
            created_at_override="2026-10-12T12:00:00Z",
        )

        self.assertEqual(draft1.draft_digest, draft2.draft_digest)
        self.assertEqual(draft1.narrative, draft2.narrative)


if __name__ == "__main__":
    unittest.main()
