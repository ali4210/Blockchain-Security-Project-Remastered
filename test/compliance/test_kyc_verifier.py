"""Unit tests for the Compliance KYC/AML Name Screener.

These test the matching ENGINE deterministically by injecting records via
snapshot_records=, so they never depend on the live, changing OpenSanctions
snapshot. A separate, skipped-by-default smoke test exercises the real
snapshot when one is present (run with KYC_SNAPSHOT_SMOKE=1).

Validates:
1. Name normalization (case/punctuation/whitespace).
2. Exact name and alias matching -> CONFIRMED.
3. Clean verdicts for unrelated names -> NO_MATCH.
4. Ambiguous partial/substring overlap -> INCONCLUSIVE (not silently CONFIRMED
   and not silently dropped as clean).
5. Batch screening determinism and snapshot fingerprint reproducibility.
6. Missing/stale snapshot raises OpenSanctionsSnapshotUnavailable (never a
   fake clean).
7. The HITL draft-review generator: only flagged matches get a draft, every
   draft starts DRAFT_PENDING_REVIEW/requires_human_approval=True, and its
   digest verifies.
"""
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from src.compliance.kyc_verifier import (
    KycReviewGenerator,
    KycReviewStatus,
    KycScreener,
    MatchConfidence,
    OpenSanctionsSnapshotUnavailable,
    normalize_name,
)

# Injected test fixtures -- NOT the live OpenSanctions list.
TEST_RECORDS = [
    {"id": "NK-001", "schema": "Organization", "name": "Lazarus Group",
     "aliases": ["APT38", "Hidden Cobra"], "countries": ["kp"],
     "sanctions": "US OFAC SDN List", "program_ids": ["US-NK"], "dataset": "US OFAC SDN"},
    {"id": "ZW-002", "schema": "Person", "name": "Lazarus Dokora",
     "aliases": [], "countries": ["zw"],
     "sanctions": "Zimbabwe sanctions", "program_ids": ["CA-SEMA"], "dataset": "Canadian Sanctions List"},
]


class TestKycScreener(unittest.TestCase):
    def setUp(self):
        self.screener = KycScreener(snapshot_records=TEST_RECORDS)

    def test_normalize_collapses_case_punctuation_whitespace(self):
        self.assertEqual(normalize_name("  Lazarus,  Group.  "), "LAZARUS GROUP")
        self.assertEqual(normalize_name("lazarus group"), "LAZARUS GROUP")

    def test_exact_name_match_is_confirmed(self):
        res = self.screener.screen("Lazarus Group")
        self.assertTrue(res.is_flagged)
        self.assertEqual(res.confidence, MatchConfidence.CONFIRMED)
        self.assertEqual(res.score, 1.0)
        self.assertIsNotNone(res.matched_entity)
        self.assertEqual(res.matched_entity.name, "Lazarus Group")

    def test_alias_match_is_confirmed(self):
        res = self.screener.screen("APT38")
        self.assertTrue(res.is_flagged)
        self.assertEqual(res.confidence, MatchConfidence.CONFIRMED)
        self.assertEqual(res.matched_entity.name, "Lazarus Group")

    def test_clean_name_returns_no_match(self):
        res = self.screener.screen("Harriet Quilborne-Fenwick")
        self.assertFalse(res.is_flagged)
        self.assertEqual(res.confidence, MatchConfidence.NO_MATCH)
        self.assertIsNone(res.matched_entity)
        self.assertIn("Clean", res.reason)

    def test_ambiguous_substring_overlap_is_inconclusive_not_confirmed(self):
        # "Lazarus" alone overlaps two unrelated real entities ("Lazarus
        # Group" and "Lazarus Dokora") -- this must never silently become a
        # CONFIRMED hit on either, and must never be silently dropped clean.
        res = self.screener.screen("Lazarus")
        self.assertTrue(res.is_flagged)
        self.assertEqual(res.confidence, MatchConfidence.INCONCLUSIVE)
        self.assertIsNotNone(res.matched_entity)
        self.assertIn("human review", res.reason)

    def test_screen_batch_returns_ordered_matches(self):
        batch = ["Lazarus Group", "Harriet Quilborne-Fenwick", "APT38"]
        results = self.screener.screen_batch(batch)
        self.assertEqual(len(results), 3)
        self.assertTrue(results[0].is_flagged)
        self.assertFalse(results[1].is_flagged)
        self.assertTrue(results[2].is_flagged)

    def test_snapshot_hash_is_deterministic(self):
        s1 = KycScreener(snapshot_records=TEST_RECORDS)
        s2 = KycScreener(snapshot_records=TEST_RECORDS)
        self.assertEqual(s1.snapshot_hash, s2.snapshot_hash)
        self.assertEqual(len(s1.snapshot_hash), 64)


class TestSnapshotUnavailable(unittest.TestCase):
    def test_missing_snapshot_refuses(self):
        with self.assertRaises(OpenSanctionsSnapshotUnavailable):
            KycScreener(snapshot_path=Path("/nonexistent/opensanctions-snapshot.json"))

    def test_stale_snapshot_refuses(self):
        d = tempfile.mkdtemp()
        path = Path(d) / "snap.json"
        old = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
        path.write_text(json.dumps(
            {"downloaded_at": old, "entries": [{"id": "x", "name": "x"}]}))
        with self.assertRaises(OpenSanctionsSnapshotUnavailable):
            KycScreener(snapshot_path=path, max_age_days=90)


class TestKycReviewGenerator(unittest.TestCase):
    def setUp(self):
        self.screener = KycScreener(snapshot_records=TEST_RECORDS)
        self.generator = KycReviewGenerator()

    def test_confirmed_match_produces_draft_pending_review(self):
        match = self.screener.screen("Lazarus Group")
        draft = self.generator.generate_draft("CASE-1", match)
        self.assertEqual(draft.status, KycReviewStatus.DRAFT_PENDING_REVIEW)
        self.assertTrue(draft.requires_human_approval)
        self.assertEqual(draft.action_channel, "LOCAL_STAGING_ONLY")
        self.assertTrue(KycReviewGenerator.verify_draft_integrity(draft))

    def test_inconclusive_match_also_produces_draft(self):
        match = self.screener.screen("Lazarus")
        draft = self.generator.generate_draft("CASE-2", match)
        self.assertEqual(draft.confidence, MatchConfidence.INCONCLUSIVE)
        self.assertEqual(draft.status, KycReviewStatus.DRAFT_PENDING_REVIEW)

    def test_clean_match_refuses_to_generate_a_draft(self):
        match = self.screener.screen("Harriet Quilborne-Fenwick")
        with self.assertRaises(ValueError):
            self.generator.generate_draft("CASE-3", match)

    def test_tampered_draft_fails_integrity_check(self):
        match = self.screener.screen("Lazarus Group")
        draft = self.generator.generate_draft("CASE-4", match)
        tampered = draft.__class__(**{**draft.__dict__, "score": 0.42})
        self.assertFalse(KycReviewGenerator.verify_draft_integrity(tampered))


@unittest.skipUnless(os.getenv("KYC_SNAPSHOT_SMOKE") == "1",
                     "set KYC_SNAPSHOT_SMOKE=1 to screen against the real local snapshot")
class TestRealSnapshotSmoke(unittest.TestCase):
    def test_real_snapshot_loads_and_flags_known_entry(self):
        s = KycScreener()  # real snapshot from mirror-opensanctions.py
        self.assertGreater(s.total_entities(), 0)
        # Lazarus Group was present in the real OpenSanctions sanctions
        # collection when the snapshot was written -- verified live, not assumed.
        res = s.screen("Lazarus Group")
        self.assertTrue(res.is_flagged)
        self.assertEqual(res.confidence, MatchConfidence.CONFIRMED)

    def test_real_snapshot_clean_control_is_not_flagged(self):
        s = KycScreener()
        res = s.screen("Harriet Quilborne-Fenwick")
        self.assertFalse(res.is_flagged)


if __name__ == "__main__":
    unittest.main()
