"""Unit tests for the Compliance Address Screener.

These test the matching ENGINE deterministically by injecting records via
snapshot_records=, so they never depend on the live, changing OFAC snapshot.
A separate, skipped-by-default smoke test exercises the real snapshot when one
is present (run with OFAC_SNAPSHOT_SMOKE=1).

Validates:
1. Normalization of varied address formats (and that case-sensitive non-ETH
   addresses are left untouched).
2. Exact matching and risk tiers against injected records.
3. Clean verdicts for non-listed addresses.
4. Batch screening determinism.
5. Snapshot fingerprint reproducibility.
6. Missing/stale snapshot raises SnapshotUnavailable (never a fake clean).
"""
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from src.compliance.address_screener import (
    AddressScreener,
    RiskTier,
    SnapshotUnavailable,
    normalize_address,
)

# Injected test fixtures — NOT the live OFAC list.
TEST_RECORDS = [
    {"address": "0x098B716B8Aaf21512996dC57EB0615e2383E2f96",
     "entity_name": "LAZARUS GROUP", "currency": "ETH", "risk_score": 1.0},
    {"address": "0x72a5843cc08275C80f0A307B6e804f5D51543884",
     "entity_name": "High-Risk P2P Gateway", "currency": "ETH", "risk_score": 0.75},
]


class TestAddressScreener(unittest.TestCase):
    def setUp(self):
        self.screener = AddressScreener(snapshot_records=TEST_RECORDS)

    def test_normalize_eth_handles_casing_and_prefixes(self):
        mixed = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
        no_prefix = "098b716b8aaf21512996dc57eb0615e2383e2f96"
        self.assertEqual(normalize_address(mixed), mixed.lower())
        self.assertEqual(normalize_address(no_prefix), mixed.lower())

    def test_normalize_preserves_case_sensitive_btc(self):
        # Bitcoin addresses are case-sensitive and must not be lowercased.
        btc = "1P5ZEDWTKTFGxQjZphgWPQUpe554WKDfHQ"
        self.assertEqual(normalize_address(btc), btc)

    def test_sanctioned_address_match_critical(self):
        res = self.screener.screen("0x098B716B8Aaf21512996dC57EB0615e2383E2f96")
        self.assertTrue(res.is_flagged)
        self.assertEqual(res.risk_tier, RiskTier.CRITICAL_SANCTIONED)
        self.assertEqual(res.risk_score, 1.0)
        self.assertIsNotNone(res.matched_entry)
        self.assertEqual(res.matched_entry.entity_name, "LAZARUS GROUP")
        self.assertIn("OFAC_SDN", res.matched_entry.source_list)

    def test_high_risk_tier(self):
        res = self.screener.screen("0x72a5843cc08275C80f0A307B6e804f5D51543884")
        self.assertTrue(res.is_flagged)
        self.assertEqual(res.risk_tier, RiskTier.HIGH_RISK)

    def test_clean_address_returns_low_clean(self):
        res = self.screener.screen("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
        self.assertFalse(res.is_flagged)
        self.assertEqual(res.risk_tier, RiskTier.LOW_CLEAN)
        self.assertEqual(res.risk_score, 0.0)
        self.assertIsNone(res.matched_entry)
        self.assertIn("Clean", res.reason)

    def test_screen_batch_returns_ordered_matches(self):
        batch = [
            "0x098B716B8Aaf21512996dC57EB0615e2383E2f96",  # flagged (critical)
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",  # clean
            "0x72a5843cc08275C80f0A307B6e804f5D51543884",  # flagged (high risk)
        ]
        results = self.screener.screen_batch(batch)
        self.assertEqual(len(results), 3)
        self.assertTrue(results[0].is_flagged)
        self.assertFalse(results[1].is_flagged)
        self.assertTrue(results[2].is_flagged)
        self.assertEqual(results[2].risk_tier, RiskTier.HIGH_RISK)

    def test_snapshot_hash_is_deterministic(self):
        s1 = AddressScreener(snapshot_records=TEST_RECORDS)
        s2 = AddressScreener(snapshot_records=TEST_RECORDS)
        self.assertEqual(s1.snapshot_hash, s2.snapshot_hash)
        self.assertEqual(len(s1.snapshot_hash), 64)


class TestSnapshotUnavailable(unittest.TestCase):
    def test_missing_snapshot_refuses(self):
        with self.assertRaises(SnapshotUnavailable):
            AddressScreener(snapshot_path=Path("/nonexistent/ofac-snapshot.json"))

    def test_stale_snapshot_refuses(self):
        d = tempfile.mkdtemp()
        path = Path(d) / "snap.json"
        old = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
        path.write_text(json.dumps(
            {"downloaded_at": old, "entries": [{"address": "0xabc", "entity_name": "x"}]}))
        with self.assertRaises(SnapshotUnavailable):
            AddressScreener(snapshot_path=path, max_age_days=30)


@unittest.skipUnless(os.getenv("OFAC_SNAPSHOT_SMOKE") == "1",
                     "set OFAC_SNAPSHOT_SMOKE=1 to screen against the real local snapshot")
class TestRealSnapshotSmoke(unittest.TestCase):
    def test_real_snapshot_loads_and_flags_known_entry(self):
        s = AddressScreener()  # real snapshot from mirror-ofac.py
        self.assertGreater(s.total_entries(), 0)
        # Lazarus/Ronin address was present in the real SDN list when written.
        res = s.screen("0x098B716B8Aaf21512996dC57EB0615e2383E2f96")
        self.assertTrue(res.is_flagged)


if __name__ == "__main__":
    unittest.main()
