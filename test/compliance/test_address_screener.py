"""
Task P13-001: Unit tests for Compliance Address Screener.
Validates:
1. Normalization of varied address formats.
2. Exact matching against known OFAC / high-risk lists.
3. Clean verdicts for non-sanctioned addresses.
4. Batch screening deterministic execution.
5. Snapshot SHA-256 fingerprint reproducibility.
"""

import unittest

from src.compliance.address_screener import (
    AddressScreener,
    RiskTier,
    normalize_address,
)


class TestAddressScreener(unittest.TestCase):
    def setUp(self):
        self.screener = AddressScreener()

    def test_normalize_address_handles_casing_and_prefixes(self):
        addr_mixed = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
        addr_no_prefix = "098b716b8aaf21512996dc57eb0615e2383e2f96"
        self.assertEqual(normalize_address(addr_mixed), addr_mixed.lower())
        self.assertEqual(normalize_address(addr_no_prefix), addr_mixed.lower())

    def test_sanctioned_address_match_critical(self):
        # Ronin Bridge Exploiter address
        addr = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
        res = self.screener.screen(addr)

        self.assertTrue(res.is_flagged)
        self.assertEqual(res.risk_tier, RiskTier.CRITICAL_SANCTIONED)
        self.assertEqual(res.risk_score, 1.0)
        self.assertIsNotNone(res.matched_entry)
        self.assertEqual(res.matched_entry.entity_name, "Ronin Bridge Exploiter")
        self.assertIn("OFAC_SDN", res.matched_entry.category)

    def test_tornado_cash_router_match_critical(self):
        addr = "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b"
        res = self.screener.screen(addr)

        self.assertTrue(res.is_flagged)
        self.assertEqual(res.risk_tier, RiskTier.CRITICAL_SANCTIONED)
        self.assertEqual(res.matched_entry.entity_name, "Tornado Cash Router")

    def test_clean_address_returns_low_clean(self):
        clean_addr = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        res = self.screener.screen(clean_addr)

        self.assertFalse(res.is_flagged)
        self.assertEqual(res.risk_tier, RiskTier.LOW_CLEAN)
        self.assertEqual(res.risk_score, 0.0)
        self.assertIsNone(res.matched_entry)
        self.assertIn("Clean", res.reason)

    def test_screen_batch_returns_ordered_matches(self):
        batch = [
            "0x098B716B8Aaf21512996dC57EB0615e2383E2f96",  # Flagged
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",  # Clean
            "0x72a5843cc08275C80f0A307B6e804f5D51543884",  # High Risk P2P
        ]
        results = self.screener.screen_batch(batch)

        self.assertEqual(len(results), 3)
        self.assertTrue(results[0].is_flagged)
        self.assertFalse(results[1].is_flagged)
        self.assertTrue(results[2].is_flagged)
        self.assertEqual(results[2].risk_tier, RiskTier.HIGH_RISK)

    def test_snapshot_hash_is_deterministic(self):
        screener1 = AddressScreener()
        screener2 = AddressScreener()
        self.assertEqual(screener1.snapshot_hash, screener2.snapshot_hash)
        self.assertEqual(len(screener1.snapshot_hash), 64)


if __name__ == "__main__":
    unittest.main()
