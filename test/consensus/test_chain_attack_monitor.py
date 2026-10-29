"""
Section A unit tests: chain_attack_monitor.py's finding-builder functions,
exercised with synthetic/fabricated detector outputs (a fabricated ReorgEvent,
a fabricated concentrated-miner distribution, a fabricated concentrated peer
set, and a real SelfishMiningDetector fed a crafted orphan-rate sequence) --
NOT a live Anvil run. The underlying detector classes (ChainReorgMonitor,
ConsensusConcentrationTracker, P2PEclipseDetector, SelfishMiningDetector)
already have their own passing unit tests elsewhere in this directory; this
file tests only the new orchestration/schema-building logic added in
chain_attack_monitor.py.
"""
import unittest

from src.consensus.chain_attack_monitor import (
    SAFE_REORG_DEPTH,
    build_reorg_finding,
    build_concentration_findings,
    build_eclipse_findings,
    build_selfish_mining_finding,
    build_demo_peers,
)
from src.consensus.reorg_monitor import ReorgEvent, ReorgSeverity
from src.consensus.concentration_tracker import ConsensusConcentrationTracker
from src.consensus.eclipse_detector import P2PEclipseDetector
from src.consensus.p2p_listener import PeerInfo
from src.consensus.selfish_mining_detector import SelfishMiningDetector


class TestReorgFinding(unittest.TestCase):
    def test_fabricated_deep_reorg_triggers(self):
        event = ReorgEvent(
            event_id="fabricated-1", reorg_depth=SAFE_REORG_DEPTH + 1,
            common_ancestor_hash="0xaa", common_ancestor_number=3,
            old_canonical_tip="0xbb", new_canonical_tip="0xcc",
            orphaned_block_hashes=["0xbb"], new_canonical_block_hashes=["0xcc"],
            severity=ReorgSeverity.CRITICAL_FINALITY_VIOLATION, timestamp=0.0,
        )
        finding = build_reorg_finding(event)
        self.assertTrue(finding["triggered"])
        self.assertEqual(finding["observed_value"], SAFE_REORG_DEPTH + 1)
        self.assertEqual(finding["severity"], "CRITICAL_FINALITY_VIOLATION")

    def test_fabricated_shallow_reorg_does_not_trigger(self):
        event = ReorgEvent(
            event_id="fabricated-2", reorg_depth=1,
            common_ancestor_hash="0xaa", common_ancestor_number=10,
            old_canonical_tip="0xbb", new_canonical_tip="0xcc",
            orphaned_block_hashes=["0xbb"], new_canonical_block_hashes=["0xcc"],
            severity=ReorgSeverity.MICRO_FORK, timestamp=0.0,
        )
        finding = build_reorg_finding(event)
        self.assertFalse(finding["triggered"])

    def test_no_reorg_does_not_trigger(self):
        finding = build_reorg_finding(None)
        self.assertFalse(finding["triggered"])
        self.assertEqual(finding["observed_value"], 0)
        self.assertEqual(finding["severity"], "NONE")


class TestConcentrationFindings(unittest.TestCase):
    def test_fabricated_concentrated_miner_triggers(self):
        tracker = ConsensusConcentrationTracker()
        tracker.set_explicit_distribution({"miner-A": 95.0, "miner-B": 5.0})
        metrics = tracker.calculate_metrics()
        findings = build_concentration_findings(metrics)
        share = next(f for f in findings if f["metric"] == "validator_concentration_max_single_share")
        self.assertTrue(share["triggered"])
        self.assertAlmostEqual(share["observed_value"], 0.95)
        hhi = next(f for f in findings if f["metric"] == "validator_concentration_hhi")
        self.assertTrue(hhi["triggered"])  # 0.95^2 + 0.05^2 scaled to 0-10000 >> 2500

    def test_fabricated_diverse_distribution_does_not_trigger(self):
        tracker = ConsensusConcentrationTracker()
        tracker.set_explicit_distribution({f"miner-{i}": 1.0 for i in range(20)})
        metrics = tracker.calculate_metrics()
        findings = build_concentration_findings(metrics)
        self.assertFalse(any(f["triggered"] for f in findings))


class TestEclipseFindings(unittest.TestCase):
    def test_demo_peer_set_triggers(self):
        detector = P2PEclipseDetector()
        alert = detector.evaluate_peers(build_demo_peers())
        findings = build_eclipse_findings(alert, detector)
        self.assertTrue(any(f["triggered"] for f in findings))
        asn_finding = next(f for f in findings if f["metric"] == "eclipse_asn_concentration")
        self.assertTrue(asn_finding["triggered"])
        self.assertEqual(asn_finding["threat_level"], "CRITICAL")

    def test_fabricated_diverse_peers_do_not_trigger(self):
        detector = P2PEclipseDetector()
        peers = [PeerInfo(f"p{i}", f"10.{i}.0.1", 30303, 60000 + i, "Geth/v1.14", 20.0, 0.0)
                 for i in range(8)]
        alert = detector.evaluate_peers(peers)
        self.assertIsNone(alert)  # fully diverse: 8 unique ASNs, 8 unique /24s
        findings = build_eclipse_findings(alert, detector)
        self.assertFalse(any(f["triggered"] for f in findings))


class TestSelfishMiningFinding(unittest.TestCase):
    def test_real_detector_documented_trigger_condition_fires(self):
        # Documented trigger (selfish_mining_detector.py's own docstring/evaluate_miner):
        # z-score >= z_critical_threshold from an observed orphan rate far above
        # baseline_orphan_rate over >= min_window_for_stats observations.
        detector = SelfishMiningDetector()
        for i in range(30):
            is_orphaned = i < 6  # 6/30 = 20% orphan rate vs 2% baseline -> z >> 5.0
            detector.record_block(i, f"0x{i:064x}", f"0x{i - 1:064x}", "miner-X",
                                  is_orphaned=is_orphaned, timestamp=float(i))
        alert = detector.evaluate_miner("miner-X")
        self.assertIsNotNone(alert)
        finding = build_selfish_mining_finding(alert, detector)
        self.assertTrue(finding["triggered"])
        self.assertEqual(finding["threat_level"], "CRITICAL_ATTACK")

    def test_no_alert_does_not_trigger(self):
        finding = build_selfish_mining_finding(None)
        self.assertFalse(finding["triggered"])
        self.assertIsNone(finding["observed_value"])


if __name__ == "__main__":
    unittest.main()
