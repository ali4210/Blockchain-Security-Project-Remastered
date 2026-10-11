"""
Task P11-007: Unit tests for Zone 6 Threat Graph Enricher.
Validates normalization of reorgs, concentration, selfish mining, and eclipse alerts
into typed Zone 3 graph nodes, edges, finding digests, and AVS requirement flags.
"""

import unittest

from src.consensus.concentration_tracker import ConcentrationAlertLevel, ConcentrationMetrics
from src.consensus.eclipse_detector import EclipseAlert, EclipseThreatLevel
from src.consensus.graph_enricher import ConsensusGraphEnricher
from src.consensus.reorg_monitor import ReorgEvent, ReorgSeverity
from src.consensus.selfish_mining_detector import SelfishMiningAlert, SelfishMiningThreatLevel


class TestGraphEnricher(unittest.TestCase):
    def setUp(self):
        self.enricher = ConsensusGraphEnricher()

    def test_reorg_event_enrichment(self):
        # Micro fork yields None
        event_micro = ReorgEvent(
            event_id="e1",
            reorg_depth=1,
            common_ancestor_hash="0x" + "0" * 64,
            common_ancestor_number=100,
            old_canonical_tip="0x" + "1" * 64,
            new_canonical_tip="0x" + "2" * 64,
            orphaned_block_hashes=[],
            new_canonical_block_hashes=[],
            severity=ReorgSeverity.MICRO_FORK,
            timestamp=1700000000.0,
        )
        self.assertIsNone(self.enricher.enrich_reorg_event(event_micro))

        # Deep reorg yields HIGH finding with AVS required
        event_deep = ReorgEvent(
            event_id="e2",
            reorg_depth=6,
            common_ancestor_hash="0x" + "a" * 64,
            common_ancestor_number=102,
            old_canonical_tip="0x" + "b" * 64,
            new_canonical_tip="0x" + "c" * 64,
            orphaned_block_hashes=["0x" + "d" * 64],
            new_canonical_block_hashes=["0x" + "e" * 64],
            severity=ReorgSeverity.DEEP_REORG_ANOMALY,
            timestamp=1700000000.0,
        )
        finding = self.enricher.enrich_reorg_event(event_deep)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.zone, "ZONE_6_CONSENSUS")
        self.assertEqual(finding.layer, "CONSENSUS")
        self.assertTrue(finding.requires_avs)
        self.assertEqual(len(finding.nodes), 3)
        self.assertEqual(len(finding.edges), 2)
        self.assertEqual(len(finding.crypto_digest), 64)

    def test_concentration_metrics_enrichment(self):
        metrics_clear = ConcentrationMetrics(
            total_entities=5,
            nakamoto_coefficient=3,
            hhi=1200.0,
            max_single_share=0.20,
            top3_cumulative_share=0.50,
            top_entity_id="pool-1",
            alert_level=ConcentrationAlertLevel.CLEAR,
            alert_reasons=[],
        )
        self.assertIsNone(self.enricher.enrich_concentration_metrics(metrics_clear))

        metrics_crit = ConcentrationMetrics(
            total_entities=3,
            nakamoto_coefficient=1,
            hhi=3500.0,
            max_single_share=0.55,
            top3_cumulative_share=1.0,
            top_entity_id="hostile-pool",
            alert_level=ConcentrationAlertLevel.CRITICAL,
            alert_reasons=["Single entity holds 55%"],
        )
        finding = self.enricher.enrich_concentration_metrics(metrics_crit)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertTrue(finding.requires_avs)
        self.assertTrue(any(n.node_id == "entity-hostile-pool" for n in finding.nodes))

    def test_selfish_mining_enrichment(self):
        alert = SelfishMiningAlert(
            alert_id="sm-1",
            threat_level=SelfishMiningThreatLevel.CRITICAL_ATTACK,
            suspected_miner="rogue-pool",
            observed_orphan_rate=0.15,
            expected_orphan_rate=0.02,
            z_score=6.2,
            window_blocks=100,
            total_orphans=15,
            private_release_streak=4,
            reasons=["Extreme z-score"],
            timestamp=1700000000.0,
        )
        finding = self.enricher.enrich_selfish_mining_alert(alert)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertTrue(finding.requires_avs)
        self.assertTrue(any(e.relationship == "ATTRIBUTED_TO" for e in finding.edges))

    def test_eclipse_alert_enrichment(self):
        alert = EclipseAlert(
            alert_id="ec-1",
            threat_level=EclipseThreatLevel.CRITICAL,
            total_peers=10,
            unique_asns=1,
            unique_subnets=1,
            max_asn_share=0.90,
            dominant_asn=13335,
            max_subnet_share=0.90,
            dominant_subnet="198.51.100.0/24",
            reasons=["Severe ASN monopolization"],
            timestamp=1700000000.0,
        )
        finding = self.enricher.enrich_eclipse_alert(alert)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertTrue(finding.requires_avs)
        self.assertTrue(any(n.node_id == "asn-13335" for n in finding.nodes))
        self.assertTrue(any(e.relationship == "ISOLATED_BY_NETWORK" for e in finding.edges))


if __name__ == "__main__":
    unittest.main()
