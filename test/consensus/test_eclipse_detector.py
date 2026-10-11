"""
Task P11-005: Unit tests for P2P Eclipse Attack Detector.
Validates multi-homed peer table safety, min-peer evaluation gating,
ASN monopolization, subnet clustering, and private network allowlists.
"""

import unittest

from src.consensus.eclipse_detector import (
    EclipseAlert,
    EclipseThreatLevel,
    P2PEclipseDetector,
)
from src.consensus.p2p_listener import PeerInfo


class TestEclipseDetector(unittest.TestCase):
    def setUp(self):
        self.detector = P2PEclipseDetector(
            min_peers_for_eval=8,
            min_asns_required=3,
            asn_warning_threshold=0.50,
            asn_critical_threshold=0.80,
            subnet_warning_threshold=0.40,
            subnet_critical_threshold=0.60,
            allowlist_private_networks=False,
        )

    def test_insufficient_peers_suppresses_eval(self):
        # 4 peers (less than min 8)
        peers = [
            PeerInfo(
                peer_id=f"p-{i}",
                ip_addr=f"198.51.100.{i}",
                port=30303,
                asn=13335,
                client_version="Geth/v1.14.0",
                latency_rtt_ms=20.0,
                connected_timestamp=1700000000.0,
            )
            for i in range(1, 5)
        ]
        alert = self.detector.evaluate_peers(peers)
        self.assertIsNone(alert)

    def test_healthy_diverse_peer_table_is_clear(self):
        # 10 peers across 5 ASNs and 10 distinct subnets
        asns = [13335, 16509, 15169, 14061, 8075]  # Cloudflare, AWS, Google, DigitalOcean, Microsoft
        peers = [
            PeerInfo(
                peer_id=f"p-{i}",
                ip_addr=f"198.51.{i}.10",
                port=30303,
                asn=asns[i % len(asns)],
                client_version="Geth/v1.14.0",
                latency_rtt_ms=25.0,
                connected_timestamp=1700000000.0,
            )
            for i in range(10)
        ]
        alert = self.detector.evaluate_peers(peers)
        self.assertIsNone(alert)

    def test_critical_asn_monopolization(self):
        # 10 peers: 9 from ASN 13335 (90% >= 80% critical threshold)
        peers = [
            PeerInfo(
                peer_id=f"p-{i}",
                ip_addr=f"198.51.{i}.10",
                port=30303,
                asn=13335 if i < 9 else 16509,
                client_version="Geth/v1.14.0",
                latency_rtt_ms=20.0,
                connected_timestamp=1700000000.0,
            )
            for i in range(10)
        ]
        alert = self.detector.evaluate_peers(peers)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_level, EclipseThreatLevel.CRITICAL)
        self.assertEqual(alert.dominant_asn, 13335)
        self.assertEqual(alert.max_asn_share, 0.90)
        self.assertTrue(any("Severe ASN concentration" in r for r in alert.reasons))

    def test_critical_subnet_clustering(self):
        # 10 peers: 7 from same /24 subnet (198.51.100.0/24) (70% >= 60% critical threshold)
        peers = [
            PeerInfo(
                peer_id=f"p-{i}",
                ip_addr=f"198.51.100.{i}" if i < 7 else f"203.0.113.{i}",
                port=30303,
                asn=10000 + i,  # diverse ASNs
                client_version="Geth/v1.14.0",
                latency_rtt_ms=20.0,
                connected_timestamp=1700000000.0,
            )
            for i in range(10)
        ]
        alert = self.detector.evaluate_peers(peers)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_level, EclipseThreatLevel.CRITICAL)
        self.assertEqual(alert.max_subnet_share, 0.70)
        self.assertTrue(any("Severe subnet concentration" in r for r in alert.reasons))

    def test_warning_low_asn_diversity(self):
        # 10 peers from only 2 ASNs (less than min 3 required)
        peers = [
            PeerInfo(
                peer_id=f"p-{i}",
                ip_addr=f"198.51.{i}.10",
                port=30303,
                asn=13335 if i < 5 else 16509,  # 50% each
                client_version="Geth/v1.14.0",
                latency_rtt_ms=20.0,
                connected_timestamp=1700000000.0,
            )
            for i in range(10)
        ]
        alert = self.detector.evaluate_peers(peers)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_level, EclipseThreatLevel.WARNING)
        self.assertEqual(alert.unique_asns, 2)
        self.assertTrue(any("Low ASN diversity" in r for r in alert.reasons))

    def test_allowlist_private_networks_filtering(self):
        detector_local = P2PEclipseDetector(
            min_peers_for_eval=8,
            allowlist_private_networks=True,
        )
        # 10 peers all on 127.0.0.1 or 192.168.1.x
        peers = [
            PeerInfo(
                peer_id=f"p-{i}",
                ip_addr=f"192.168.1.{i}",
                port=30303,
                asn=0,
                client_version="Geth/v1.14.0",
                latency_rtt_ms=1.0,
                connected_timestamp=1700000000.0,
            )
            for i in range(10)
        ]
        alert = detector_local.evaluate_peers(peers)
        # All filtered out, active peers < 8 -> no alert
        self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main()
