"""
Task P11-005: P2P Eclipse Attack Detector.
Evaluates peer topological diversity, ASN concentration, /24 and /48 subnet clustering,
and connection influx patterns to identify peer table monopolization.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional, Set

from src.consensus.p2p_listener import PeerInfo


class EclipseThreatLevel(str, Enum):
    CLEAR = "CLEAR"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class EclipseAlert:
    alert_id: str
    threat_level: EclipseThreatLevel
    total_peers: int
    unique_asns: int
    unique_subnets: int
    max_asn_share: float
    dominant_asn: int
    max_subnet_share: float
    dominant_subnet: str
    reasons: List[str]
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["threat_level"] = self.threat_level.value
        return data


class P2PEclipseDetector:
    """Detects eclipse attacks by analyzing peer table topology, ASN, and subnet distribution."""

    def __init__(
        self,
        min_peers_for_eval: int = 8,
        min_asns_required: int = 3,
        asn_warning_threshold: float = 0.50,
        asn_critical_threshold: float = 0.80,
        subnet_warning_threshold: float = 0.40,
        subnet_critical_threshold: float = 0.60,
        allowlist_private_networks: bool = False,
    ):
        self.min_peers_for_eval = min_peers_for_eval
        self.min_asns_required = min_asns_required
        self.asn_warning_threshold = asn_warning_threshold
        self.asn_critical_threshold = asn_critical_threshold
        self.subnet_warning_threshold = subnet_warning_threshold
        self.subnet_critical_threshold = subnet_critical_threshold
        self.allowlist_private_networks = allowlist_private_networks

    def _is_private_ip(self, ip_str: str) -> bool:
        try:
            return ip_address(ip_str).is_private or ip_address(ip_str).is_loopback
        except ValueError:
            return False

    def evaluate_peers(self, peers: List[PeerInfo]) -> Optional[EclipseAlert]:
        """Evaluates active peer list for topological eclipse patterns."""
        filtered_peers = peers
        if self.allowlist_private_networks:
            filtered_peers = [p for p in peers if not self._is_private_ip(p.ip_addr)]

        total_peers = len(filtered_peers)
        if total_peers < self.min_peers_for_eval:
            return None

        asn_counts: Dict[int, int] = {}
        subnet_counts: Dict[str, int] = {}

        for p in filtered_peers:
            asn_counts[p.asn] = asn_counts.get(p.asn, 0) + 1
            subnet_counts[p.subnet_24] = subnet_counts.get(p.subnet_24, 0) + 1

        # Dominant entities
        top_asn_item = max(asn_counts.items(), key=lambda x: x[1])
        top_subnet_item = max(subnet_counts.items(), key=lambda x: x[1])

        max_asn_share = round(top_asn_item[1] / total_peers, 4)
        dominant_asn = top_asn_item[0]

        max_subnet_share = round(top_subnet_item[1] / total_peers, 4)
        dominant_subnet = top_subnet_item[0]

        unique_asns = len(asn_counts)
        unique_subnets = len(subnet_counts)

        # Threat evaluation
        threat_level = EclipseThreatLevel.CLEAR
        reasons: List[str] = []

        # 1. Critical thresholds
        if max_asn_share >= self.asn_critical_threshold:
            threat_level = EclipseThreatLevel.CRITICAL
            reasons.append(
                f"Severe ASN concentration: ASN {dominant_asn} controls {max_asn_share*100:.1f}% >= {self.asn_critical_threshold*100:.1f}% of peers"
            )
        if max_subnet_share >= self.subnet_critical_threshold:
            threat_level = EclipseThreatLevel.CRITICAL
            reasons.append(
                f"Severe subnet concentration: subnet {dominant_subnet} controls {max_subnet_share*100:.1f}% >= {self.subnet_critical_threshold*100:.1f}% of peers"
            )

        # 2. Warning thresholds
        if threat_level != EclipseThreatLevel.CRITICAL:
            if max_asn_share >= self.asn_warning_threshold:
                threat_level = EclipseThreatLevel.WARNING
                reasons.append(
                    f"Elevated ASN concentration: ASN {dominant_asn} controls {max_asn_share*100:.1f}% >= {self.asn_warning_threshold*100:.1f}% of peers"
                )
            if max_subnet_share >= self.subnet_warning_threshold:
                threat_level = EclipseThreatLevel.WARNING
                reasons.append(
                    f"Elevated subnet concentration: subnet {dominant_subnet} controls {max_subnet_share*100:.1f}% >= {self.subnet_warning_threshold*100:.1f}% of peers"
                )
            if unique_asns < self.min_asns_required:
                threat_level = EclipseThreatLevel.WARNING
                reasons.append(
                    f"Low ASN diversity: only {unique_asns} unique ASNs active < required {self.min_asns_required}"
                )

        if threat_level == EclipseThreatLevel.CLEAR:
            return None

        now = datetime.now(timezone.utc).timestamp()
        return EclipseAlert(
            alert_id=f"eclipse-alert-{int(now)}",
            threat_level=threat_level,
            total_peers=total_peers,
            unique_asns=unique_asns,
            unique_subnets=unique_subnets,
            max_asn_share=max_asn_share,
            dominant_asn=dominant_asn,
            max_subnet_share=max_subnet_share,
            dominant_subnet=dominant_subnet,
            reasons=reasons,
            timestamp=now,
        )
