"""
Task P11-007: Zone 6 Consensus Finding Threat Graph Enricher.
Transforms consensus anomaly alerts (Reorgs, Concentration, Selfish Mining, Eclipse)
into typed Zone 3 graph nodes, edges, and cryptographic finding records.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional, Set

from src.consensus.concentration_tracker import ConcentrationMetrics
from src.consensus.eclipse_detector import EclipseAlert
from src.consensus.reorg_monitor import ReorgEvent
from src.consensus.selfish_mining_detector import SelfishMiningAlert


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    node_type: str
    properties: Dict[str, Any]


@dataclass(frozen=True)
class GraphEdge:
    source_id: str
    target_id: str
    relationship: str
    properties: Dict[str, Any]


@dataclass(frozen=True)
class ConsensusFinding:
    finding_id: str
    finding_type: str
    severity: str
    zone: str
    layer: str
    title: str
    description: str
    crypto_digest: str
    requires_avs: bool
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "zone": self.zone,
            "layer": self.layer,
            "title": self.title,
            "description": self.description,
            "crypto_digest": self.crypto_digest,
            "requires_avs": self.requires_avs,
            "nodes": [asdict(n) for n in self.nodes],
            "edges": [asdict(e) for e in self.edges],
            "timestamp": self.timestamp,
        }


class ConsensusGraphEnricher:
    """Enriches and maps consensus-layer security alerts into the Zone 3 threat graph."""

    def __init__(self, zone_tag: str = "ZONE_6_CONSENSUS", layer_tag: str = "CONSENSUS"):
        self.zone_tag = zone_tag
        self.layer_tag = layer_tag

    @staticmethod
    def _compute_digest(data: Dict[str, Any]) -> str:
        serialized = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def enrich_reorg_event(self, event: ReorgEvent) -> Optional[ConsensusFinding]:
        """Maps a chain reorganization event to a typed finding and graph projection."""
        if event.severity.value in ["NONE", "MICRO_FORK"]:
            return None  # Normal transient micro-forks do not pollute threat graph

        severity_map = {
            "SHALLOW_REORG": "MEDIUM",
            "DEEP_REORG_ANOMALY": "HIGH",
            "CRITICAL_FINALITY_VIOLATION": "CRITICAL",
        }
        severity = severity_map.get(event.severity.value, "MEDIUM")
        requires_avs = severity in ["HIGH", "CRITICAL"]

        payload_to_hash = {
            "event_id": event.event_id,
            "reorg_depth": event.reorg_depth,
            "common_ancestor_hash": event.common_ancestor_hash,
            "old_tip": event.old_canonical_tip,
            "new_tip": event.new_canonical_tip,
        }
        digest = self._compute_digest(payload_to_hash)
        finding_id = f"c6-reorg-{digest[:12]}"

        # Graph nodes
        node_finding = GraphNode(
            node_id=finding_id,
            node_type="FINDING",
            properties={"severity": severity, "depth": event.reorg_depth},
        )
        node_attack = GraphNode(
            node_id=f"attack-{event.severity.value.lower()}",
            node_type="CONSENSUS_ATTACK",
            properties={"attack_class": event.severity.value},
        )
        node_block = GraphNode(
            node_id=f"block-{event.common_ancestor_number}",
            node_type="BLOCK_ANCESTOR",
            properties={"hash": event.common_ancestor_hash, "height": event.common_ancestor_number},
        )

        # Graph edges
        edges = [
            GraphEdge(
                source_id=node_finding.node_id,
                target_id=node_attack.node_id,
                relationship="INDICATES",
                properties={"reorg_depth": event.reorg_depth},
            ),
            GraphEdge(
                source_id=node_attack.node_id,
                target_id=node_block.node_id,
                relationship="BRANCHES_FROM",
                properties={"ancestor_height": event.common_ancestor_number},
            ),
        ]

        return ConsensusFinding(
            finding_id=finding_id,
            finding_type="CHAIN_REORGANIZATION",
            severity=severity,
            zone=self.zone_tag,
            layer=self.layer_tag,
            title=f"Consensus Reorg Anomaly: {event.severity.value} (Depth {event.reorg_depth})",
            description=(
                f"Chain reorg of depth {event.reorg_depth} detected diverging from ancestor "
                f"#{event.common_ancestor_number} ({event.common_ancestor_hash[:10]}...)."
            ),
            crypto_digest=digest,
            requires_avs=requires_avs,
            nodes=[node_finding, node_attack, node_block],
            edges=edges,
            timestamp=event.timestamp,
        )

    def enrich_concentration_metrics(self, metrics: ConcentrationMetrics) -> Optional[ConsensusFinding]:
        """Maps stake/hashpower concentration alerts to threat graph findings."""
        if metrics.alert_level.value == "CLEAR":
            return None

        severity = "CRITICAL" if metrics.alert_level.value == "CRITICAL" else "HIGH"
        requires_avs = True

        payload_to_hash = {
            "top_entity": metrics.top_entity_id,
            "max_single_share": metrics.max_single_share,
            "nakamoto": metrics.nakamoto_coefficient,
            "hhi": metrics.hhi,
        }
        digest = self._compute_digest(payload_to_hash)
        finding_id = f"c6-concentration-{digest[:12]}"

        node_finding = GraphNode(
            node_id=finding_id,
            node_type="FINDING",
            properties={"severity": severity, "hhi": metrics.hhi, "nakamoto": metrics.nakamoto_coefficient},
        )
        node_entity = GraphNode(
            node_id=f"entity-{metrics.top_entity_id}",
            node_type="CONSENSUS_PRODUCER",
            properties={"entity_id": metrics.top_entity_id, "share": metrics.max_single_share},
        )
        node_risk = GraphNode(
            node_id="risk-centralization-cartel",
            node_type="CONSENSUS_ATTACK",
            properties={"type": "STAKE_OR_HASHPOWER_CONCENTRATION"},
        )

        edges = [
            GraphEdge(
                source_id=node_finding.node_id,
                target_id=node_risk.node_id,
                relationship="INDICATES",
                properties={"reasons": metrics.alert_reasons},
            ),
            GraphEdge(
                source_id=node_finding.node_id,
                target_id=node_entity.node_id,
                relationship="DOMINATED_BY",
                properties={"share": metrics.max_single_share},
            ),
        ]

        return ConsensusFinding(
            finding_id=finding_id,
            finding_type="CONSENSUS_CONCENTRATION",
            severity=severity,
            zone=self.zone_tag,
            layer=self.layer_tag,
            title=f"Consensus Concentration Risk: {metrics.alert_level.value}",
            description="; ".join(metrics.alert_reasons),
            crypto_digest=digest,
            requires_avs=requires_avs,
            nodes=[node_finding, node_entity, node_risk],
            edges=edges,
            timestamp=datetime.now(timezone.utc).timestamp(),
        )

    def enrich_selfish_mining_alert(self, alert: SelfishMiningAlert) -> Optional[ConsensusFinding]:
        """Maps selfish mining alerts to threat graph findings."""
        if alert.threat_level.value == "CLEAR":
            return None

        severity = "CRITICAL" if alert.threat_level.value == "CRITICAL_ATTACK" else "HIGH"
        requires_avs = True

        payload_to_hash = {
            "alert_id": alert.alert_id,
            "suspected_miner": alert.suspected_miner,
            "z_score": alert.z_score,
            "private_streak": alert.private_release_streak,
        }
        digest = self._compute_digest(payload_to_hash)
        finding_id = f"c6-selfish-{digest[:12]}"

        node_finding = GraphNode(
            node_id=finding_id,
            node_type="FINDING",
            properties={"severity": severity, "z_score": alert.z_score},
        )
        node_miner = GraphNode(
            node_id=f"miner-{alert.suspected_miner}",
            node_type="SUSPECTED_MINER",
            properties={"miner_id": alert.suspected_miner, "private_streak": alert.private_release_streak},
        )
        node_attack = GraphNode(
            node_id="attack-selfish-mining",
            node_type="CONSENSUS_ATTACK",
            properties={"type": "SELFISH_MINING_WITHHOLDING"},
        )

        edges = [
            GraphEdge(
                source_id=node_finding.node_id,
                target_id=node_attack.node_id,
                relationship="INDICATES",
                properties={"z_score": alert.z_score},
            ),
            GraphEdge(
                source_id=node_finding.node_id,
                target_id=node_miner.node_id,
                relationship="ATTRIBUTED_TO",
                properties={"private_release_streak": alert.private_release_streak},
            ),
        ]

        return ConsensusFinding(
            finding_id=finding_id,
            finding_type="SELFISH_MINING",
            severity=severity,
            zone=self.zone_tag,
            layer=self.layer_tag,
            title=f"Selfish Mining Anomaly: {alert.threat_level.value}",
            description="; ".join(alert.reasons),
            crypto_digest=digest,
            requires_avs=requires_avs,
            nodes=[node_finding, node_miner, node_attack],
            edges=edges,
            timestamp=alert.timestamp,
        )

    def enrich_eclipse_alert(self, alert: EclipseAlert) -> Optional[ConsensusFinding]:
        """Maps P2P eclipse alerts to threat graph findings."""
        if alert.threat_level.value == "CLEAR":
            return None

        severity = "CRITICAL" if alert.threat_level.value == "CRITICAL" else "HIGH"
        requires_avs = True

        payload_to_hash = {
            "alert_id": alert.alert_id,
            "dominant_asn": alert.dominant_asn,
            "dominant_subnet": alert.dominant_subnet,
            "max_asn_share": alert.max_asn_share,
        }
        digest = self._compute_digest(payload_to_hash)
        finding_id = f"c6-eclipse-{digest[:12]}"

        node_finding = GraphNode(
            node_id=finding_id,
            node_type="FINDING",
            properties={"severity": severity, "asn_share": alert.max_asn_share},
        )
        node_network = GraphNode(
            node_id=f"asn-{alert.dominant_asn}",
            node_type="NETWORK_AUTONOMOUS_SYSTEM",
            properties={"asn": alert.dominant_asn, "share": alert.max_asn_share, "subnet": alert.dominant_subnet},
        )
        node_attack = GraphNode(
            node_id="attack-p2p-eclipse",
            node_type="CONSENSUS_ATTACK",
            properties={"type": "P2P_ECLIPSE_MONOPOLIZATION"},
        )

        edges = [
            GraphEdge(
                source_id=node_finding.node_id,
                target_id=node_attack.node_id,
                relationship="INDICATES",
                properties={"reasons": alert.reasons},
            ),
            GraphEdge(
                source_id=node_finding.node_id,
                target_id=node_network.node_id,
                relationship="ISOLATED_BY_NETWORK",
                properties={"asn": alert.dominant_asn, "share": alert.max_asn_share},
            ),
        ]

        return ConsensusFinding(
            finding_id=finding_id,
            finding_type="P2P_ECLIPSE_ATTACK",
            severity=severity,
            zone=self.zone_tag,
            layer=self.layer_tag,
            title=f"P2P Eclipse Attack: {alert.threat_level.value}",
            description="; ".join(alert.reasons),
            crypto_digest=digest,
            requires_avs=requires_avs,
            nodes=[node_finding, node_network, node_attack],
            edges=edges,
            timestamp=alert.timestamp,
        )
