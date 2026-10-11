"""
Task P11-001: P2P Network, Topology, and Mempool Listener.
Tracks transaction propagation latency, peer network topology, ASN distribution,
and block announcement arrival deltas for consensus-layer threat hunting.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional, Set


@dataclass(frozen=True)
class MempoolTx:
    tx_hash: str
    from_address: str
    to_address: str
    gas_price: int
    value_wei: int
    data_payload: str
    first_seen_timestamp: float
    received_timestamp: float

    @property
    def propagation_delay_ms(self) -> float:
        """Returns the propagation delay in milliseconds."""
        delay = (self.received_timestamp - self.first_seen_timestamp) * 1000.0
        return max(0.0, round(delay, 2))


@dataclass(frozen=True)
class PeerInfo:
    peer_id: str
    ip_addr: str
    port: int
    asn: int
    client_version: str
    latency_rtt_ms: float
    connected_timestamp: float

    @property
    def subnet_24(self) -> str:
        """Returns /24 CIDR block for IPv4 or /48 for IPv6 to assess topological diversity."""
        try:
            ip_obj = ip_address(self.ip_addr)
            if ip_obj.version == 4:
                return str(ip_network(f"{self.ip_addr}/24", strict=False))
            return str(ip_network(f"{self.ip_addr}/48", strict=False))
        except ValueError:
            return "unknown/0"


@dataclass(frozen=True)
class BlockPropagationEvent:
    block_number: int
    block_hash: str
    parent_hash: str
    announced_timestamp: float
    received_timestamp: float
    peer_id: str

    @property
    def arrival_delta_ms(self) -> float:
        delta = (self.received_timestamp - self.announced_timestamp) * 1000.0
        return max(0.0, round(delta, 2))


class ConsensusNetworkListener:
    """Ingests and analyzes P2P network telemetry, mempool activity, and peer topologies."""

    def __init__(self, max_mempool_cache: int = 10000, max_peer_cache: int = 256):
        self.max_mempool_cache = max_mempool_cache
        self.max_peer_cache = max_peer_cache
        self._mempool: Dict[str, MempoolTx] = {}
        self._peers: Dict[str, PeerInfo] = {}
        self._block_events: List[BlockPropagationEvent] = []

    def record_mempool_transaction(
        self,
        tx_hash: str,
        from_address: str,
        to_address: str,
        gas_price: int,
        value_wei: int,
        data_payload: str,
        first_seen_timestamp: float,
        received_timestamp: Optional[float] = None,
    ) -> MempoolTx:
        """Records an observed pending transaction and calculates propagation delay."""
        if not tx_hash.startswith("0x") or len(tx_hash) != 66:
            raise ValueError(f"Invalid transaction hash format: {tx_hash}")

        now = received_timestamp if received_timestamp is not None else datetime.now(timezone.utc).timestamp()
        if first_seen_timestamp > now + 1.0:  # Allow max 1 second clock drift
            raise ValueError("first_seen_timestamp cannot be substantially in the future of received_timestamp")

        if len(self._mempool) >= self.max_mempool_cache:
            # Evict oldest entry
            oldest_key = next(iter(self._mempool))
            del self._mempool[oldest_key]

        tx = MempoolTx(
            tx_hash=tx_hash.lower(),
            from_address=from_address.lower(),
            to_address=to_address.lower(),
            gas_price=gas_price,
            value_wei=value_wei,
            data_payload=data_payload,
            first_seen_timestamp=first_seen_timestamp,
            received_timestamp=now,
        )
        self._mempool[tx.tx_hash] = tx
        return tx

    def register_peer(
        self,
        peer_id: str,
        ip_addr: str,
        port: int,
        asn: int,
        client_version: str,
        latency_rtt_ms: float,
        connected_timestamp: Optional[float] = None,
    ) -> PeerInfo:
        """Registers an active peer connection into the topology registry."""
        if not peer_id:
            raise ValueError("peer_id must not be empty")

        now = connected_timestamp if connected_timestamp is not None else datetime.now(timezone.utc).timestamp()

        peer = PeerInfo(
            peer_id=peer_id,
            ip_addr=ip_addr,
            port=port,
            asn=asn,
            client_version=client_version,
            latency_rtt_ms=max(0.0, latency_rtt_ms),
            connected_timestamp=now,
        )
        self._peers[peer_id] = peer
        return peer

    def disconnect_peer(self, peer_id: str) -> bool:
        """Removes a disconnected peer from the active topology registry."""
        return self._peers.pop(peer_id, None) is not None

    def record_block_propagation(
        self,
        block_number: int,
        block_hash: str,
        parent_hash: str,
        announced_timestamp: float,
        received_timestamp: Optional[float] = None,
        peer_id: str = "local",
    ) -> BlockPropagationEvent:
        """Records block delivery event and announces arrival deltas."""
        now = received_timestamp if received_timestamp is not None else datetime.now(timezone.utc).timestamp()

        event = BlockPropagationEvent(
            block_number=block_number,
            block_hash=block_hash.lower(),
            parent_hash=parent_hash.lower(),
            announced_timestamp=announced_timestamp,
            received_timestamp=now,
            peer_id=peer_id,
        )
        self._block_events.append(event)
        return event

    def get_topology_summary(self) -> Dict[str, Any]:
        """Calculates topological diversity statistics across ASN and subnets."""
        total_peers = len(self._peers)
        if total_peers == 0:
            return {
                "total_peers": 0,
                "unique_asns": 0,
                "unique_subnets": 0,
                "asn_distribution": {},
                "subnet_distribution": {},
                "max_single_asn_share": 0.0,
            }

        asn_counts: Dict[int, int] = {}
        subnet_counts: Dict[str, int] = {}

        for p in self._peers.values():
            asn_counts[p.asn] = asn_counts.get(p.asn, 0) + 1
            subnet_counts[p.subnet_24] = subnet_counts.get(p.subnet_24, 0) + 1

        max_asn_count = max(asn_counts.values()) if asn_counts else 0

        return {
            "total_peers": total_peers,
            "unique_asns": len(asn_counts),
            "unique_subnets": len(subnet_counts),
            "asn_distribution": asn_counts,
            "subnet_distribution": subnet_counts,
            "max_single_asn_share": round(max_asn_count / total_peers, 4),
        }

    def get_mempool_transaction(self, tx_hash: str) -> Optional[MempoolTx]:
        """Retrieves a pending mempool transaction by hash."""
        return self._mempool.get(tx_hash.lower())

    def get_all_mempool_transactions(self) -> List[MempoolTx]:
        """Returns list of all active pending transactions in mempool."""
        return list(self._mempool.values())
