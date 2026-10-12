"""
Task P13-002: AML Pattern Rules and Graph-Model Detector.
Provides deterministic telemetry evaluation for:
1. Structuring (smurfing below regulatory reporting thresholds).
2. Rapid layering hops and peeling chains.
3. Mixer and privacy pool interaction signals.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import time


class AMLRiskType(str, Enum):
    STRUCTURING = "STRUCTURING"
    RAPID_LAYERING = "RAPID_LAYERING"
    MIXER_INTERACTION = "MIXER_INTERACTION"
    PEELING_CHAIN = "PEELING_CHAIN"
    NORMAL = "NORMAL"


@dataclass(frozen=True)
class AMLTransaction:
    tx_hash: str
    sender: str
    recipient: str
    value_wei: int
    timestamp: float
    block_number: int


@dataclass(frozen=True)
class AMLFinding:
    rule_id: str
    risk_type: AMLRiskType
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    confidence: float  # 0.0 to 1.0
    involved_addresses: List[str]
    evidence_tx_hashes: List[str]
    description: str


class AMLDetector:
    """
    Deterministic rule-based and graph-model detector for anti-money laundering typologies.
    """

    def __init__(
        self,
        structuring_threshold_wei: int = 10**19,  # ~10 ETH reporting threshold
        structuring_lower_bound_wei: int = 8 * 10**18,  # ~8 ETH (80% boundary)
        max_layering_hop_interval_sec: float = 120.0,  # 2 minutes max hop interval
        known_mixer_addresses: Optional[Set[str]] = None,
    ):
        self.structuring_threshold_wei = structuring_threshold_wei
        self.structuring_lower_bound_wei = structuring_lower_bound_wei
        self.max_layering_hop_interval_sec = max_layering_hop_interval_sec
        self.known_mixers = (
            {m.lower() for m in known_mixer_addresses}
            if known_mixer_addresses is not None
            else {
                "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",  # Tornado Router
                "0x8576acc5c05d6ce88f4e49bf65bdf0c62f91353c",  # Tornado Vault
                "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc",  # Tornado 0.1 ETH
            }
        )

    def evaluate_structuring(self, transactions: List[AMLTransaction]) -> List[AMLFinding]:
        """
        Detects multiple transactions just below the reporting threshold from the same sender
        within a short sliding window.
        """
        findings: List[AMLFinding] = []
        by_sender: Dict[str, List[AMLTransaction]] = {}

        for tx in transactions:
            sender = tx.sender.lower()
            by_sender.setdefault(sender, []).append(tx)

        for sender, tx_list in by_sender.items():
            tx_sorted = sorted(tx_list, key=lambda t: t.timestamp)
            # Filter transactions falling in the smurfing bracket [lower_bound, threshold)
            smurf_txs = [
                tx
                for tx in tx_sorted
                if self.structuring_lower_bound_wei <= tx.value_wei < self.structuring_threshold_wei
            ]

            if len(smurf_txs) >= 2:
                # Check if executed in close temporal proximity (< 1 hour)
                time_span = smurf_txs[-1].timestamp - smurf_txs[0].timestamp
                if time_span <= 3600.0:
                    findings.append(
                        AMLFinding(
                            rule_id="RULE-AML-001",
                            risk_type=AMLRiskType.STRUCTURING,
                            severity="HIGH",
                            confidence=0.85,
                            involved_addresses=[sender],
                            evidence_tx_hashes=[t.tx_hash for t in smurf_txs],
                            description=(
                                f"Detected {len(smurf_txs)} transactions just below reporting threshold "
                                f"({self.structuring_threshold_wei} wei) within {int(time_span)}s."
                            ),
                        )
                    )

        return findings

    def evaluate_mixer_signals(self, transactions: List[AMLTransaction]) -> List[AMLFinding]:
        """
        Detects direct interactions with privacy pools or mixers.
        """
        findings: List[AMLFinding] = []

        for tx in transactions:
            sender = tx.sender.lower()
            recipient = tx.recipient.lower()

            if recipient in self.known_mixers or sender in self.known_mixers:
                mixer_hit = recipient if recipient in self.known_mixers else sender
                findings.append(
                    AMLFinding(
                        rule_id="RULE-AML-002",
                        risk_type=AMLRiskType.MIXER_INTERACTION,
                        severity="CRITICAL",
                        confidence=0.98,
                        involved_addresses=[sender, recipient],
                        evidence_tx_hashes=[tx.tx_hash],
                        description=f"Direct transaction interaction with known mixer contract {mixer_hit}.",
                    )
                )

        return findings

    def evaluate_layering_hops(self, transactions: List[AMLTransaction]) -> List[AMLFinding]:
        """
        Graph-model tracing: detects rapid sequential transfers across intermediate accounts
        (A -> B -> C -> D) where holding time between consecutive hops is minimal.
        """
        findings: List[AMLFinding] = []
        if len(transactions) < 3:
            return findings

        # Index transactions by sender
        tx_by_sender: Dict[str, List[AMLTransaction]] = {}
        for tx in transactions:
            tx_by_sender.setdefault(tx.sender.lower(), []).append(tx)

        # Trace paths
        visited_chains: Set[str] = set()
        for root_tx in transactions:
            chain = [root_tx]
            curr_tx = root_tx

            while True:
                next_hops = tx_by_sender.get(curr_tx.recipient.lower(), [])
                # Look for an outbound tx shortly after arrival with similar or slightly lesser value (peeling fee)
                forward_hop = None
                for candidate in next_hops:
                    dt = candidate.timestamp - curr_tx.timestamp
                    if 0.0 <= dt <= self.max_layering_hop_interval_sec:
                        # Value conservation check: candidate must be between 80% and 100% of incoming value
                        if 0.80 * curr_tx.value_wei <= candidate.value_wei <= curr_tx.value_wei:
                            forward_hop = candidate
                            break

                if forward_hop and forward_hop.tx_hash not in [c.tx_hash for c in chain]:
                    chain.append(forward_hop)
                    curr_tx = forward_hop
                else:
                    break

            if len(chain) >= 3:
                chain_key = "->".join(t.tx_hash for t in chain)
                if chain_key not in visited_chains:
                    visited_chains.add(chain_key)
                    involved = [chain[0].sender.lower()] + [t.recipient.lower() for t in chain]
                    findings.append(
                        AMLFinding(
                            rule_id="RULE-AML-003",
                            risk_type=AMLRiskType.RAPID_LAYERING,
                            severity="HIGH",
                            confidence=0.90,
                            involved_addresses=list(dict.fromkeys(involved)),
                            evidence_tx_hashes=[t.tx_hash for t in chain],
                            description=(
                                f"Detected rapid layering peeling chain across {len(chain)} hops "
                                f"with holding intervals <= {self.max_layering_hop_interval_sec}s."
                            ),
                        )
                    )

        return findings

    def analyze_batch(self, transactions: List[AMLTransaction]) -> List[AMLFinding]:
        """
        Runs comprehensive AML analysis over a batch of transaction telemetry records.
        """
        findings: List[AMLFinding] = []
        findings.extend(self.evaluate_structuring(transactions))
        findings.extend(self.evaluate_mixer_signals(transactions))
        findings.extend(self.evaluate_layering_hops(transactions))
        return findings
