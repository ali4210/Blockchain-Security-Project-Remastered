"""
Task P11-002: Chain Reorganization Monitor.
Tracks block header lineages, fork trees, common ancestors, and reorg events.
Evaluates reorganization depth against chain finality configuration to identify
micro-forks, deep reorg anomalies, and critical finality violations.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class ReorgSeverity(str, Enum):
    NONE = "NONE"
    MICRO_FORK = "MICRO_FORK"
    SHALLOW_REORG = "SHALLOW_REORG"
    DEEP_REORG_ANOMALY = "DEEP_REORG_ANOMALY"
    CRITICAL_FINALITY_VIOLATION = "CRITICAL_FINALITY_VIOLATION"


@dataclass(frozen=True)
class BlockHeaderRecord:
    block_number: int
    block_hash: str
    parent_hash: str
    timestamp: float
    miner_or_validator: str = "unknown"


@dataclass(frozen=True)
class ReorgEvent:
    event_id: str
    reorg_depth: int
    common_ancestor_hash: str
    common_ancestor_number: int
    old_canonical_tip: str
    new_canonical_tip: str
    orphaned_block_hashes: List[str]
    new_canonical_block_hashes: List[str]
    severity: ReorgSeverity
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


class ChainReorgMonitor:
    """Monitors block headers, builds chain lineages, and detects reorganizations."""

    def __init__(self, finality_depth: int = 12, max_block_cache: int = 2048):
        if finality_depth < 1:
            raise ValueError("finality_depth must be at least 1")
        self.finality_depth = finality_depth
        self.max_block_cache = max_block_cache

        # Storage: block_hash -> BlockHeaderRecord
        self._blocks: Dict[str, BlockHeaderRecord] = {}
        # Canonical chain list: ordered list of block hashes from genesis/anchor to tip
        self._canonical_chain: List[str] = []
        self._reorg_events: List[ReorgEvent] = []

    @property
    def canonical_tip_hash(self) -> Optional[str]:
        return self._canonical_chain[-1] if self._canonical_chain else None

    @property
    def canonical_tip_number(self) -> int:
        if not self._canonical_chain:
            return -1
        return self._blocks[self._canonical_chain[-1]].block_number

    def initialize_anchor(self, header: BlockHeaderRecord) -> None:
        """Initializes canonical chain with an anchor or genesis block."""
        norm_hash = header.block_hash.lower()
        norm_parent = header.parent_hash.lower()
        rec = BlockHeaderRecord(
            block_number=header.block_number,
            block_hash=norm_hash,
            parent_hash=norm_parent,
            timestamp=header.timestamp,
            miner_or_validator=header.miner_or_validator,
        )
        self._blocks[norm_hash] = rec
        self._canonical_chain = [norm_hash]

    def _classify_reorg(self, depth: int) -> ReorgSeverity:
        if depth <= 0:
            return ReorgSeverity.NONE
        if depth == 1:
            return ReorgSeverity.MICRO_FORK
        if depth < (self.finality_depth // 2):
            return ReorgSeverity.SHALLOW_REORG
        if depth < self.finality_depth:
            return ReorgSeverity.DEEP_REORG_ANOMALY
        return ReorgSeverity.CRITICAL_FINALITY_VIOLATION

    def process_header(self, header: BlockHeaderRecord) -> Optional[ReorgEvent]:
        """
        Ingests a new block header. Extends canonical chain if it builds directly on tip,
        or detects and evaluates a reorganization if it out-chains an alternative branch.
        """
        norm_hash = header.block_hash.lower()
        norm_parent = header.parent_hash.lower()

        if norm_hash in self._blocks:
            return None  # Duplicate header

        rec = BlockHeaderRecord(
            block_number=header.block_number,
            block_hash=norm_hash,
            parent_hash=norm_parent,
            timestamp=header.timestamp,
            miner_or_validator=header.miner_or_validator,
        )
        self._blocks[norm_hash] = rec

        if not self._canonical_chain:
            self._canonical_chain.append(norm_hash)
            return None

        current_tip_hash = self.canonical_tip_hash
        current_tip = self._blocks[current_tip_hash]

        # Case 1: Direct linear extension of canonical tip
        if norm_parent == current_tip_hash:
            self._canonical_chain.append(norm_hash)
            return None

        # Case 2: Block has lower or equal height than current tip and does not outgrow it
        if rec.block_number <= current_tip.block_number:
            # Fork exists, but not long enough to trigger a reorganization
            return None

        # Case 3: Candidate block has greater height than canonical tip - evaluate reorganization
        # Trace lineage of new branch backwards until common ancestor on canonical chain
        new_branch: List[str] = [norm_hash]
        curr = norm_parent

        while curr in self._blocks and curr not in self._canonical_chain:
            new_branch.append(curr)
            curr = self._blocks[curr].parent_hash

        if curr not in self._canonical_chain:
            # Lineage cannot be anchored back to canonical history (missing blocks)
            raise ValueError(
                f"Disconnected block lineage: parent '{curr}' not found in known canonical chain"
            )

        common_ancestor_hash = curr
        ancestor_record = self._blocks[common_ancestor_hash]
        ancestor_idx = self._canonical_chain.index(common_ancestor_hash)

        # Orphaned canonical blocks are those after the common ancestor
        orphaned_hashes = self._canonical_chain[ancestor_idx + 1 :]
        reorg_depth = len(orphaned_hashes)

        # Assemble new canonical chain
        new_branch.reverse()  # now ordered ascending from after ancestor to new tip
        self._canonical_chain = self._canonical_chain[: ancestor_idx + 1] + new_branch

        severity = self._classify_reorg(reorg_depth)
        now = datetime.now(timezone.utc).timestamp()

        event = ReorgEvent(
            event_id=f"reorg-{rec.block_number}-{len(self._reorg_events) + 1}",
            reorg_depth=reorg_depth,
            common_ancestor_hash=common_ancestor_hash,
            common_ancestor_number=ancestor_record.block_number,
            old_canonical_tip=current_tip_hash,
            new_canonical_tip=norm_hash,
            orphaned_block_hashes=orphaned_hashes,
            new_canonical_block_hashes=new_branch,
            severity=severity,
            timestamp=now,
        )
        self._reorg_events.append(event)
        return event

    def get_reorg_history(self) -> List[ReorgEvent]:
        """Returns all recorded reorganization events."""
        return list(self._reorg_events)

    def get_canonical_chain(self) -> List[str]:
        """Returns current canonical block hash sequence."""
        return list(self._canonical_chain)
