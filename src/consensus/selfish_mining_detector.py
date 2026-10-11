"""
Task P11-004: Selfish Mining and Block Withholding Anomaly Detector.
Implements statistical z-score evaluation comparing observed vs expected
orphan/stale rates, and detects strategic private branch dump patterns.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
import math
from typing import Any, Dict, List, Optional


class SelfishMiningThreatLevel(str, Enum):
    CLEAR = "CLEAR"
    SUSPECTED = "SUSPECTED"
    CRITICAL_ATTACK = "CRITICAL_ATTACK"


@dataclass(frozen=True)
class BlockObservation:
    block_number: int
    block_hash: str
    parent_hash: str
    miner_or_pool: str
    is_orphaned: bool
    timestamp: float
    reorg_depth_caused: int = 0


@dataclass(frozen=True)
class SelfishMiningAlert:
    alert_id: str
    threat_level: SelfishMiningThreatLevel
    suspected_miner: str
    observed_orphan_rate: float
    expected_orphan_rate: float
    z_score: float
    window_blocks: int
    total_orphans: int
    private_release_streak: int
    reasons: List[str]
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["threat_level"] = self.threat_level.value
        return data


class SelfishMiningDetector:
    """Detects selfish mining anomalies via orphan rate statistics and private release patterns."""

    def __init__(
        self,
        baseline_orphan_rate: float = 0.02,
        min_window_for_stats: int = 30,
        z_warning_threshold: float = 3.0,
        z_critical_threshold: float = 5.0,
        private_release_threshold: int = 2,
    ):
        if not (0.0 < baseline_orphan_rate < 1.0):
            raise ValueError("baseline_orphan_rate must be between 0.0 and 1.0")

        self.baseline_orphan_rate = baseline_orphan_rate
        self.min_window_for_stats = min_window_for_stats
        self.z_warning_threshold = z_warning_threshold
        self.z_critical_threshold = z_critical_threshold
        self.private_release_threshold = private_release_threshold

        self._observations: List[BlockObservation] = []
        # Miner -> Count of private branch dumps (blocks published in burst causing reorgs)
        self._private_dump_counters: Dict[str, int] = {}

    def record_block(
        self,
        block_number: int,
        block_hash: str,
        parent_hash: str,
        miner_or_pool: str,
        is_orphaned: bool,
        timestamp: float,
        reorg_depth_caused: int = 0,
    ) -> BlockObservation:
        """Records a canonical or orphaned block observation."""
        obs = BlockObservation(
            block_number=block_number,
            block_hash=block_hash.lower(),
            parent_hash=parent_hash.lower(),
            miner_or_pool=miner_or_pool,
            is_orphaned=is_orphaned,
            timestamp=timestamp,
            reorg_depth_caused=reorg_depth_caused,
        )
        self._observations.append(obs)

        # Track strategic branch dumps: blocks causing reorgs of depth >= 1
        if not is_orphaned and reorg_depth_caused >= 1:
            self._private_dump_counters[miner_or_pool] = (
                self._private_dump_counters.get(miner_or_pool, 0) + 1
            )

        return obs

    def evaluate_miner(self, miner_or_pool: str) -> Optional[SelfishMiningAlert]:
        """
        Evaluates an individual miner or the aggregate network for selfish mining anomalies.
        """
        if len(self._observations) < self.min_window_for_stats:
            return None

        # Gather relevant observations
        total_observed = len(self._observations)
        total_orphans = sum(1 for o in self._observations if o.is_orphaned)

        # Observed rate across the active window
        observed_orphan_rate = total_orphans / total_observed

        # Expected binomial distribution parameters
        p = self.baseline_orphan_rate
        mu = total_observed * p
        variance = total_observed * p * (1.0 - p)
        sigma = math.sqrt(variance) if variance > 0 else 1e-6

        # Standard score (z-score)
        z = (total_orphans - mu) / sigma

        # Check private releases by the target miner
        dumps_by_target = self._private_dump_counters.get(miner_or_pool, 0)

        # Evaluate threat level
        reasons: List[str] = []
        threat_level = SelfishMiningThreatLevel.CLEAR

        if z >= self.z_critical_threshold or dumps_by_target >= (self.private_release_threshold * 2):
            threat_level = SelfishMiningThreatLevel.CRITICAL_ATTACK
            if z >= self.z_critical_threshold:
                reasons.append(
                    f"Orphan rate z-score {z:.2f} >= {self.z_critical_threshold:.1f} (extreme statistical deviation)"
                )
            if dumps_by_target >= (self.private_release_threshold * 2):
                reasons.append(
                    f"Miner '{miner_or_pool}' executed {dumps_by_target} private branch release dumps"
                )
        elif z >= self.z_warning_threshold or dumps_by_target >= self.private_release_threshold:
            threat_level = SelfishMiningThreatLevel.SUSPECTED
            if z >= self.z_warning_threshold:
                reasons.append(
                    f"Orphan rate z-score {z:.2f} >= {self.z_warning_threshold:.1f} (elevated orphan rate)"
                )
            if dumps_by_target >= self.private_release_threshold:
                reasons.append(
                    f"Miner '{miner_or_pool}' executed {dumps_by_target} private branch release dumps"
                )

        if threat_level == SelfishMiningThreatLevel.CLEAR:
            return None

        now = datetime.now(timezone.utc).timestamp()
        return SelfishMiningAlert(
            alert_id=f"sm-alert-{int(now)}-{miner_or_pool}",
            threat_level=threat_level,
            suspected_miner=miner_or_pool,
            observed_orphan_rate=round(observed_orphan_rate, 4),
            expected_orphan_rate=self.baseline_orphan_rate,
            z_score=round(z, 2),
            window_blocks=total_observed,
            total_orphans=total_orphans,
            private_release_streak=dumps_by_target,
            reasons=reasons,
            timestamp=now,
        )
