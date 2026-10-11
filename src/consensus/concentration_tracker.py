"""
Task P11-003: PoW/PoS Consensus Concentration Tracker.
Computes Nakamoto coefficient, Herfindahl-Hirschman Index (HHI),
single entity dominance, and cumulative top-N concentration shares.
Enforces warning (>33% or top-3 >51%) and critical (>50%) thresholds.
"""

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class ConcentrationAlertLevel(str, Enum):
    CLEAR = "CLEAR"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class ConcentrationMetrics:
    total_entities: int
    nakamoto_coefficient: int
    hhi: float
    max_single_share: float
    top3_cumulative_share: float
    top_entity_id: str
    alert_level: ConcentrationAlertLevel
    alert_reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["alert_level"] = self.alert_level.value
        return data


class ConsensusConcentrationTracker:
    """Tracks validator stake or mining power concentration across sliding windows."""

    def __init__(
        self,
        window_size: int = 100,
        warning_single_threshold: float = 0.33,
        critical_single_threshold: float = 0.50,
        warning_top3_threshold: float = 0.51,
    ):
        if window_size < 1:
            raise ValueError("window_size must be at least 1")
        self.window_size = window_size
        self.warning_single_threshold = warning_single_threshold
        self.critical_single_threshold = critical_single_threshold
        self.warning_top3_threshold = warning_top3_threshold

        # Sliding window buffer: List of tuples (entity_id, weight)
        self._window: List[Tuple[str, float]] = []

    def record_production_event(self, entity_id: str, weight: float = 1.0) -> None:
        """Records a block mint or validation event with corresponding weight."""
        if not entity_id:
            raise ValueError("entity_id must not be empty")
        if weight <= 0:
            raise ValueError("weight must be positive")

        self._window.append((entity_id, float(weight)))
        if len(self._window) > self.window_size:
            self._window.pop(0)

    def set_explicit_distribution(self, distribution: Dict[str, float]) -> None:
        """Sets explicit static snapshot of validator stake or hashpower distribution."""
        self._window.clear()
        for entity_id, weight in distribution.items():
            if weight > 0:
                self._window.append((entity_id, float(weight)))

    def calculate_metrics(self) -> ConcentrationMetrics:
        """Calculates Nakamoto coefficient, HHI, and concentration risk level."""
        if not self._window:
            return ConcentrationMetrics(
                total_entities=0,
                nakamoto_coefficient=0,
                hhi=0.0,
                max_single_share=0.0,
                top3_cumulative_share=0.0,
                top_entity_id="none",
                alert_level=ConcentrationAlertLevel.CLEAR,
                alert_reasons=[],
            )

        # Aggregate weights per entity
        entity_weights: Dict[str, float] = {}
        total_weight = 0.0
        for entity_id, weight in self._window:
            entity_weights[entity_id] = entity_weights.get(entity_id, 0.0) + weight
            total_weight += weight

        if total_weight == 0.0:
            total_weight = 1.0

        # Sort entities by weight descending
        sorted_entities = sorted(
            entity_weights.items(),
            key=lambda item: item[1],
            reverse=True,
        )

        # Calculate percentage shares (0.0 to 1.0)
        shares = [w / total_weight for _, w in sorted_entities]

        # 1. Herfindahl-Hirschman Index (scale 0 to 10,000)
        hhi = round(sum((s * 100.0) ** 2 for s in shares), 2)

        # 2. Nakamoto Coefficient: min entities needed to strictly exceed 50% (> 0.50)
        accumulated = 0.0
        nakamoto = 0
        for s in shares:
            accumulated += s
            nakamoto += 1
            if accumulated > 0.50:
                break

        # 3. Share ratios
        max_single_share = round(shares[0], 4) if shares else 0.0
        top_entity_id = sorted_entities[0][0] if sorted_entities else "none"
        top3_cumulative_share = round(sum(shares[:3]), 4) if len(shares) >= 3 else round(sum(shares), 4)

        # 4. Alert Level Evaluation
        reasons: List[str] = []
        alert_level = ConcentrationAlertLevel.CLEAR

        if max_single_share >= self.critical_single_threshold:
            alert_level = ConcentrationAlertLevel.CRITICAL
            reasons.append(
                f"Single entity '{top_entity_id}' controls {max_single_share*100:.1f}% >= {self.critical_single_threshold*100:.1f}% (51% safety hazard)"
            )
        elif max_single_share >= self.warning_single_threshold:
            alert_level = ConcentrationAlertLevel.WARNING
            reasons.append(
                f"Single entity '{top_entity_id}' controls {max_single_share*100:.1f}% >= {self.warning_single_threshold*100:.1f}% (BFT liveness hazard)"
            )

        if top3_cumulative_share >= self.warning_top3_threshold and alert_level != ConcentrationAlertLevel.CRITICAL:
            alert_level = ConcentrationAlertLevel.WARNING
            reasons.append(
                f"Top 3 entities control {top3_cumulative_share*100:.1f}% >= {self.warning_top3_threshold*100:.1f}% (Cartel risk)"
            )

        return ConcentrationMetrics(
            total_entities=len(entity_weights),
            nakamoto_coefficient=nakamoto,
            hhi=hhi,
            max_single_share=max_single_share,
            top3_cumulative_share=top3_cumulative_share,
            top_entity_id=top_entity_id,
            alert_level=alert_level,
            alert_reasons=reasons,
        )
