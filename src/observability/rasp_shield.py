"""
Task P08-003: Runtime Application Self-Protection (RASP) Shield Engine.
Integrates read-only RPC execution traces, GraphSense address clustering,
and threat intelligence signals (Forta / Rekt) to evaluate on-chain transaction risk.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.mcp_middleware.telemetry import query_web3_rpc, query_graphsense


class ThreatSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatSignalSource(str, Enum):
    RPC_TRACE = "RPC_TRACE"
    GRAPHSENSE = "GRAPHSENSE"
    FORTA = "FORTA"
    REKT = "REKT"


@dataclass(frozen=True)
class ThreatSignal:
    source: ThreatSignalSource
    severity: ThreatSeverity
    indicator: str
    details: Dict[str, Any]
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class RaspFinding:
    finding_id: str
    target_contract: str
    tx_hash: str
    severity: ThreatSeverity
    risk_score: float
    signals: List[ThreatSignal]
    is_suspicious: bool
    cluster_entity: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "target_contract": self.target_contract,
            "tx_hash": self.tx_hash,
            "severity": self.severity.value,
            "risk_score": round(self.risk_score, 3),
            "is_suspicious": self.is_suspicious,
            "cluster_entity": self.cluster_entity,
            "signals": [
                {
                    "source": s.source.value,
                    "severity": s.severity.value,
                    "indicator": s.indicator,
                    "details": s.details,
                    "detected_at": s.detected_at,
                }
                for s in self.signals
            ],
            "created_at": self.created_at,
        }


class RaspShield:
    """RASP engine providing multi-source runtime on-chain threat detection."""

    SEVERITY_WEIGHTS = {
        ThreatSeverity.LOW: 0.15,
        ThreatSeverity.MEDIUM: 0.40,
        ThreatSeverity.HIGH: 0.75,
        ThreatSeverity.CRITICAL: 1.00,
    }

    SUSPICIOUS_THRESHOLD = 0.50

    def __init__(
        self,
        rpc_query_fn: Optional[Callable[[str, Optional[List[Any]]], Dict[str, Any]]] = None,
        graphsense_query_fn: Optional[Callable[[str], Dict[str, Any]]] = None,
    ):
        self._rpc_fn = rpc_query_fn or query_web3_rpc
        self._graphsense_fn = graphsense_query_fn or query_graphsense

    def inspect_rpc_trace(
        self, target_contract: str, tx_hash: str, from_address: str, call_depth: int = 1
    ) -> List[ThreatSignal]:
        """Inspects read-only RPC traces and execution parameters for anomalies."""
        signals: List[ThreatSignal] = []

        # 1. Probe read-only eth_call simulation
        call_sim = self._rpc_fn("eth_call", [{"to": target_contract, "data": "0x"}, "latest"])
        if call_sim.get("status") == "reverted":
            signals.append(
                ThreatSignal(
                    source=ThreatSignalSource.RPC_TRACE,
                    severity=ThreatSeverity.MEDIUM,
                    indicator="TRACE_SIMULATION_REVERT",
                    details={"target": target_contract, "raw": call_sim},
                )
            )

        # 2. Call depth threshold check
        if call_depth > 4:
            signals.append(
                ThreatSignal(
                    source=ThreatSignalSource.RPC_TRACE,
                    severity=ThreatSeverity.HIGH,
                    indicator="ABNORMAL_CALL_DEPTH",
                    details={"call_depth": call_depth, "threshold": 4},
                )
            )

        # 3. Read-only transaction receipt check
        receipt = self._rpc_fn("eth_getTransactionReceipt", [tx_hash])
        if receipt.get("status") == "0x0":
            signals.append(
                ThreatSignal(
                    source=ThreatSignalSource.RPC_TRACE,
                    severity=ThreatSeverity.LOW,
                    indicator="TX_EXECUTION_FAILURE",
                    details={"tx_hash": tx_hash, "receipt": receipt},
                )
            )

        return signals

    def inspect_graphsense_cluster(self, address: str) -> Tuple[List[ThreatSignal], Optional[str]]:
        """Queries GraphSense cluster intelligence for sanctioned or flagged addresses."""
        signals: List[ThreatSignal] = []
        cluster_info = self._graphsense_fn(address)
        entity_name = cluster_info.get("entity")

        if cluster_info.get("is_sanctioned", False):
            signals.append(
                ThreatSignal(
                    source=ThreatSignalSource.GRAPHSENSE,
                    severity=ThreatSeverity.CRITICAL,
                    indicator="SANCTIONED_ADDRESS_CLUSTER",
                    details={"address": address, "cluster": cluster_info},
                )
            )
        elif cluster_info.get("risk_category") in ("mixer", "illicit", "darknet"):
            signals.append(
                ThreatSignal(
                    source=ThreatSignalSource.GRAPHSENSE,
                    severity=ThreatSeverity.HIGH,
                    indicator="HIGH_RISK_ENTITY_CLUSTER",
                    details={"address": address, "category": cluster_info.get("risk_category")},
                )
            )

        return signals, entity_name

    def evaluate_transaction(
        self,
        target_contract: str,
        tx_hash: str,
        from_address: str,
        call_depth: int = 1,
        external_signals: Optional[List[ThreatSignal]] = None,
    ) -> RaspFinding:
        """Evaluates complete RASP threat context across RPC traces, GraphSense, and threat feeds."""
        all_signals: List[ThreatSignal] = []

        # Step 1: Trace inspection
        trace_signals = self.inspect_rpc_trace(target_contract, tx_hash, from_address, call_depth)
        all_signals.extend(trace_signals)

        # Step 2: Address clustering inspection
        cluster_signals, entity = self.inspect_graphsense_cluster(from_address)
        all_signals.extend(cluster_signals)

        # Step 3: Ingest external intelligence (Forta / Rekt)
        if external_signals:
            all_signals.extend(external_signals)

        # Step 4: Calculate composite risk score
        if not all_signals:
            risk_score = 0.0
            max_severity = ThreatSeverity.LOW
        else:
            weights = [self.SEVERITY_WEIGHTS[s.severity] for s in all_signals]
            risk_score = 1.0
            for w in weights:
                risk_score *= (1.0 - w)
            risk_score = 1.0 - risk_score

            if any(s.severity == ThreatSeverity.CRITICAL for s in all_signals):
                max_severity = ThreatSeverity.CRITICAL
            elif any(s.severity == ThreatSeverity.HIGH for s in all_signals):
                max_severity = ThreatSeverity.HIGH
            elif any(s.severity == ThreatSeverity.MEDIUM for s in all_signals):
                max_severity = ThreatSeverity.MEDIUM
            else:
                max_severity = ThreatSeverity.LOW

        is_suspicious = risk_score >= self.SUSPICIOUS_THRESHOLD

        finding_seed = f"{target_contract}:{tx_hash}:{risk_score}".encode("utf-8")
        finding_id = f"RASP-{hashlib.sha256(finding_seed).hexdigest()[:12].upper()}"

        return RaspFinding(
            finding_id=finding_id,
            target_contract=target_contract,
            tx_hash=tx_hash,
            severity=max_severity,
            risk_score=risk_score,
            signals=all_signals,
            is_suspicious=is_suspicious,
            cluster_entity=entity,
        )
