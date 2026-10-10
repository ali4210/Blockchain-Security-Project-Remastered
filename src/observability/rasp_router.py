"""
Task P08-005: Route Validated RASP Findings to Agent B (Threat Hunter).
Filters shadow-fork exploit verification reports, maps execution traces to SIEM telemetry,
and routes actionable incidents into Agent B's threat correlation pipeline.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import logging
from typing import Any, Callable, Dict, List, Optional

from src.agents.state import SwarmState
from src.agents.agent_b_threat_hunter import threat_hunter_node
from src.observability.shadow_fork_verifier import (
    AgentEShadowVerificationReport,
    ShadowReplayOutcome,
)

logger = logging.getLogger(__name__)


class RoutingStatus(str, Enum):
    ROUTED_TO_AGENT_B = "ROUTED_TO_AGENT_B"
    FILTERED_BENIGN = "FILTERED_BENIGN"
    INVALID_REPORT = "INVALID_REPORT"


@dataclass
class RouterDispatchResult:
    status: RoutingStatus
    finding_id: str
    target: str
    routed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    final_state: Optional[SwarmState] = None
    agent_b_findings: List[Dict[str, Any]] = field(default_factory=list)
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "finding_id": self.finding_id,
            "target": self.target,
            "routed_at": self.routed_at,
            "agent_b_findings_count": len(self.agent_b_findings),
            "reason": self.reason,
        }


class RaspThreatRouter:
    """Routes confirmed on-chain RASP exploit findings into Agent B."""

    def __init__(
        self,
        threat_hunter_fn: Optional[Callable[[SwarmState], SwarmState]] = None,
    ):
        self._threat_hunter_fn = threat_hunter_fn or threat_hunter_node

    def should_route(self, report: AgentEShadowVerificationReport) -> bool:
        """Determines if a verification report warrants Agent B threat hunting."""
        if report.outcome == ShadowReplayOutcome.CONFIRMED_EXPLOIT:
            return True
        if report.severity_level in ("SEV-1", "SEV-2"):
            return True
        return False

    def format_siem_telemetry(self, report: AgentEShadowVerificationReport) -> str:
        """Formats shadow execution trace into SIEM log format for Agent B."""
        trace = report.execution_trace
        tx_hash = trace.get("tx_hash", "0x0")
        gas_used = trace.get("gas_used", 0)
        balance_delta = trace.get("balance_delta_wei", 0)

        # Estimate ETH loss from wei
        eth_delta = abs(balance_delta) / 10**18

        lines = [
            f"TIMESTAMP={datetime.now(timezone.utc).isoformat()} EVENT=RASP_SHADOW_REPLAY_EXPLOIT",
            f"FINDING_ID={report.finding_id} TARGET={report.target} OUTCOME={report.outcome.value}",
            f"TX_HASH={tx_hash} GAS_USED={gas_used} VALUE_DRAINED_ETH={eth_delta:.4f}",
            f"SEVERITY={report.severity_level} CONTAINMENT_STATUS={report.containment_status}",
            f"PLAYBOOK_ACTIONS={','.join(report.playbook_actions)}",
            f"AUDIT_DIGEST={report.audit_record_digest}",
        ]
        return " ".join(lines)

    def route_to_agent_b(
        self,
        report: AgentEShadowVerificationReport,
        initial_state: Optional[SwarmState] = None,
    ) -> RouterDispatchResult:
        """Evaluates and routes a validated report to Agent B."""
        if not report or not report.finding_id:
            return RouterDispatchResult(
                status=RoutingStatus.INVALID_REPORT,
                finding_id="UNKNOWN",
                target="UNKNOWN",
                reason="Verification report is empty or missing finding_id",
            )

        # Step 1: Filtering check
        if not self.should_route(report):
            return RouterDispatchResult(
                status=RoutingStatus.FILTERED_BENIGN,
                finding_id=report.finding_id,
                target=report.target,
                reason=f"Outcome {report.outcome.value} and severity {report.severity_level} do not meet escalation threshold",
            )

        # Step 2: Format SIEM telemetry
        telemetry_log_line = self.format_siem_telemetry(report)

        # Step 3: Construct SwarmState
        base_state = initial_state or SwarmState(
            target_contract=report.target,
            findings=[],
            current_stage="rasp_verified",
            escalation_needed=True,
            errors=[],
            metadata={},
        )

        base_state["target_contract"] = report.target
        base_state["telemetry_logs"] = telemetry_log_line
        base_state["escalation_needed"] = True

        metadata = dict(base_state.get("metadata", {}))
        metadata["rasp_escalated"] = True
        metadata["rasp_finding_id"] = report.finding_id
        metadata["shadow_outcome"] = report.outcome.value
        metadata["shadow_report"] = report.to_dict()
        base_state["metadata"] = metadata

        # Step 4: Dispatch to Agent B
        try:
            prior_count = len(base_state.get("findings", []))
            updated_state = self._threat_hunter_fn(base_state)
            new_findings = updated_state.get("findings", [])[prior_count:]

            return RouterDispatchResult(
                status=RoutingStatus.ROUTED_TO_AGENT_B,
                finding_id=report.finding_id,
                target=report.target,
                final_state=updated_state,
                agent_b_findings=new_findings,
            )
        except Exception as e:
            logger.error("Error executing Agent B for finding %s: %s", report.finding_id, e)
            return RouterDispatchResult(
                status=RoutingStatus.INVALID_REPORT,
                finding_id=report.finding_id,
                target=report.target,
                reason=f"Agent B execution failed: {str(e)}",
            )
