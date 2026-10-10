"""
Task P08-006: Continuous Telemetry Emissions for Deploy, Abort, and RASP Branches.
Enforces that smart contract deployment successes, consensus/policy aborts,
and RASP mitigations continuously emit Prometheus metrics and ECS security logs.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from src.mcp_middleware.telemetry import (
    PrometheusCollector,
    ECSLogFormatter,
    _prom_collector,
    _ecs_formatter,
)
from src.deployment.consensus_deployer import DeploymentPlan, DeploymentReceipt
from src.deployment.readiness_policy_gate import DeploymentAbortEvent, AbortReasonCode

logger = logging.getLogger(__name__)


class LifecycleTelemetryEmitter:
    """Non-blocking continuous telemetry emitter for deployment and runtime events."""

    def __init__(
        self,
        prom_collector: Optional[PrometheusCollector] = None,
        ecs_formatter: Optional[ECSLogFormatter] = None,
    ):
        self._prom = prom_collector or _prom_collector
        self._ecs = ecs_formatter or _ecs_formatter
        self._emitted_logs: List[Dict[str, Any]] = []

    @property
    def emitted_logs(self) -> List[Dict[str, Any]]:
        """Returns the in-memory log buffer."""
        return list(self._emitted_logs)

    def record_deploy_success(
        self,
        plan: DeploymentPlan,
        receipt: DeploymentReceipt,
        network: str = "mainnet",
    ) -> Dict[str, Any]:
        """Emits metrics and ECS security logs for successful contract deployment."""
        log_payload: Dict[str, Any] = {}
        try:
            # 1. Prometheus metric emission
            target = getattr(plan, "target_contract", "UnknownContract")
            self._prom.record_deploy(target=target, network=network)

            # 2. ECS structured log formatting
            details = {
                "plan_id": receipt.plan_id,
                "deployment_id": receipt.deployment_id,
                "contract_address": receipt.contract_address,
                "tx_hash": receipt.tx_hash,
                "deployer_address": receipt.deployer_address,
                "certificate_attestation_id": receipt.certificate_attestation_id,
                "status": receipt.status.value if hasattr(receipt.status, "value") else str(receipt.status),
                "deployed_at": receipt.deployed_at,
                "network": network,
            }
            log_payload = self._ecs.format_event(
                event_name="CONTRACT_DEPLOYMENT_SUCCESS",
                category="deployment",
                outcome="success",
                details=details,
                level="INFO",
            )
            self._emitted_logs.append(log_payload)
        except Exception as e:
            logger.error("Non-blocking failure emitting deploy success telemetry: %s", e)

        return log_payload

    def record_deploy_abort(
        self,
        abort_event: DeploymentAbortEvent,
        network: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Emits metrics and ECS security logs for aborted deployment pipelines."""
        log_payload: Dict[str, Any] = {}
        try:
            target_network = network or getattr(abort_event, "targetNetwork", "mainnet")
            abort_code = getattr(abort_event, "abortCode", None)
            reason_str = abort_code.value if hasattr(abort_code, "value") else str(abort_code)
            target_contract = getattr(abort_event, "targetContract", "UnknownContract")

            # 1. Prometheus metric emission
            self._prom.record_abort(reason=reason_str, target=target_contract)

            # 2. ECS structured log formatting
            details = {
                "plan_id": getattr(abort_event, "planId", ""),
                "target_contract": target_contract,
                "target_network": target_network,
                "abort_code": reason_str,
                "reason": getattr(abort_event, "reason", ""),
                "event_type": getattr(abort_event, "eventType", "DEPLOYMENT_ABORT"),
                "event_digest": getattr(abort_event, "eventDigest", ""),
                "timestamp": getattr(abort_event, "timestamp", ""),
            }
            log_payload = self._ecs.format_event(
                event_name="DEPLOYMENT_PIPELINE_ABORTED",
                category="deployment",
                outcome="failure",
                details=details,
                level="WARN" if reason_str != AbortReasonCode.ERR_UNCONFIGURED_HARDWARE.value else "ERROR",
            )
            self._emitted_logs.append(log_payload)
        except Exception as e:
            logger.error("Non-blocking failure emitting deploy abort telemetry: %s", e)

        return log_payload

    def record_quorum_update(self, network: str, quorum_ratio: float) -> None:
        """Updates consensus quorum gauge metric."""
        try:
            self._prom.record_quorum_ratio(network=network, ratio=quorum_ratio)
        except Exception as e:
            logger.error("Non-blocking failure emitting quorum telemetry: %s", e)

    def record_rasp_mitigation(
        self,
        finding_id: str,
        target_contract: str,
        action: str,
        network: str = "mainnet",
    ) -> Dict[str, Any]:
        """Emits telemetry for RASP active mitigation actions."""
        log_payload: Dict[str, Any] = {}
        try:
            # 1. Prometheus metric emission
            self._prom.record_rasp_finding(target=target_contract, finding_id=finding_id)

            # 2. ECS log formatting
            details = {
                "finding_id": finding_id,
                "target_contract": target_contract,
                "mitigation_action": action,
                "network": network,
            }
            log_payload = self._ecs.format_event(
                event_name="RASP_MITIGATION_ACTION",
                category="security",
                outcome="success",
                details=details,
                level="CRITICAL",
            )
            self._emitted_logs.append(log_payload)
        except Exception as e:
            logger.error("Non-blocking failure emitting RASP mitigation telemetry: %s", e)

        return log_payload
