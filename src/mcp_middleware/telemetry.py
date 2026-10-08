"""
Telemetry and Observability MCP Stubs (Task P04-008).
Provides structured stubs for Prometheus metrics exposition, ELK ECS logging,
Web3.py RPC node queries, and GraphSense on-chain clustering.
Live socket connections and production ingestion pipelines are deferred to Phase 8.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import json
import time


class PrometheusCollector:
    """In-memory collector and formatter for Prometheus metrics."""

    def __init__(self):
        self._metrics: Dict[str, Dict[str, Any]] = {}

    def set_gauge(self, name: str, value: float, help_text: str = "") -> None:
        self._metrics[name] = {
            "type": "gauge",
            "value": float(value),
            "help": help_text,
        }

    def inc_counter(self, name: str, value: float = 1.0, help_text: str = "") -> None:
        if name not in self._metrics:
            self._metrics[name] = {
                "type": "counter",
                "value": 0.0,
                "help": help_text,
            }
        self._metrics[name]["value"] += float(value)

    def export_text(self) -> str:
        """Renders metrics in standard Prometheus exposition format."""
        lines = []
        for name, meta in sorted(self._metrics.items()):
            if meta["help"]:
                lines.append(f"# HELP {name} {meta['help']}")
            lines.append(f"# TYPE {name} {meta['type']}")
            lines.append(f"{name} {meta['value']}")
        return "\n".join(lines) + ("\n" if lines else "")


class ECSLogFormatter:
    """Formats log records into Elastic Common Schema (ECS) compliant JSON."""

    def __init__(self, service_name: str = "blockchain-sec-mcp"):
        self.service_name = service_name

    def format(
        self,
        level: str,
        message: str,
        dataset: str = "security.telemetry",
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        record: Dict[str, Any] = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "log.level": level.upper(),
            "service.name": self.service_name,
            "event.dataset": dataset,
            "message": message,
        }
        if extra:
            record["extra"] = extra
        return record


# Module-level singletons for stub usage
_prom_collector = PrometheusCollector()
_ecs_formatter = ECSLogFormatter()


def query_prometheus(query: str) -> Dict[str, Any]:
    """
    Scaffolded Prometheus PromQL query evaluator.
    Returns structured metric evaluation format (live HTTP client deferred to Phase 8).
    """
    current_time = time.time()
    return {
        "status": "success",
        "phase": "phase-04-stub",
        "live_integration_deferred_to": "phase-8",
        "data": {
            "resultType": "vector",
            "result": [
                {
                    "metric": {"__name__": query.split("{")[0].strip()},
                    "value": [current_time, "1.0"],
                }
            ],
        },
    }


def query_elk(query: str, limit: int = 10) -> Dict[str, Any]:
    """
    Scaffolded ELK Elasticsearch query evaluator.
    Returns structured hits format (live cluster connection deferred to Phase 8).
    """
    sample_event = _ecs_formatter.format(
        level="INFO",
        message=f"Telemetry event matching query: {query}",
        extra={"query_filter": query},
    )
    return {
        "status": "success",
        "phase": "phase-04-stub",
        "live_integration_deferred_to": "phase-8",
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [
                {
                    "_index": "logs-security-remastered",
                    "_id": "stub-doc-001",
                    "_source": sample_event,
                }
            ],
        },
    }


def query_web3_rpc(method: str, params: Optional[List[Any]] = None) -> Dict[str, Any]:
    """
    Scaffolded Web3 JSON-RPC client stub for node health and gas tracking.
    (Live RPC network binding deferred to Phase 8).
    """
    params = params or []
    mock_responses: Dict[str, Any] = {
        "eth_blockNumber": "0x123456",
        "eth_gasPrice": "0x4a817c800",  # 20 Gwei
        "net_version": "1",
        "eth_syncing": False,
    }

    result = mock_responses.get(method, {"status": "ok", "mocked": True, "params": params})
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "phase": "phase-04-stub",
        "method": method,
        "result": result,
    }


def query_graphsense(currency: str, entity_type: str, identifier: str) -> Dict[str, Any]:
    """
    Scaffolded GraphSense on-chain address and cluster lookup stub.
    (Live GraphSense API integration deferred to Phase 8).
    """
    return {
        "status": "success",
        "phase": "phase-04-stub",
        "currency": currency.lower(),
        "entity_type": entity_type.lower(),
        "identifier": identifier,
        "cluster_id": f"cluster-{identifier[:8]}",
        "no_addresses": 1,
        "total_received": {"value": 1000000000, "currency": currency.upper()},
        "total_spent": {"value": 500000000, "currency": currency.upper()},
        "live_integration_deferred_to": "phase-8",
    }
