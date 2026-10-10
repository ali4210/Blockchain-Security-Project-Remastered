"""
Task P08-002: Prometheus and Elasticsearch Real Query Functions.
Provides HTTP query clients for Prometheus metrics (instant and range queries)
and Elasticsearch ECS security log queries and document indexing.
"""

import base64
from dataclasses import dataclass, field
import json
import logging
from typing import Any, Dict, List, Optional
import urllib.parse
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)


@dataclass
class PrometheusQueryResult:
    status: str
    result_type: str
    data: List[Dict[str, Any]]
    raw: Dict[str, Any]

    @property
    def is_success(self) -> bool:
        return self.status == "success"

    def get_scalar_value(self) -> Optional[float]:
        """Extracts first scalar value if vector contains results."""
        if not self.data:
            return None
        first = self.data[0]
        val = first.get("value")
        if isinstance(val, (list, tuple)) and len(val) >= 2:
            try:
                return float(val[1])
            except (ValueError, TypeError):
                return None
        return None


class PrometheusQueryClient:
    """Client for querying Prometheus HTTP API v1."""

    def __init__(self, base_url: str = "http://localhost:9090", timeout: float = 3.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def query(self, expr: str, timestamp: Optional[float] = None) -> PrometheusQueryResult:
        """Executes instant vector query against /api/v1/query."""
        params = {"query": expr}
        if timestamp is not None:
            params["time"] = str(timestamp)
        url = f"{self.base_url}/api/v1/query?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return PrometheusQueryResult(
                    status=data.get("status", "error"),
                    result_type=data.get("data", {}).get("resultType", ""),
                    data=data.get("data", {}).get("result", []),
                    raw=data,
                )
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            logger.warning("Prometheus query failed for %s: %s", expr, e)
            return PrometheusQueryResult(status="error", result_type="", data=[], raw={"error": str(e)})

    def query_range(self, expr: str, start: float, end: float, step: str = "15s") -> PrometheusQueryResult:
        """Executes range matrix query against /api/v1/query_range."""
        params = {
            "query": expr,
            "start": str(start),
            "end": str(end),
            "step": step,
        }
        url = f"{self.base_url}/api/v1/query_range?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return PrometheusQueryResult(
                    status=data.get("status", "error"),
                    result_type=data.get("data", {}).get("resultType", ""),
                    data=data.get("data", {}).get("result", []),
                    raw=data,
                )
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            logger.warning("Prometheus range query failed for %s: %s", expr, e)
            return PrometheusQueryResult(status="error", result_type="", data=[], raw={"error": str(e)})

    def get_metric_value(self, metric_name: str) -> Optional[float]:
        """Convenience method returning current scalar value of a metric."""
        res = self.query(metric_name)
        return res.get_scalar_value()


class ElasticsearchQueryClient:
    """Client for querying and indexing ECS records in Elasticsearch."""

    def __init__(
        self,
        base_url: str = "http://localhost:9200",
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 3.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.username and self.password:
            auth_str = f"{self.username}:{self.password}"
            b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
            headers["Authorization"] = f"Basic {b64_auth}"
        return headers

    def search(self, index_pattern: str, query_dsl: Dict[str, Any]) -> Dict[str, Any]:
        """Executes a search against the specified index pattern."""
        url = f"{self.base_url}/{index_pattern}/_search"
        payload = json.dumps(query_dsl).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=self._get_headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.reason}", "status": e.code}
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            logger.warning("Elasticsearch search failed on %s: %s", index_pattern, e)
            return {"error": str(e), "status": 500}

    def index_document(self, index: str, document: Dict[str, Any], doc_id: Optional[str] = None) -> Dict[str, Any]:
        """Indexes an ECS document into the target index."""
        url = f"{self.base_url}/{index}/_doc"
        if doc_id:
            url = f"{url}/{urllib.parse.quote(doc_id)}"
        payload = json.dumps(document).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=self._get_headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.reason}", "status": e.code}
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            logger.warning("Elasticsearch index failed on %s: %s", index, e)
            return {"error": str(e), "status": 500}

    def query_security_events(
        self,
        finding_id: Optional[str] = None,
        event_category: Optional[str] = None,
        size: int = 50,
    ) -> List[Dict[str, Any]]:
        """Queries security events filtered by finding ID or category."""
        filters = []
        if finding_id:
            filters.append({"term": {"labels.finding_id": finding_id}})
        if event_category:
            filters.append({"term": {"event.category": event_category}})

        query: Dict[str, Any] = {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
        }
        res = self.search("blockchain-soc-logs-*", query)
        hits = res.get("hits", {}).get("hits", [])
        return [hit.get("_source", {}) for hit in hits]


class SOCTelemetryClient:
    """Unified telemetry query client combining metrics and log correlations."""

    def __init__(
        self,
        prometheus_url: str = "http://localhost:9090",
        elasticsearch_url: str = "http://localhost:9200",
        es_user: Optional[str] = None,
        es_pass: Optional[str] = None,
    ):
        self.prometheus = PrometheusQueryClient(base_url=prometheus_url)
        self.elasticsearch = ElasticsearchQueryClient(base_url=elasticsearch_url, username=es_user, password=es_pass)

    def get_system_telemetry_snapshot(self) -> Dict[str, Any]:
        """Gathers unified snapshot of metrics and recent security logs."""
        deploy_total = self.prometheus.get_metric_value("blockchain_soc_deploy_total")
        abort_total = self.prometheus.get_metric_value("blockchain_soc_deploy_aborted_total")
        quorum_ratio = self.prometheus.get_metric_value("blockchain_soc_consensus_quorum_ratio")
        suspicious_txs = self.prometheus.get_metric_value("blockchain_soc_rasp_suspicious_tx_total")

        recent_events = self.elasticsearch.query_security_events(size=10)

        return {
            "metrics": {
                "blockchain_soc_deploy_total": deploy_total,
                "blockchain_soc_deploy_aborted_total": abort_total,
                "blockchain_soc_consensus_quorum_ratio": quorum_ratio,
                "blockchain_soc_rasp_suspicious_tx_total": suspicious_txs,
            },
            "recent_security_events_count": len(recent_events),
            "recent_security_events": recent_events,
        }
