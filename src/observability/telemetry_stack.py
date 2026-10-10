"""
Task P08-001: Telemetry Stack Harness and Health Probe.
Manages configuration profiles for Prometheus + ELK (Enterprise) and
Prometheus + Grafana/Loki (Lightweight) observability pipelines.
Integrates directly with live host services on localhost.
"""

from dataclasses import dataclass, field
from enum import Enum
import socket
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error


class TelemetryProfile(str, Enum):
    ELK = "elk"
    GRAFANA_LOKI = "grafana_loki"


@dataclass(frozen=True)
class EndpointConfig:
    host: str
    port: int
    path: str = ""
    protocol: str = "http"

    @property
    def url(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}{self.path}"


@dataclass
class TelemetryStackConfig:
    profile: TelemetryProfile = TelemetryProfile.ELK
    prometheus_endpoint: EndpointConfig = field(default_factory=lambda: EndpointConfig("localhost", 9090, "/-/healthy"))
    metrics_exporter_ports: List[int] = field(default_factory=lambda: [9100, 9101, 9102])
    log_ingest_endpoint: EndpointConfig = field(default_factory=lambda: EndpointConfig("localhost", 9200, "/"))
    visualization_endpoint: EndpointConfig = field(default_factory=lambda: EndpointConfig("localhost", 5601, "/api/status"))
    grafana_endpoint: EndpointConfig = field(default_factory=lambda: EndpointConfig("localhost", 3000, "/api/health"))
    index_prefix: str = "blockchain-soc-logs-"
    scrape_interval_seconds: int = 5

    @classmethod
    def create_elk_profile(cls) -> "TelemetryStackConfig":
        return cls(
            profile=TelemetryProfile.ELK,
            prometheus_endpoint=EndpointConfig("localhost", 9090, "/-/healthy"),
            metrics_exporter_ports=[9100, 9101, 9102],
            log_ingest_endpoint=EndpointConfig("localhost", 9200, "/"),
            visualization_endpoint=EndpointConfig("localhost", 5601, "/api/status"),
            grafana_endpoint=EndpointConfig("localhost", 3000, "/api/health"),
            index_prefix="blockchain-soc-logs-",
            scrape_interval_seconds=5,
        )

    @classmethod
    def create_lightweight_profile(cls) -> "TelemetryStackConfig":
        return cls(
            profile=TelemetryProfile.GRAFANA_LOKI,
            prometheus_endpoint=EndpointConfig("localhost", 9090, "/-/healthy"),
            metrics_exporter_ports=[9100, 9101, 9102],
            log_ingest_endpoint=EndpointConfig("localhost", 3100, "/ready"),
            visualization_endpoint=EndpointConfig("localhost", 3000, "/api/health"),
            grafana_endpoint=EndpointConfig("localhost", 3000, "/api/health"),
            index_prefix="blockchain-soc-logs-",
            scrape_interval_seconds=5,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile": self.profile.value,
            "prometheus": self.prometheus_endpoint.url,
            "metricsExporters": self.metrics_exporter_ports,
            "logIngest": self.log_ingest_endpoint.url,
            "visualization": self.visualization_endpoint.url,
            "grafana": self.grafana_endpoint.url,
            "indexPrefix": self.index_prefix,
            "scrapeIntervalSeconds": self.scrape_interval_seconds,
        }


class TelemetryStackManager:
    """Manages telemetry environment probes, health inspections, and profile resolution."""

    def __init__(self, config: Optional[TelemetryStackConfig] = None):
        self.config = config or TelemetryStackConfig.create_elk_profile()

    def check_tcp_port(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Verifies whether a TCP port is active and reachable."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def probe_http_health(self, endpoint: EndpointConfig, timeout: float = 2.0) -> bool:
        """Sends an HTTP GET probe to determine if service endpoint responds (accepting 200, 204, or 401)."""
        try:
            req = urllib.request.Request(endpoint.url, headers={"User-Agent": "BlockchainSOC-TelemetryProbe/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status in (200, 204)
        except urllib.error.HTTPError as e:
            # HTTP 401/403 proves the HTTP daemon is active and enforcing auth
            return e.code in (200, 204, 401, 403)
        except (urllib.error.URLError, TimeoutError, OSError):
            return False

    def get_stack_status(self) -> Dict[str, Any]:
        """Returns health probe state for active profile components."""
        return {
            "profile": self.config.profile.value,
            "prometheus_alive": self.check_tcp_port(self.config.prometheus_endpoint.host, self.config.prometheus_endpoint.port),
            "log_ingest_alive": self.check_tcp_port(self.config.log_ingest_endpoint.host, self.config.log_ingest_endpoint.port),
            "visualization_alive": self.check_tcp_port(self.config.visualization_endpoint.host, self.config.visualization_endpoint.port),
            "grafana_alive": self.check_tcp_port(self.config.grafana_endpoint.host, self.config.grafana_endpoint.port),
            "config": self.config.to_dict(),
        }
