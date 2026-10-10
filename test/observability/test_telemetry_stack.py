"""
Task P08-001: Unit Tests for Telemetry Stack Harness and Profiles.
Validates profile construction, configuration serialization, TCP port checking,
HTTP health inspection (including 401 auth challenges), and documentation existence.
"""

from pathlib import Path
import unittest
from unittest.mock import patch, MagicMock
import urllib.error

from src.observability.telemetry_stack import (
    TelemetryProfile,
    EndpointConfig,
    TelemetryStackConfig,
    TelemetryStackManager,
)


class TestTelemetryStack(unittest.TestCase):
    def test_endpoint_config_url(self):
        ep = EndpointConfig(host="127.0.0.1", port=9090, path="/metrics")
        self.assertEqual(ep.url, "http://127.0.0.1:9090/metrics")

    def test_elk_profile_creation(self):
        cfg = TelemetryStackConfig.create_elk_profile()
        self.assertEqual(cfg.profile, TelemetryProfile.ELK)
        self.assertEqual(cfg.prometheus_endpoint.port, 9090)
        self.assertEqual(cfg.log_ingest_endpoint.port, 9200)
        self.assertEqual(cfg.visualization_endpoint.port, 5601)
        self.assertEqual(cfg.grafana_endpoint.port, 3000)
        self.assertEqual(cfg.index_prefix, "blockchain-soc-logs-")

        d = cfg.to_dict()
        self.assertEqual(d["profile"], "elk")
        self.assertIn("9200", d["logIngest"])
        self.assertIn("5601", d["visualization"])
        self.assertIn("3000", d["grafana"])

    def test_lightweight_profile_creation(self):
        cfg = TelemetryStackConfig.create_lightweight_profile()
        self.assertEqual(cfg.profile, TelemetryProfile.GRAFANA_LOKI)
        self.assertEqual(cfg.prometheus_endpoint.port, 9090)
        self.assertEqual(cfg.log_ingest_endpoint.port, 3100)
        self.assertEqual(cfg.visualization_endpoint.port, 3000)

        d = cfg.to_dict()
        self.assertEqual(d["profile"], "grafana_loki")
        self.assertIn("3100", d["logIngest"])
        self.assertIn("3000", d["visualization"])

    def test_documentation_and_config_files_exist(self):
        self.assertTrue(Path("docs/OBSERVABILITY_STACK.md").exists())
        self.assertTrue(Path("config/telemetry/prometheus.blockchain-soc.yml").exists())

    @patch("socket.create_connection")
    def test_check_tcp_port_success(self, mock_create):
        mock_conn = MagicMock()
        mock_create.return_value.__enter__.return_value = mock_conn

        manager = TelemetryStackManager()
        self.assertTrue(manager.check_tcp_port("localhost", 9090))
        mock_create.assert_called_once_with(("localhost", 9090), timeout=1.0)

    @patch("socket.create_connection", side_effect=ConnectionRefusedError("Offline"))
    def test_check_tcp_port_failure(self, mock_create):
        manager = TelemetryStackManager()
        self.assertFalse(manager.check_tcp_port("localhost", 9090))

    @patch("urllib.request.urlopen")
    def test_probe_http_health_success_200(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        manager = TelemetryStackManager()
        ep = EndpointConfig("localhost", 9090, "/-/healthy")
        self.assertTrue(manager.probe_http_health(ep))

    @patch("urllib.request.urlopen")
    def test_probe_http_health_accepts_auth_challenge_401(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://localhost:9200/",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=None,
        )

        manager = TelemetryStackManager()
        ep = EndpointConfig("localhost", 9200, "/")
        self.assertTrue(manager.probe_http_health(ep))

    @patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused"))
    def test_probe_http_health_failure(self, mock_urlopen):
        manager = TelemetryStackManager()
        ep = EndpointConfig("localhost", 9999, "/invalid")
        self.assertFalse(manager.probe_http_health(ep))

    @patch("src.observability.telemetry_stack.TelemetryStackManager.check_tcp_port", return_value=True)
    def test_get_stack_status_reporting(self, mock_tcp):
        manager = TelemetryStackManager()
        status = manager.get_stack_status()
        self.assertEqual(status["profile"], "elk")
        self.assertTrue(status["prometheus_alive"])
        self.assertTrue(status["log_ingest_alive"])
        self.assertTrue(status["visualization_alive"])
        self.assertTrue(status["grafana_alive"])


if __name__ == "__main__":
    unittest.main()
