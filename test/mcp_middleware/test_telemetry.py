import unittest

from src.mcp_middleware.telemetry import (
    PrometheusCollector,
    ECSLogFormatter,
    query_prometheus,
    query_elk,
    query_web3_rpc,
    query_graphsense,
)


class TestTelemetry(unittest.TestCase):
    def test_prometheus_collector_and_exporter(self):
        collector = PrometheusCollector()
        collector.set_gauge("mcp_active_workers", 4.0, help_text="Active workers")
        collector.inc_counter("mcp_requests_total", 10.0, help_text="Total requests")

        output = collector.export_text()
        self.assertIn("# HELP mcp_active_workers Active workers", output)
        self.assertIn("# TYPE mcp_active_workers gauge", output)
        self.assertIn("mcp_active_workers 4.0", output)
        self.assertIn("# HELP mcp_requests_total Total requests", output)
        self.assertIn("# TYPE mcp_requests_total counter", output)
        self.assertIn("mcp_requests_total 10.0", output)

    def test_ecs_log_formatter(self):
        formatter = ECSLogFormatter(service_name="test-service")
        event = formatter.format(level="WARN", message="High latency detected", extra={"latency_ms": 150})
        self.assertEqual(event["service.name"], "test-service")
        self.assertEqual(event["log.level"], "WARN")
        self.assertEqual(event["message"], "High latency detected")
        self.assertEqual(event["extra"]["latency_ms"], 150)
        self.assertIn("@timestamp", event)

    def test_query_prometheus_stub(self):
        res = query_prometheus("mcp_cpu_usage{instance='localhost'}")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["phase"], "phase-04-stub")
        self.assertEqual(res["live_integration_deferred_to"], "phase-8")
        self.assertIn("data", res)

    def test_query_elk_stub(self):
        res = query_elk("level:ERROR AND service:mcp")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["phase"], "phase-04-stub")
        self.assertEqual(res["hits"]["total"]["value"], 1)
        self.assertEqual(len(res["hits"]["hits"]), 1)

    def test_query_web3_rpc_stub(self):
        res = query_web3_rpc("eth_blockNumber")
        self.assertEqual(res["jsonrpc"], "2.0")
        self.assertEqual(res["method"], "eth_blockNumber")
        self.assertEqual(res["result"], "0x123456")

        custom_res = query_web3_rpc("custom_method", [1, 2])
        self.assertEqual(custom_res["result"]["status"], "ok")

    def test_query_graphsense_stub(self):
        res = query_graphsense("eth", "address", "0x000000000000000000000000000000000000dead")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["currency"], "eth")
        self.assertEqual(res["entity_type"], "address")
        self.assertEqual(res["identifier"], "0x000000000000000000000000000000000000dead")
        self.assertIn("cluster_id", res)


if __name__ == "__main__":
    unittest.main()
