"""
Task P08-002: Unit Tests for Prometheus and Elasticsearch Query Clients.
Validates instant query, range query, metric scalar extraction,
Elasticsearch searching, indexing, security event filtering,
and unified SOC snapshot compilation with mock responses and error handling.
"""

import json
import unittest
from unittest.mock import patch, MagicMock
import urllib.error

from src.observability.telemetry_client import (
    PrometheusQueryResult,
    PrometheusQueryClient,
    ElasticsearchQueryClient,
    SOCTelemetryClient,
)


class TestTelemetryClient(unittest.TestCase):
    def test_prometheus_query_result_parsing(self):
        raw = {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{"metric": {"__name__": "deploy_count"}, "value": [1700000000.0, "42.0"]}],
            },
        }
        res = PrometheusQueryResult(
            status=raw["status"],
            result_type=raw["data"]["resultType"],
            data=raw["data"]["result"],
            raw=raw,
        )
        self.assertTrue(res.is_success)
        self.assertEqual(res.get_scalar_value(), 42.0)

    def test_prometheus_query_result_empty(self):
        res = PrometheusQueryResult(status="success", result_type="vector", data=[], raw={})
        self.assertTrue(res.is_success)
        self.assertIsNone(res.get_scalar_value())

    @patch("urllib.request.urlopen")
    def test_prometheus_instant_query_success(self, mock_urlopen):
        mock_response = MagicMock()
        payload = {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{"metric": {"job": "agents"}, "value": [1700000000, "1.0"]}],
            },
        }
        mock_response.read.return_value = json.dumps(payload).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        client = PrometheusQueryClient()
        res = client.query("up{job='agents'}")
        self.assertTrue(res.is_success)
        self.assertEqual(res.get_scalar_value(), 1.0)

    @patch("urllib.request.urlopen")
    def test_prometheus_range_query_success(self, mock_urlopen):
        mock_response = MagicMock()
        payload = {
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [{"metric": {}, "values": [[1700000000, "1.0"], [1700000015, "2.0"]]}],
            },
        }
        mock_response.read.return_value = json.dumps(payload).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        client = PrometheusQueryClient()
        res = client.query_range("up", start=1700000000, end=1700000030, step="15s")
        self.assertTrue(res.is_success)
        self.assertEqual(res.result_type, "matrix")

    @patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused"))
    def test_prometheus_query_network_error(self, mock_urlopen):
        client = PrometheusQueryClient()
        res = client.query("up")
        self.assertFalse(res.is_success)
        self.assertEqual(res.status, "error")

    @patch("urllib.request.urlopen")
    def test_elasticsearch_search_success(self, mock_urlopen):
        mock_response = MagicMock()
        payload = {
            "took": 2,
            "timed_out": False,
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [{"_id": "doc1", "_source": {"event": {"category": "security"}, "message": "auth success"}}],
            },
        }
        mock_response.read.return_value = json.dumps(payload).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        client = ElasticsearchQueryClient()
        res = client.search("blockchain-soc-logs-*", {"query": {"match_all": {}}})
        self.assertIn("hits", res)
        self.assertEqual(len(res["hits"]["hits"]), 1)

    @patch("urllib.request.urlopen")
    def test_elasticsearch_query_security_events(self, mock_urlopen):
        mock_response = MagicMock()
        payload = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "labels": {"finding_id": "FINDING-VAULT-01"},
                            "event": {"category": "security"},
                            "message": "Deployment certified",
                        }
                    }
                ]
            }
        }
        mock_response.read.return_value = json.dumps(payload).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        client = ElasticsearchQueryClient()
        events = client.query_security_events(finding_id="FINDING-VAULT-01")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["labels"]["finding_id"], "FINDING-VAULT-01")

    @patch("urllib.request.urlopen")
    def test_elasticsearch_index_document(self, mock_urlopen):
        mock_response = MagicMock()
        payload = {"_index": "blockchain-soc-logs-2026.10.10", "_id": "doc-01", "result": "created"}
        mock_response.read.return_value = json.dumps(payload).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        client = ElasticsearchQueryClient()
        res = client.index_document("blockchain-soc-logs-2026.10.10", {"test": "data"}, doc_id="doc-01")
        self.assertEqual(res.get("result"), "created")

    @patch("urllib.request.urlopen")
    def test_soc_telemetry_snapshot_compilation(self, mock_urlopen):
        def mock_urlopen_dispatcher(req, *args, **kwargs):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            resp = MagicMock()
            if "9090" in url:
                payload = {
                    "status": "success",
                    "data": {"resultType": "vector", "result": [{"value": [1700000000, "5.0"]}]},
                }
            else:
                payload = {"hits": {"hits": [{"_source": {"message": "alert"}}]}}
            resp.read.return_value = json.dumps(payload).encode("utf-8")
            resp.__enter__.return_value = resp
            return resp

        mock_urlopen.side_effect = mock_urlopen_dispatcher
        client = SOCTelemetryClient()
        snapshot = client.get_system_telemetry_snapshot()

        self.assertIn("metrics", snapshot)
        self.assertEqual(snapshot["metrics"]["blockchain_soc_deploy_total"], 5.0)
        self.assertEqual(snapshot["recent_security_events_count"], 1)


if __name__ == "__main__":
    unittest.main()
