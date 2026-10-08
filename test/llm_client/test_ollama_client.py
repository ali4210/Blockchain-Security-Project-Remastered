import os
import unittest
from unittest.mock import patch

from src.llm_client.ollama_client import (
    AGENT_MODEL_ROUTING,
    AGENT_NUM_CTX,
    AGENT_TIMEOUTS,
    get_auth_headers,
    get_ollama_base_url,
    chat,
    purge_model,
    agent_stage,
)


class TestOllamaClient(unittest.TestCase):
    def test_agent_configurations(self):
        for agent in ["A", "B", "C", "D", "E", "F", "G"]:
            self.assertIn(agent, AGENT_MODEL_ROUTING)
            self.assertIn(agent, AGENT_NUM_CTX)
            self.assertIn(agent, AGENT_TIMEOUTS)

        self.assertEqual(AGENT_NUM_CTX["A"], 32768)
        self.assertEqual(AGENT_NUM_CTX["B"], 16384)
        self.assertEqual(AGENT_NUM_CTX["C"], 8192)
        self.assertEqual(AGENT_NUM_CTX["G"], 32768)
        self.assertEqual(AGENT_TIMEOUTS["G"], 300.0)

    def test_auth_headers(self):
        with patch.dict(os.environ, {"OLLAMA_BEARER_TOKEN": "secret-test-token"}):
            headers = get_auth_headers()
            self.assertEqual(headers["Authorization"], "Bearer secret-test-token")
            self.assertEqual(headers["Content-Type"], "application/json")

        with patch.dict(os.environ, {"OLLAMA_BEARER_TOKEN": ""}):
            headers = get_auth_headers()
            self.assertNotIn("Authorization", headers)

    def test_base_url_normalization(self):
        with patch.dict(os.environ, {"OLLAMA_HOST": "192.168.1.50:11434"}):
            self.assertEqual(get_ollama_base_url(), "http://192.168.1.50:11434")

        with patch.dict(os.environ, {"OLLAMA_HOST": "https://gpu-node:11434/"}):
            self.assertEqual(get_ollama_base_url(), "https://gpu-node:11434")

    def test_purge_model(self):
        res = purge_model("qwen2.5-coder:32b")
        self.assertIn(res["status"], ["purged", "purged_simulated"])
        self.assertEqual(res["model"], "qwen2.5-coder:32b")

    def test_agent_stage_context_manager(self):
        purged = []
        with patch("src.llm_client.ollama_client.purge_model", side_effect=lambda m: purged.append(m)):
            with agent_stage("B") as ctx:
                self.assertEqual(ctx["agent"], "B")
                self.assertEqual(ctx["model"], "deepseek-r1:32b")
                self.assertEqual(ctx["num_ctx"], 16384)
                self.assertEqual(ctx["timeout"], 180.0)

        self.assertEqual(purged, ["deepseek-r1:32b"])

    def test_chat_offline_fallback(self):
        with patch.dict(os.environ, {"OLLAMA_HOST": "http://127.0.0.1:99999"}):
            res = chat([{"role": "user", "content": "hello"}], force_agent="A")
            self.assertIn("[OFFLINE_FALLBACK]", res)



    def test_model_tier_scheduling(self):
        from src.llm_client.ollama_client import get_model_routing, AGENT_MODEL_ROUTING_TIER1, AGENT_MODEL_ROUTING_TIER2
        with patch.dict(os.environ, {"OLLAMA_MODEL_TIER": "tier1"}):
            routing1 = get_model_routing()
            self.assertEqual(routing1["A"], "qwen2.5-coder:32b")
            self.assertEqual(routing1["G"], "qwen2.5-coder:32b")

        with patch.dict(os.environ, {"OLLAMA_MODEL_TIER": "tier2"}):
            routing2 = get_model_routing()
            self.assertEqual(routing2["A"], "qwen2.5-coder:14b")
            self.assertEqual(routing2["G"], "qwen2.5-coder:7b")

if __name__ == "__main__":
    unittest.main()
