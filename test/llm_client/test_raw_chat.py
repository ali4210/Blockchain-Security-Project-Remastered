import json
import os
import unittest
from unittest.mock import patch, MagicMock

from src.llm_client.ollama_client import (
    chat,
    get_auth_headers,
    AGENT_MODEL_ROUTING,
    AGENT_NUM_CTX,
)


class TestRawChat(unittest.TestCase):
    def test_authenticated_chat_payload_structure(self):
        """Verifies chat() constructs the exact HTTP request body and headers."""
        messages = [
            {"role": "system", "content": "You are a blockchain security auditor."},
            {"role": "user", "content": "Analyze VulnerableVault for reentrancy."},
        ]

        fake_response = MagicMock()
        fake_response.read.return_value = json.dumps({
            "model": "qwen2.5-coder:32b",
            "message": {"role": "assistant", "content": "Reentrancy detected at line 18."},
            "done": True,
        }).encode("utf-8")
        fake_response.__enter__.return_value = fake_response

        with patch.dict(os.environ, {"OLLAMA_BEARER_TOKEN": "soc-auth-token-xyz"}):
            with patch("urllib.request.urlopen", return_value=fake_response) as mock_urlopen:
                reply = chat(messages, force_agent="A")
                self.assertEqual(reply, "Reentrancy detected at line 18.")

                # Inspect HTTP request object passed to urlopen
                req = mock_urlopen.call_args[0][0]
                self.assertEqual(req.get_header("Authorization"), "Bearer soc-auth-token-xyz")
                self.assertEqual(req.get_header("Content-type"), "application/json")

                payload = json.loads(req.data.decode("utf-8"))
                self.assertEqual(payload["model"], AGENT_MODEL_ROUTING["A"])
                self.assertEqual(payload["options"]["num_ctx"], AGENT_NUM_CTX["A"])
                self.assertEqual(payload["messages"], messages)

    def test_custom_model_override(self):
        """Verifies explicit model parameter overrides default routing."""
        messages = [{"role": "user", "content": "Ping"}]

        fake_response = MagicMock()
        fake_response.read.return_value = json.dumps({
            "message": {"role": "assistant", "content": "Pong"},
        }).encode("utf-8")
        fake_response.__enter__.return_value = fake_response

        with patch("urllib.request.urlopen", return_value=fake_response) as mock_urlopen:
            reply = chat(messages, model="custom-eval-model:latest")
            self.assertEqual(reply, "Pong")

            req = mock_urlopen.call_args[0][0]
            payload = json.loads(req.data.decode("utf-8"))
            self.assertEqual(payload["model"], "custom-eval-model:latest")

    def test_offline_fallback_diagnostics(self):
        """Verifies structured offline diagnostics when connection fails."""
        with patch.dict(os.environ, {"OLLAMA_HOST": "http://127.0.0.1:1"}):
            reply = chat([{"role": "user", "content": "test"}], force_agent="B")
            self.assertIn("[OFFLINE_FALLBACK]", reply)
            self.assertIn("agent=B", reply)
            self.assertIn("deepseek-r1:32b", reply)
            self.assertIn("ctx=16384", reply)


if __name__ == "__main__":
    unittest.main()
