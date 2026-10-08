import json
import unittest
from unittest.mock import patch, MagicMock

from src.llm_client.ollama_client import (
    chat,
    purge_model,
    list_running_models,
    agent_stage,
)


class TestModelLifecycle(unittest.TestCase):
    def test_list_running_models_parses_response(self):
        fake_response = MagicMock()
        fake_response.read.return_value = json.dumps({
            "models": [
                {"name": "qwen2.5-coder:32b", "size_vram": 19000000000}
            ]
        }).encode("utf-8")
        fake_response.__enter__.return_value = fake_response

        with patch("urllib.request.urlopen", return_value=fake_response):
            models = list_running_models()
            self.assertEqual(len(models), 1)
            self.assertEqual(models[0]["name"], "qwen2.5-coder:32b")

    def test_model_lifecycle_load_call_purge_empty(self):
        """Simulates full cycle: loaded state -> purge -> empty running model list."""
        running_models = [{"name": "deepseek-r1:32b"}]

        def mock_ps_or_generate(req, *args, **kwargs):
            mock_res = MagicMock()
            if req.full_url.endswith("/api/ps"):
                mock_res.read.return_value = json.dumps({"models": list(running_models)}).encode("utf-8")
            elif req.full_url.endswith("/api/generate"):
                # Purge empties the list
                running_models.clear()
                mock_res.read.return_value = json.dumps({"status": "success"}).encode("utf-8")
                mock_res.status = 200
            mock_res.__enter__.return_value = mock_res
            return mock_res

        with patch("urllib.request.urlopen", side_effect=mock_ps_or_generate):
            # 1. Models loaded
            initial = list_running_models()
            self.assertEqual(len(initial), 1)
            self.assertEqual(initial[0]["name"], "deepseek-r1:32b")

            # 2. Purge executed
            purge_res = purge_model("deepseek-r1:32b")
            self.assertEqual(purge_res["status"], "purged")

            # 3. Model list confirmed empty
            post_purge = list_running_models()
            self.assertEqual(len(post_purge), 0)

    def test_agent_stage_cleans_up_on_completion(self):
        purged_models = []

        with patch("src.llm_client.ollama_client.purge_model", side_effect=lambda m: purged_models.append(m)):
            with agent_stage("A") as ctx:
                self.assertEqual(ctx["model"], "qwen2.5-coder:32b")

        self.assertIn("qwen2.5-coder:32b", purged_models)

    def test_offline_fallback_returns_empty_model_list(self):
        # When connection fails or host is offline, cleanly returns empty list without crashing
        with patch("urllib.request.urlopen", side_effect=OSError("Unreachable host")):
            models = list_running_models()
            self.assertEqual(models, [])


if __name__ == "__main__":
    unittest.main()
