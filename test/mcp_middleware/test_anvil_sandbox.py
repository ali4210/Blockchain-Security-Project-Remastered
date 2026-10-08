import unittest
from unittest.mock import MagicMock, patch
import subprocess

from src.mcp_middleware.anvil_sandbox import AnvilSandbox, run_poc


class TestAnvilSandbox(unittest.TestCase):
    def setUp(self):
        self.sandbox = AnvilSandbox(port=8545, timeout=5)

    def test_find_free_port(self):
        port = self.sandbox.find_free_port()
        self.assertIsInstance(port, int)
        self.assertGreater(port, 1024)

    @patch("shutil.which")
    def test_binary_availability_check(self, mock_which):
        mock_which.return_value = "/usr/local/bin/anvil"
        self.assertTrue(self.sandbox.is_anvil_available())
        mock_which.return_value = None
        self.assertFalse(self.sandbox.is_anvil_available())

    @patch("src.mcp_middleware.anvil_sandbox.AnvilSandbox.is_anvil_available", return_value=False)
    def test_start_fails_when_binary_missing(self, _mock):
        started = self.sandbox.start()
        self.assertFalse(started)
        self.assertIsNone(self.sandbox.process)

    @patch("src.mcp_middleware.anvil_sandbox.AnvilSandbox.is_anvil_available", return_value=True)
    @patch("subprocess.Popen")
    def test_start_and_stop_lifecycle(self, mock_popen, _mock_avail):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        started = self.sandbox.start()
        self.assertTrue(started)
        self.assertIsNotNone(self.sandbox.process)

        self.sandbox.stop()
        self.assertIsNone(self.sandbox.process)
        mock_proc.terminate.assert_called_once()

    @patch("src.mcp_middleware.anvil_sandbox.AnvilSandbox.is_forge_available", return_value=True)
    @patch("subprocess.run")
    def test_run_forge_test_success(self, mock_run, _mock_avail):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "[PASS] testExploit()"
        mock_res.stderr = ""
        mock_run.return_value = mock_res

        res = self.sandbox.run_forge_test(match_contract="Exploit")
        self.assertTrue(res["success"])
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("testExploit", res["output"])

    @patch("src.mcp_middleware.anvil_sandbox.AnvilSandbox.is_forge_available", return_value=True)
    @patch("subprocess.run")
    def test_run_forge_test_timeout(self, mock_run, _mock_avail):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="forge test", timeout=5)

        res = self.sandbox.run_forge_test(match_contract="Exploit", timeout=5)
        self.assertFalse(res["success"])
        self.assertEqual(res["exit_code"], -2)
        self.assertIn("timed out", res["error"])

    @patch("src.mcp_middleware.anvil_sandbox.AnvilSandbox.run_forge_test")
    @patch("src.mcp_middleware.anvil_sandbox.AnvilSandbox.start", return_value=True)
    @patch("src.mcp_middleware.anvil_sandbox.AnvilSandbox.stop")
    def test_run_poc_helper(self, mock_stop, mock_start, mock_forge):
        mock_forge.return_value = {"success": True, "exit_code": 0}
        success = run_poc("test/foundry/Exploit.t.sol")
        self.assertTrue(success)
        mock_start.assert_called_once()
        mock_stop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
