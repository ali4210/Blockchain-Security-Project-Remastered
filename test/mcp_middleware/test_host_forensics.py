import unittest
from unittest.mock import MagicMock, patch
import subprocess

from src.mcp_middleware.host_forensics import (
    HostForensicsWrapper,
    list_partitions,
    list_files,
    analyze,
)


class TestHostForensics(unittest.TestCase):
    def setUp(self):
        self.forensics = HostForensicsWrapper(timeout=5)

    def test_forbidden_command_and_injection_rejection(self):
        malicious_inputs = [
            "disk.img; rm -rf /",
            "disk.img | dd if=/dev/zero",
            "disk.img && cat /etc/shadow",
            "disk.img `whoami`",
            "disk.img $(id)",
        ]
        for bad_input in malicious_inputs:
            res = self.forensics.list_partitions(bad_input)
            self.assertEqual(res["status"], "error")
            self.assertIn("forbidden characters", res["error"])

    def test_parse_mmls_output(self):
        mock_mmls = """DOS Partition Table
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -----     0000000001   0000002047   0000002047   Unallocated
002:  000:000   0000002048   0000206847   0000204800   Linux (0x83)
003:  000:001   0000206848   0000411647   0000204800   Linux Swap (0x82)
"""
        partitions = self.forensics.parse_mmls_output(mock_mmls)
        self.assertEqual(len(partitions), 4)
        self.assertEqual(partitions[2]["slot"], "002")
        self.assertEqual(partitions[2]["start_sector"], 2048)
        self.assertEqual(partitions[2]["length_sectors"], 204800)
        self.assertEqual(partitions[2]["description"], "Linux (0x83)")

    def test_parse_fls_output(self):
        mock_fls = """r/r 12-128-3: secrets.env
d/d 14-144-1: backups
r/* 15-128-1: deleted_key.pem
"""
        files = self.forensics.parse_fls_output(mock_fls)
        self.assertEqual(len(files), 3)
        self.assertEqual(files[0]["name"], "secrets.env")
        self.assertFalse(files[0]["is_directory"])
        self.assertTrue(files[1]["is_directory"])
        self.assertTrue(files[2]["is_deleted"])

    @patch("src.mcp_middleware.host_forensics.HostForensicsWrapper.is_tool_available", return_value=True)
    @patch("subprocess.run")
    def test_list_partitions_success(self, mock_run, _mock_avail):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "000:  000   0000002048  0000206847  0000204800  Linux (0x83)\n"
        mock_res.stderr = ""
        mock_run.return_value = mock_res

        res = self.forensics.list_partitions("/tmp/test_disk.img")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["partition_count"], 1)
        self.assertEqual(res["partitions"][0]["description"], "Linux (0x83)")

    @patch("src.mcp_middleware.host_forensics.HostForensicsWrapper.is_tool_available", return_value=False)
    def test_list_partitions_unavailable_tool(self, _mock_avail):
        res = self.forensics.list_partitions("/tmp/test_disk.img")
        self.assertEqual(res["status"], "unavailable")
        self.assertIn("not found in PATH", res["error"])

    @patch("src.mcp_middleware.host_forensics.HostForensicsWrapper.is_tool_available", return_value=True)
    @patch("subprocess.run")
    def test_list_files_success(self, mock_run, _mock_avail):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "r/r 12-128-3: config.json\n"
        mock_res.stderr = ""
        mock_run.return_value = mock_res

        res = self.forensics.list_files("/tmp/test_disk.img", offset=2048)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["file_count"], 1)
        self.assertEqual(res["files"][0]["name"], "config.json")

    @patch("src.mcp_middleware.host_forensics.HostForensicsWrapper.list_partitions")
    def test_analyze_module_helper(self, mock_parts):
        mock_parts.return_value = {"status": "success", "partitions": [{"slot": "000"}]}
        res = analyze("/tmp/test_disk.img")
        self.assertEqual(res["status"], "completed")
        self.assertTrue(res["read_only"])
        self.assertEqual(len(res["partitions"]), 1)


if __name__ == "__main__":
    unittest.main()
