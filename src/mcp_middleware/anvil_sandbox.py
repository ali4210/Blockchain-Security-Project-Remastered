"""
Anvil-fork MCP Sandbox Manager (Task P04-006).
Spins up ephemeral local Anvil instances with controlled lifecycle management,
runs bounded `forge test` executions, and reports structured status.
"""

from typing import Any, Dict, List, Optional
import os
import shutil
import socket
import subprocess
import time


class AnvilSandbox:
    """
    Manages ephemeral Anvil subprocess lifecycle and executes controlled
    forge test runs with bounded timeouts and isolated state.
    """

    def __init__(
        self,
        port: int = 8545,
        fork_url: Optional[str] = None,
        timeout: int = 30,
        anvil_bin: str = "anvil",
        forge_bin: str = "forge",
    ):
        self.port = port
        self.fork_url = fork_url
        self.timeout = timeout
        self.anvil_bin = anvil_bin
        self.forge_bin = forge_bin
        self.process: Optional[subprocess.Popen] = None

    def find_free_port(self) -> int:
        """Finds an available local TCP port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return s.getsockname()[1]

    def is_anvil_available(self) -> bool:
        """Checks if the anvil binary is available in the system PATH."""
        return shutil.which(self.anvil_bin) is not None

    def is_forge_available(self) -> bool:
        """Checks if the forge binary is available in the system PATH."""
        return shutil.which(self.forge_bin) is not None

    def start(self, auto_port: bool = False) -> bool:
        """Starts an ephemeral local Anvil instance."""
        if not self.is_anvil_available():
            return False

        if auto_port:
            self.port = self.find_free_port()

        cmd = [self.anvil_bin, "--port", str(self.port), "--silent"]
        if self.fork_url:
            cmd.extend(["--fork-url", self.fork_url])

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Brief pause to verify process is alive
            time.sleep(0.1)
            return self.process.poll() is None
        except Exception:
            self.process = None
            return False

    def stop(self) -> None:
        """Terminates and cleans up the Anvil subprocess."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except (subprocess.TimeoutExpired, Exception):
                self.process.kill()
            finally:
                self.process = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def run_forge_test(
        self,
        match_contract: Optional[str] = None,
        test_file: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes `forge test` against the target contract/file with bounded timeouts.
        """
        if not self.is_forge_available():
            return {
                "success": False,
                "exit_code": -1,
                "output": "forge binary not available in PATH",
                "error": "FORGE_UNAVAILABLE",
            }

        cmd = [self.forge_bin, "test"]
        if match_contract:
            cmd.extend(["--match-contract", match_contract])
        if test_file:
            cmd.extend(["--match-path", test_file])

        exec_timeout = timeout or self.timeout

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=exec_timeout,
            )
            return {
                "success": res.returncode == 0,
                "exit_code": res.returncode,
                "output": res.stdout,
                "error": res.stderr if res.returncode != 0 else None,
            }
        except subprocess.TimeoutExpired as e:
            return {
                "success": False,
                "exit_code": -2,
                "output": e.stdout or "",
                "error": f"Execution timed out after {exec_timeout}s",
            }
        except Exception as e:
            return {
                "success": False,
                "exit_code": -3,
                "output": "",
                "error": str(e),
            }


def run_poc(exploit_path: str = "test/foundry/Exploit.t.sol") -> bool:
    """
    Module-level entrypoint queried by MCP middleware to run PoC tests.
    """
    sandbox = AnvilSandbox()
    try:
        sandbox.start(auto_port=True)
        res = sandbox.run_forge_test(test_file=exploit_path)
        return bool(res.get("success", False))
    finally:
        sandbox.stop()
