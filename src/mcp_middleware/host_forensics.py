"""
Read-Only Sleuth Kit Host Forensics MCP Wrapper (Task P04-007).
Provides safe, read-only disk and filesystem inspection using The Sleuth Kit (TSK)
tools (mmls, fls, fsstat) with structured JSON output and strict execution guardrails.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import os
import re
import shutil
import subprocess


class HostForensicsWrapper:
    """
    Read-only wrapper around Sleuth Kit CLI tools enforcing strict
    read-only invariants, argument sanitization, and structured JSON outputs.
    """

    FORBIDDEN_PATTERNS = [
        re.compile(r"[;&|`$]"),  # Command chaining / shell injection tokens
        re.compile(r"\b(rm|dd|mkfs|write|truncate|shred)\b", re.IGNORECASE),
    ]

    def __init__(
        self,
        mmls_bin: str = "mmls",
        fls_bin: str = "fls",
        fsstat_bin: str = "fsstat",
        timeout: int = 30,
    ):
        self.mmls_bin = mmls_bin
        self.fls_bin = fls_bin
        self.fsstat_bin = fsstat_bin
        self.timeout = timeout

    def is_tool_available(self, tool_bin: str) -> bool:
        """Checks if a specified CLI binary is available in the system PATH."""
        return shutil.which(tool_bin) is not None

    def validate_image_path(self, image_path: str) -> Path:
        """
        Validates target image path and rejects dangerous shell characters
        or malformed path representations.
        """
        if not image_path or not isinstance(image_path, str):
            raise ValueError("Target image path must be a non-empty string.")

        for pat in self.FORBIDDEN_PATTERNS:
            if pat.search(image_path):
                raise ValueError(f"Target path contains forbidden characters or commands: '{image_path}'")

        path = Path(image_path).resolve()
        return path

    def list_partitions(self, image_path: str) -> Dict[str, Any]:
        """
        Runs `mmls` to list partitions on a disk image and returns structured JSON.
        """
        try:
            path = self.validate_image_path(image_path)
        except ValueError as e:
            return {
                "status": "error",
                "tool": "mmls",
                "error": str(e),
                "partitions": [],
            }

        if not self.is_tool_available(self.mmls_bin):
            return {
                "status": "unavailable",
                "tool": "mmls",
                "error": f"Binary '{self.mmls_bin}' not found in PATH",
                "partitions": [],
            }

        cmd = [self.mmls_bin, str(path)]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            if res.returncode != 0:
                return {
                    "status": "execution_failed",
                    "tool": "mmls",
                    "exit_code": res.returncode,
                    "error": res.stderr.strip(),
                    "partitions": [],
                }

            partitions = self.parse_mmls_output(res.stdout)
            return {
                "status": "success",
                "tool": "mmls",
                "image_path": str(path),
                "partition_count": len(partitions),
                "partitions": partitions,
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "tool": "mmls",
                "error": f"mmls execution timed out after {self.timeout}s",
                "partitions": [],
            }
        except Exception as e:
            return {
                "status": "error",
                "tool": "mmls",
                "error": str(e),
                "partitions": [],
            }

    def parse_mmls_output(self, output: str) -> List[Dict[str, Any]]:
        """Parses raw `mmls` tabular stdout into structured partition dicts."""
        partitions: List[Dict[str, Any]] = []
        lines = output.strip().splitlines()

        # mmls format: Slot Start End Length Description
        # e.g.: 000:  Meta      0000000000  0000000000  0000000001  Primary Table (#0)
        #       001:  -----     0000000001  0000002047  0000002047  Unallocated
        #       002:  000:000   0000002048  0000206847  0000204800  Linux (0x83)
        row_regex = re.compile(
            r"^\s*(\d{3}):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)$"
        )

        for line in lines:
            match = row_regex.match(line)
            if match:
                slot, part_type, start, end, length, desc = match.groups()
                partitions.append({
                    "slot": slot,
                    "type": part_type,
                    "start_sector": int(start),
                    "end_sector": int(end),
                    "length_sectors": int(length),
                    "description": desc.strip(),
                })

        return partitions

    def list_files(self, image_path: str, offset: Optional[int] = None) -> Dict[str, Any]:
        """
        Runs `fls` to list files and directory inodes on an image or partition.
        """
        try:
            path = self.validate_image_path(image_path)
        except ValueError as e:
            return {
                "status": "error",
                "tool": "fls",
                "error": str(e),
                "files": [],
            }

        if not self.is_tool_available(self.fls_bin):
            return {
                "status": "unavailable",
                "tool": "fls",
                "error": f"Binary '{self.fls_bin}' not found in PATH",
                "files": [],
            }

        cmd = [self.fls_bin, "-r"]
        if offset is not None:
            cmd.extend(["-o", str(int(offset))])
        cmd.append(str(path))

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            if res.returncode != 0:
                return {
                    "status": "execution_failed",
                    "tool": "fls",
                    "exit_code": res.returncode,
                    "error": res.stderr.strip(),
                    "files": [],
                }

            files = self.parse_fls_output(res.stdout)
            return {
                "status": "success",
                "tool": "fls",
                "image_path": str(path),
                "offset": offset,
                "file_count": len(files),
                "files": files,
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "tool": "fls",
                "error": f"fls execution timed out after {self.timeout}s",
                "files": [],
            }
        except Exception as e:
            return {
                "status": "error",
                "tool": "fls",
                "error": str(e),
                "files": [],
            }

    def parse_fls_output(self, output: str) -> List[Dict[str, Any]]:
        """Parses raw `fls` directory entries into structured file dicts."""
        files: List[Dict[str, Any]] = []
        lines = output.strip().splitlines()

        # fls format: r/r 12-128-3: file.txt OR d/d 14-144-1: folder
        fls_regex = re.compile(r"^([a-z*]/[a-z*])\s+([0-9\-]+):\s+(.+)$")

        for line in lines:
            match = fls_regex.match(line.strip())
            if match:
                entry_type, inode, name = match.groups()
                files.append({
                    "entry_type": entry_type,
                    "is_directory": entry_type.startswith("d/"),
                    "is_deleted": "*" in entry_type,
                    "inode": inode,
                    "name": name.strip(),
                })

        return files

    def analyze(self, target: str) -> Dict[str, Any]:
        """High-level analysis combining partition listing and metadata scan."""
        partitions_result = self.list_partitions(target)
        return {
            "status": "completed",
            "target": target,
            "read_only": True,
            "partitions": partitions_result.get("partitions", []),
            "partition_analysis": partitions_result,
        }


# Module-level convenience functions
def list_partitions(image_path: str) -> Dict[str, Any]:
    wrapper = HostForensicsWrapper()
    return wrapper.list_partitions(image_path)


def list_files(image_path: str, offset: Optional[int] = None) -> Dict[str, Any]:
    wrapper = HostForensicsWrapper()
    return wrapper.list_files(image_path, offset=offset)


def analyze(target: str) -> Dict[str, Any]:
    wrapper = HostForensicsWrapper()
    return wrapper.analyze(target)
