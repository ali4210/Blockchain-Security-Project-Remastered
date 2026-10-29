"""Real test for scripts/run-echidna.sh's target/harness resolution.

Proves the fixed harness-selection logic actually picks the harness matching
TARGET_CONTRACT/SECURE for each real target, instead of the old hardcoded-to-
VulnerableVault bug. Docker is deliberately made unavailable (a PATH with no
docker binary) so this stays fast and hermetic -- the resolution logic runs
and writes its result BEFORE the script ever checks for docker, so the real
decision is still fully exercised and observable in reports/scanners/
echidna.json without actually fuzzing anything.

This script always writes to the real reports/ directory (same as every
other scanner script in this pipeline -- there is no test-mode override), so
this test backs up and restores reports/echidna-report.json and
reports/scanners/echidna.json around each real run.
"""
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[2]
SCRIPT = ROOT_DIR / "scripts" / "run-echidna.sh"
ECHIDNA_RESULT = ROOT_DIR / "reports" / "scanners" / "echidna.json"
ECHIDNA_RAW = ROOT_DIR / "reports" / "echidna-report.json"


@pytest.fixture
def no_docker_path(tmp_path):
    """A PATH with every binary run-echidna.sh needs, except docker."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("bash", "python3", "basename", "mktemp", "cp", "rm", "cat", "dirname"):
        real = shutil.which(name)
        assert real, f"{name} not found on this system"
        link = bin_dir / name
        link.symlink_to(real)
    return str(bin_dir)


@pytest.fixture
def preserve_echidna_reports():
    """Real on-disk state: back up and restore around the test, since
    run-echidna.sh always writes to the real reports/ directory."""
    saved_result = ECHIDNA_RESULT.read_bytes() if ECHIDNA_RESULT.is_file() else None
    saved_raw = ECHIDNA_RAW.read_bytes() if ECHIDNA_RAW.is_file() else None
    try:
        yield
    finally:
        if saved_result is not None:
            ECHIDNA_RESULT.write_bytes(saved_result)
        elif ECHIDNA_RESULT.is_file():
            ECHIDNA_RESULT.unlink()
        if saved_raw is not None:
            ECHIDNA_RAW.write_bytes(saved_raw)
        elif ECHIDNA_RAW.is_file():
            ECHIDNA_RAW.unlink()


def run_script(no_docker_path, env_overrides):
    env = {"PATH": no_docker_path, "HOME": os.environ.get("HOME", "/tmp")}
    env.update(env_overrides)
    proc = subprocess.run(["bash", str(SCRIPT)], cwd=ROOT_DIR, env=env,
                          capture_output=True, text=True, timeout=30)
    return proc


def result_json():
    return json.loads(ECHIDNA_RESULT.read_text(encoding="utf-8"))


@pytest.mark.usefixtures("preserve_echidna_reports")
def test_vulnerable_target_selects_vault_harness(no_docker_path):
    proc = run_script(no_docker_path, {"TARGET_CONTRACT": "contracts/solidity/VulnerableVault.sol"})
    assert proc.returncode == 0, proc.stderr
    out = result_json()
    assert out["status"] == "not_run"
    assert out["target"] == "contracts/solidity/VulnerableVault.sol"
    assert out["detail"] == "docker not available"  # reached the docker check -> harness WAS resolved


@pytest.mark.usefixtures("preserve_echidna_reports")
def test_secure_flag_selects_securevault_harness(no_docker_path):
    proc = run_script(no_docker_path, {"SECURE": "1"})
    assert proc.returncode == 0, proc.stderr
    out = result_json()
    assert out["status"] == "not_run"
    assert out["target"] == "contracts/solidity/SecureVault.sol"
    assert out["detail"] == "docker not available"


@pytest.mark.usefixtures("preserve_echidna_reports")
def test_explicit_securevault_target_overrides_secure_flag(no_docker_path):
    proc = run_script(no_docker_path, {"TARGET_CONTRACT": "contracts/solidity/SecureVault.sol", "SECURE": "0"})
    assert proc.returncode == 0, proc.stderr
    out = result_json()
    assert out["target"] == "contracts/solidity/SecureVault.sol"


@pytest.mark.usefixtures("preserve_echidna_reports")
def test_target_with_no_harness_is_honest_not_run_before_docker_check(no_docker_path):
    """RandomTestVault.sol has no Echidna harness -- must report not_run with
    a 'no harness exists' detail, never silently fuzz a different contract's
    harness and never reach the docker check at all."""
    proc = run_script(no_docker_path, {"TARGET_CONTRACT": "contracts/solidity/RandomTestVault.sol"})
    assert proc.returncode == 0, proc.stderr
    out = result_json()
    assert out["status"] == "not_run"
    assert out["target"] == "contracts/solidity/RandomTestVault.sol"
    assert "no Echidna harness exists" in out["detail"]
    assert out["detail"] != "docker not available"  # must have stopped BEFORE the docker check
