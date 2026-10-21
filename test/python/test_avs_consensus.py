"""Canary regression for src/consensus/avs_consensus.py.

This is a REAL integration test: it spins up three live Anvil nodes, deploys the
actual vault fixtures and the reentrancy attacker, and fires the exploit. It is
therefore slow and is SKIPPED by default. Run it explicitly with:

    AVS_CONSENSUS_E2E=1 pytest test/python/test_avs_consensus.py -v

It guards the canary property that must never silently regress:
    VulnerableVault -> 3/3 EXPLOIT_CONFIRMED
    SecureVault     -> 0/3 EXPLOIT_CONFIRMED (3/3 CLEAN)

It also asserts the documented solc-0.8 fact: net on-chain balance drain is 0 for
both fixtures (the vote comes from the execution trace, not a balance delta).
"""
import importlib
import socket
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR))

RUN = __import__("os").getenv("AVS_CONSENSUS_E2E") == "1"


def _load_module():
    import src.consensus.avs_consensus as avs
    importlib.reload(avs)
    return avs


def _bins_present():
    avs = _load_module()
    return all(avs.find_bin(b) for b in ("anvil", "cast", "forge"))


def _ports_free():
    avs = _load_module()
    for port in avs.PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return False
    return True


pytestmark = [
    pytest.mark.skipif(not RUN, reason="set AVS_CONSENSUS_E2E=1 to run this slow Anvil integration test"),
    pytest.mark.skipif(RUN and not _bins_present(), reason="foundry tooling (anvil/cast/forge) not installed"),
    pytest.mark.skipif(RUN and not _ports_free(), reason="an Anvil port (8545-8547) is already in use"),
]


def _run_against(monkeypatch, tmp_path, target):
    """Run the consensus gate against one fixture, redirecting all output
    writes to tmp_path so the real reports/ directory is never touched."""
    avs = _load_module()
    import scanner_result
    monkeypatch.setattr(avs, "ROOT", tmp_path)
    monkeypatch.setattr(scanner_result, "RESULTS", tmp_path / "reports" / "scanners")
    monkeypatch.setattr(scanner_result, "RAW", tmp_path / "reports" / "raw")
    monkeypatch.setenv("TARGET_CONTRACT", target)
    return avs.run_consensus()


def test_vulnerable_vault_is_unanimously_exploited(monkeypatch, tmp_path):
    report = _run_against(monkeypatch, tmp_path, "contracts/solidity/VulnerableVault.sol")
    assert report.get("exploit_confirmed_votes") == 3, report.get("detail", report)
    assert report["clean_votes"] == 0
    assert report["final_verdict"] == "EXPLOIT_PROVEN_HALT_DEPLOYMENT"
    assert report["supermajority_exploit"] is True
    for obs in report["validator_observations"]:
        assert obs["vote"] == "EXPLOIT_CONFIRMED"
        assert obs["reentrant_withdraw_frames"] >= 2
        assert obs["net_drain_wei"] == "0"          # documented: no net drain under solc 0.8
        assert obs["attack_tx_status"] == 0          # tx reverts on the bookkeeping underflow
        assert obs["attack_gas_used"] and obs["attack_gas_used"] > 0
        assert len(obs["node_result_hash"]) == 64    # content hash, not a signature


def test_secure_vault_blocks_the_exploit(monkeypatch, tmp_path):
    report = _run_against(monkeypatch, tmp_path, "contracts/solidity/SecureVault.sol")
    assert report.get("clean_votes") == 3, report.get("detail", report)
    assert report["exploit_confirmed_votes"] == 0
    assert report["final_verdict"] == "NO_REENTRANCY_DEPLOYMENT_AUTHORIZED"
    assert report["supermajority_exploit"] is False
    for obs in report["validator_observations"]:
        assert obs["vote"] == "CLEAN"
        assert obs["trace_guard_reject"] is True     # rejected at the balance guard
        assert obs["reentrant_withdraw_frames"] <= 1
        assert obs["net_drain_wei"] == "0"
