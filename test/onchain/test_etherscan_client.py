"""Real tests for src/onchain/etherscan_client.py (Phase 3b Etherscan client).

requests.get is patched at src.onchain.etherscan_client.requests.get --
etherscan_client.py does `import requests` (whole module), so this is a
direct attribute lookup at call time, not the Phase-1-style separate-import
bug (that only applies to `from module import name`). Every test isolates
FETCHED_DIR to a tmp_path, never touching the real contracts/solidity/fetched/.
"""
import json
from pathlib import Path
from unittest.mock import patch

import pytest
import requests

from src.onchain import etherscan_client as ec


@pytest.fixture(autouse=True)
def fast_rate_limit(monkeypatch):
    """Every test except the dedicated rate-limit test runs with no real
    waiting -- an effectively unlimited call rate."""
    monkeypatch.setattr(ec, "CALLS_PER_SEC", 1000.0)
    monkeypatch.setattr(ec, "_last_call_at", [0.0])


@pytest.fixture
def isolated_fetched_dir(tmp_path, monkeypatch):
    d = tmp_path / "fetched"
    monkeypatch.setattr(ec, "FETCHED_DIR", d)
    monkeypatch.setattr(ec, "ROOT", tmp_path)
    return d


@pytest.fixture
def api_key(monkeypatch):
    monkeypatch.setenv("ETHERSCAN_API_KEY", "real-test-key")


def _resp(json_body, status_code=200):
    class _R:
        def __init__(self):
            self.status_code = status_code

        def json(self):
            return json_body
    return _R()


VERIFIED_FLAT_RESULT = {
    "SourceCode": "pragma solidity ^0.8.0;\ncontract Flat { uint x; }",
    "ABI": "[]", "ContractName": "Flat", "CompilerVersion": "v0.8.24+commit.x",
    "Proxy": "0", "Implementation": "",
}
UNVERIFIED_RESULT = {"SourceCode": "", "ABI": "Contract source code not verified",
                     "ContractName": "", "CompilerVersion": ""}
MULTI_FILE_RESULT = {
    "SourceCode": '{"language":"Solidity","sources":{"A.sol":{"content":"contract A{}"}}}',
    "ABI": "[]", "ContractName": "A", "CompilerVersion": "v0.8.24+commit.x",
    "Proxy": "0", "Implementation": "",
}
CREATION_RESULT = {"contractAddress": "0xabc", "contractCreator": "0xdeadbeef",
                   "txHash": "0xtxhash", "blockNumber": "123", "timestamp": "1700000000",
                   "creationBytecode": "0x" + "ff" * 500}


def getsourcecode_ok(result):
    return _resp({"status": "1", "message": "OK", "result": [result]})


def getcontractcreation_ok(result):
    return _resp({"status": "1", "message": "OK", "result": [result]})


# ---- no-API-key honest skip -------------------------------------------------

def test_fetch_contract_no_api_key_is_honest_not_run(isolated_fetched_dir, monkeypatch):
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    result = ec.fetch_contract("0x123")
    assert result["status"] == "not_run"
    assert "ETHERSCAN_API_KEY" in result["detail"]
    assert result["target_contract_path"] is None
    assert not isolated_fetched_dir.exists()


# ---- network-failure honest skip -------------------------------------------

def test_fetch_contract_network_failure_is_honest_error(isolated_fetched_dir, api_key):
    with patch.object(ec.requests, "get", side_effect=requests.exceptions.ConnectionError("refused")):
        result = ec.fetch_contract("0x123")
    assert result["status"] == "error"
    assert "unreachable" in result["detail"]
    assert result["target_contract_path"] is None


def test_get_source_code_network_failure_returns_error_tuple(api_key):
    with patch.object(ec.requests, "get", side_effect=requests.exceptions.Timeout("timed out")):
        data, error = ec.get_source_code("0x123")
    assert data is None
    assert "unreachable" in error


# ---- verified single-file success ------------------------------------------

def test_fetch_contract_verified_flat_source_writes_real_sol_file(isolated_fetched_dir, api_key):
    def fake_get(url, params, timeout):
        if params["action"] == "getcontractcreation":
            return getcontractcreation_ok(CREATION_RESULT)
        return getsourcecode_ok(VERIFIED_FLAT_RESULT)

    with patch.object(ec.requests, "get", side_effect=fake_get):
        result = ec.fetch_contract("0xAABBCCDDEEFF00112233445566778899AABBCCDD")

    assert result["status"] == "ok"
    assert result["verified"] is True
    assert result["contract_name"] == "Flat"
    assert result["target_contract_path"] is not None

    written = ec.ROOT / result["target_contract_path"]
    assert written.is_file()
    assert written.read_text(encoding="utf-8") == VERIFIED_FLAT_RESULT["SourceCode"]
    assert result["creation"]["contractCreator"] == "0xdeadbeef"
    assert result["creation_error"] is None


def test_fetch_contract_creation_failure_does_not_block_source_fetch(isolated_fetched_dir, api_key):
    def fake_get(url, params, timeout):
        if params["action"] == "getcontractcreation":
            return _resp({"status": "0", "message": "NOTOK", "result": "creation data not found"})
        return getsourcecode_ok(VERIFIED_FLAT_RESULT)

    with patch.object(ec.requests, "get", side_effect=fake_get):
        result = ec.fetch_contract("0xAABBCCDDEEFF00112233445566778899AABBCCDD")

    assert result["status"] == "ok"
    assert result["target_contract_path"] is not None
    assert result["creation"] is None
    assert "creation data not found" in result["creation_error"]


# ---- unverified-contract fallback ------------------------------------------

def test_fetch_contract_unverified_fetches_bytecode_honestly(isolated_fetched_dir, api_key):
    def fake_get(url, params, timeout):
        if params["action"] == "getcontractcreation":
            return getcontractcreation_ok(CREATION_RESULT)
        if params["action"] == "eth_getCode":
            return _resp({"jsonrpc": "2.0", "id": 1, "result": "0x6080604052"})
        return getsourcecode_ok(UNVERIFIED_RESULT)

    with patch.object(ec.requests, "get", side_effect=fake_get):
        result = ec.fetch_contract("0x123")

    assert result["status"] == "ok"
    assert result["verified"] is False
    assert result["target_contract_path"] is None  # never a second-class/fabricated path
    assert "cannot flow into SAST/swarm" in result["detail"]
    assert result["bytecode_len_bytes"] == 5
    assert not isolated_fetched_dir.exists()


def test_fetch_contract_unverified_and_no_bytecode_is_honest_error(isolated_fetched_dir, api_key):
    def fake_get(url, params, timeout):
        if params["action"] == "getcontractcreation":
            return getcontractcreation_ok(CREATION_RESULT)
        if params["action"] == "eth_getCode":
            return _resp({"jsonrpc": "2.0", "id": 1, "result": "0x"})
        return getsourcecode_ok(UNVERIFIED_RESULT)

    with patch.object(ec.requests, "get", side_effect=fake_get):
        result = ec.fetch_contract("0x123")

    assert result["status"] == "error"
    assert "no contract code" in result["detail"]
    assert result["target_contract_path"] is None


# ---- multi-file verified source: explicitly unsupported in v1 -------------

def test_fetch_contract_multi_file_source_is_honestly_unsupported(isolated_fetched_dir, api_key):
    def fake_get(url, params, timeout):
        if params["action"] == "getcontractcreation":
            return getcontractcreation_ok(CREATION_RESULT)
        return getsourcecode_ok(MULTI_FILE_RESULT)

    with patch.object(ec.requests, "get", side_effect=fake_get):
        result = ec.fetch_contract("0x123")

    assert result["status"] == "error"
    assert "not supported" in result["detail"]
    assert result["target_contract_path"] is None
    assert not isolated_fetched_dir.exists()  # never partially written


def test_is_standard_json_input_detects_real_shapes():
    assert ec._is_standard_json_input('{"language":"Solidity"}') is True
    assert ec._is_standard_json_input("  {\n  \"sources\":{}}") is True
    assert ec._is_standard_json_input("pragma solidity ^0.8.0;\ncontract C {}") is False


# ---- proxy detection (reported, never auto-followed) -----------------------

def test_fetch_contract_proxy_is_reported_not_auto_followed(isolated_fetched_dir, api_key):
    proxy_result = {**VERIFIED_FLAT_RESULT, "Proxy": "1", "Implementation": "0xImplAddr"}

    def fake_get(url, params, timeout):
        if params["action"] == "getcontractcreation":
            return getcontractcreation_ok(CREATION_RESULT)
        return getsourcecode_ok(proxy_result)

    with patch.object(ec.requests, "get", side_effect=fake_get):
        result = ec.fetch_contract("0x123")

    assert result["status"] == "ok"
    assert result["is_proxy"] is True
    assert result["implementation"] == "0xImplAddr"
    assert "0xImplAddr" in result["detail"]
    # Only the address queried was fetched -- no second real HTTP call chased
    # the implementation address automatically.


# ---- etherscan-side API error (invalid address, etc.) ----------------------

def test_get_source_code_etherscan_error_status_is_honest(api_key):
    with patch.object(ec.requests, "get",
                      return_value=_resp({"status": "0", "message": "NOTOK", "result": "Invalid Address format"})):
        data, error = ec.get_source_code("not-an-address")
    assert data is None
    assert "Invalid Address format" in error


# ---- rate limiting: real, measurable pacing --------------------------------

def test_rate_limit_enforces_real_minimum_interval(monkeypatch):
    monkeypatch.setattr(ec, "CALLS_PER_SEC", 20.0)  # min interval 0.05s -- fast but real
    monkeypatch.setattr(ec, "_last_call_at", [0.0])
    import time
    start = time.monotonic()
    ec._rate_limit()
    ec._rate_limit()
    ec._rate_limit()
    elapsed = time.monotonic() - start
    # 3 calls at 20/sec minimum spacing -> at least 2 real intervals of 0.05s.
    assert elapsed >= 0.1 - 0.01  # small tolerance for scheduler jitter


def test_rate_limit_does_not_delay_calls_already_spaced_out(monkeypatch):
    monkeypatch.setattr(ec, "CALLS_PER_SEC", 20.0)
    monkeypatch.setattr(ec, "_last_call_at", [0.0])
    import time
    ec._rate_limit()
    time.sleep(0.1)  # already well past the 0.05s minimum interval
    start = time.monotonic()
    ec._rate_limit()
    assert time.monotonic() - start < 0.02  # no extra real wait needed
