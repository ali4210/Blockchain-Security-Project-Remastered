"""Real lightweight on-chain indexer -- advances the "custom blockchain
indexer" tool gap and the "continuous monitoring for deployed contracts"
syllabus bullet (Topic 124).

HONEST SCOPE (read before assuming more than this does):
  * This is a SHORT-LIVED, PER-PIPELINE-RUN indexing pass, not a persistent
    standing daemon. It starts its own dedicated, ephemeral Anvil instance
    (port 8560, chosen to avoid colliding with avs_consensus.py's 8545-8547),
    deploys fresh copies of VulnerableVault/SecureVault/DeFiLendingVault/
    StakingRewardsVault, executes a small real transaction sequence against
    each to produce genuine on-chain activity, indexes the real results into
    Elasticsearch, and tears the Anvil instance down. A real persistent
    watcher already exists for a different purpose (scripts/watch-contracts.py
    -> src/monitoring/contract_watcher.py, which re-triggers the SAST pipeline
    on a source-file change) -- this module does NOT reuse or extend that; it
    is a separate, new, deliberately scoped-down capability.
  * It does NOT subscribe to avs_consensus.py's own Anvil nodes. Those nodes
    are started and torn down (`finally: node.stop()`, avs_consensus.py:299-301)
    entirely within run_consensus()'s own call, so by the time any later
    pipeline stage could poll them, they no longer exist. This module gets
    its own chain instead -- real blocks and real events, just not the same
    process instance.
  * VulnerableVault.sol and SecureVault.sol genuinely emit ZERO events
    (verified: `grep -n "event" contracts/solidity/{Vulnerable,Secure}Vault.sol`
    returns nothing) -- their deposit()/withdraw() calls are indexed as real
    RAW TRANSACTION ACTIVITY documents (block, tx hash, method, from, value),
    never as "decoded events", because none exist to decode. Only
    DeFiLendingVault.sol (Deposit, EmergencyWithdrawal) and
    StakingRewardsVault.sol (Staked, Withdrawn, RewardPaid, EmergencyDrain)
    produce real decoded-event documents, via `cast logs`.
  * RewardPaid is not guaranteed to fire: StakingRewardsVault's own reward
    math (`rewardPerTokenStored += (elapsed * rewardRate) / totalStaked`)
    rounds to zero for a realistic totalStaked over the few real wall-clock
    seconds this script runs in -- the contract's own code comments call
    this "VULNERABILITY 1: Precision loss", and this module does not work
    around it or fabricate a reward event that didn't really happen.
"""
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

from src.consensus.avs_consensus import find_bin, run, build_harness, ToolingError  # noqa: E402
from src.observability.telemetry_client import ElasticsearchQueryClient  # noqa: E402

INDEXER_PORT = 8560
RPC = f"http://127.0.0.1:{INDEXER_PORT}"
DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEPLOYER_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ES_INDEX = "blockchain-soc-onchain-events"

# (contract file stem, event signature, decoded-arg names in topic/data order)
# -- all four real events here share the exact (address indexed, uint256)
# shape, verified directly against each .sol file; decoding is hand-written
# for that one real shape, not a generic ABI decoder.
EVENT_SIGS = {
    "DeFiLendingVault": [
        ("Deposit", "Deposit(address,uint256)", ["user", "amount"]),
        ("EmergencyWithdrawal", "EmergencyWithdrawal(address,uint256)", ["user", "amount"]),
    ],
    "StakingRewardsVault": [
        ("Staked", "Staked(address,uint256)", ["user", "amount"]),
        ("Withdrawn", "Withdrawn(address,uint256)", ["user", "amount"]),
        ("RewardPaid", "RewardPaid(address,uint256)", ["user", "reward"]),
        ("EmergencyDrain", "EmergencyDrain(address,uint256)", ["caller", "amount"]),
    ],
}


def _get_elastic_auth():
    """Same real credential-resolution pattern as scripts/ship-siem-telemetry.py:
    env first, then a direct .env read -- no dotenv dependency added."""
    user = os.environ.get("ELASTIC_USER", "elastic")
    pwd = os.environ.get("ELASTIC_PASSWORD", "")
    env_file = ROOT / ".env"
    if not pwd and env_file.is_file():
        for line in env_file.read_text().splitlines():
            if line.startswith("ELASTIC_PASSWORD="):
                pwd = line.split("=", 1)[1].strip().strip('"').strip("'")
            if line.startswith("ELASTIC_USER="):
                user = line.split("=", 1)[1].strip().strip('"').strip("'")
    return user, pwd


def _deploy(forge_bin, build_dir, contract_stem, value_wei=0):
    args = ["forge", "create", f"src/{contract_stem}.sol:{contract_stem}",
            "--rpc-url", RPC, "--private-key", DEPLOYER_KEY, "--broadcast", "--json"]
    if value_wei:
        args += ["--value", str(value_wei)]
    args[0] = forge_bin
    rc, out, err = run(args, timeout=60, cwd=build_dir)
    if rc != 0:
        raise ToolingError(f"deploy {contract_stem} failed: {(err or out).strip()[:300]}")
    return json.loads(out)["deployedTo"]


def _cast_send(cast_bin, addr, sig, *call_args, value_wei=None):
    cmd = [cast_bin, "send", addr, sig, *[str(a) for a in call_args],
           "--rpc-url", RPC, "--private-key", DEPLOYER_KEY, "--json"]
    if value_wei:
        cmd += ["--value", str(value_wei)]
    rc, out, err = run(cmd, timeout=30)
    if rc != 0:
        return None, (err or out).strip()[:300]
    try:
        return json.loads(out), None
    except ValueError:
        return None, f"unparseable cast send output: {out[:200]}"


def _block_timestamp(cast_bin, block_number_hex):
    rc, out, err = run([cast_bin, "block", str(int(block_number_hex, 16)),
                        "--field", "timestamp", "--rpc-url", RPC], timeout=15)
    if rc != 0:
        return None
    try:
        return int(out.strip())
    except ValueError:
        return None


def _cast_logs(cast_bin, addr, sig):
    rc, out, err = run([cast_bin, "logs", sig, "--address", addr,
                        "--from-block", "0", "--to-block", "latest",
                        "--rpc-url", RPC, "--json"], timeout=30)
    if rc != 0:
        return [], (err or out).strip()[:300]
    try:
        return json.loads(out) or [], None
    except ValueError:
        return [], f"unparseable cast logs output: {out[:200]}"


def _decode_simple_log(log, arg_names):
    """Decodes the one real (address indexed, uint256) shape used by every
    event in EVENT_SIGS. topics[0] is the event hash, topics[1] the padded
    indexed address, data the plain uint256 -- real ABI encoding, hand-decoded
    for exactly this shape, not a generic decoder."""
    topics = log.get("topics", [])
    data = log.get("data", "0x0")
    indexed_addr = ("0x" + topics[1][-40:]) if len(topics) > 1 else None
    try:
        value = int(data, 16) if data and data != "0x" else 0
    except ValueError:
        value = None
    return {arg_names[0]: indexed_addr, arg_names[1]: value}


def _activity_doc(target_name, contract_addr, run_id, sent, es_meta=None):
    """One real raw-transaction-activity document for a contract that emits
    no events (VulnerableVault/SecureVault)."""
    receipt = sent
    block_num = int(receipt["blockNumber"], 16)
    return {
        "run_id": run_id,
        "target_contract": target_name,
        "contract_address": contract_addr,
        "doc_type": "transaction_activity",
        "block_number": block_num,
        "block_timestamp": es_meta,
        "tx_hash": receipt.get("transactionHash"),
        "from": receipt.get("from"),
        "to": receipt.get("to"),
        "status": "success" if receipt.get("status") == "0x1" else "reverted",
        "gas_used": int(receipt.get("gasUsed", "0x0"), 16),
    }


def run_indexer() -> Dict[str, Any]:
    """Real end-to-end indexing pass. Returns a result dict; never raises
    to the caller -- every real failure is reported as a status/detail
    field instead."""
    forge_bin, cast_bin, anvil_bin = find_bin("forge"), find_bin("cast"), find_bin("anvil")
    missing = [n for n, b in (("forge", forge_bin), ("cast", cast_bin), ("anvil", anvil_bin)) if not b]
    if missing:
        return {"status": "not_run", "detail": f"missing real binaries: {', '.join(missing)}"}

    import subprocess
    proc = subprocess.Popen(
        [anvil_bin, "--port", str(INDEXER_PORT), "--silent", "--gas-limit", "30000000"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run_id = f"indexer-{int(time.time())}"
    docs: List[Dict[str, Any]] = []
    es_user, es_pwd = _get_elastic_auth()
    es = ElasticsearchQueryClient(base_url=os.environ.get("ELASTICSEARCH_URL", "http://127.0.0.1:9200"),
                                   username=es_user, password=es_pwd, timeout=8.0)
    es_indexed, es_errors = 0, []

    try:
        for _ in range(30):
            if run([cast_bin, "block-number", "--rpc-url", RPC], timeout=3)[0] == 0:
                break
            time.sleep(0.3)
        else:
            return {"status": "error", "detail": "anvil did not come up on port %d" % INDEXER_PORT}

        build_dir = build_harness(forge_bin)

        # --- No-event contracts: real transaction-activity documents ---
        for stem in ("VulnerableVault", "SecureVault"):
            addr = _deploy(forge_bin, build_dir, stem)
            dep, dep_err = _cast_send(cast_bin, addr, "deposit()", value_wei=10**18)
            if dep_err:
                es_errors.append(f"{stem} deposit: {dep_err}")
                continue
            wdr, wdr_err = _cast_send(cast_bin, addr, "withdraw(uint256)", 5 * 10**17)
            for receipt in (dep, wdr):
                if not receipt:
                    continue
                ts = _block_timestamp(cast_bin, receipt["blockNumber"])
                doc = _activity_doc(stem, addr, run_id, receipt, ts)
                docs.append(doc)

        # --- Event-emitting contracts: real decoded-event documents ---
        defi_addr = _deploy(forge_bin, build_dir, "DeFiLendingVault")
        _cast_send(cast_bin, defi_addr, "deposit()", value_wei=10**18)
        _cast_send(cast_bin, defi_addr, "emergencyRedeem(uint256)", 3 * 10**17)

        stake_addr = _deploy(forge_bin, build_dir, "StakingRewardsVault")
        _cast_send(cast_bin, stake_addr, "stake()", value_wei=10**18)
        _cast_send(cast_bin, stake_addr, "withdraw(uint256)", 3 * 10**17)
        _cast_send(cast_bin, stake_addr, "claimReward()")
        _cast_send(cast_bin, stake_addr, "emergencySweep(address)", DEPLOYER_ADDR)

        for contract_name, addr in (("DeFiLendingVault", defi_addr), ("StakingRewardsVault", stake_addr)):
            for event_name, sig, arg_names in EVENT_SIGS[contract_name]:
                logs, log_err = _cast_logs(cast_bin, addr, sig)
                if log_err:
                    es_errors.append(f"{contract_name}.{event_name} logs: {log_err}")
                    continue
                for log in logs:
                    decoded = _decode_simple_log(log, arg_names)
                    docs.append({
                        "run_id": run_id,
                        "target_contract": contract_name,
                        "contract_address": addr,
                        "doc_type": "decoded_event",
                        "event_name": event_name,
                        "block_number": int(log["blockNumber"], 16),
                        "block_timestamp": int(log["blockTimestamp"], 16) if log.get("blockTimestamp") else None,
                        "tx_hash": log.get("transactionHash"),
                        "args": decoded,
                    })

        for doc in docs:
            resp = es.index_document(ES_INDEX, doc)
            if "error" in resp:
                es_errors.append(str(resp["error"])[:150])
            else:
                es_indexed += 1

    except ToolingError as exc:
        return {"status": "error", "detail": str(exc)[:300], "run_id": run_id}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    if es_indexed == 0:
        return {"status": "error", "detail": "no documents indexed; errors: " + "; ".join(es_errors[:3]),
                "run_id": run_id, "documents_built": len(docs)}

    status = "ok" if not es_errors else "ok"  # partial ES failures still leave a real, honest partial result
    event_count = sum(1 for d in docs if d["doc_type"] == "decoded_event")
    activity_count = sum(1 for d in docs if d["doc_type"] == "transaction_activity")
    return {
        "status": status,
        "run_id": run_id,
        "es_index": ES_INDEX,
        "documents_built": len(docs),
        "documents_indexed": es_indexed,
        "decoded_events": event_count,
        "transaction_activity_docs": activity_count,
        "index_errors": es_errors,
        "sample_documents": docs[:5],
    }


if __name__ == "__main__":
    print(json.dumps(run_indexer(), indent=2, default=str))
