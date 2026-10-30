#!/usr/bin/env python3
"""AVS reentrancy consensus gate — real execution, no fabricated verdicts.

Three independent Anvil nodes each:
  1. deploy the pipeline's TARGET_CONTRACT vault,
  2. fund it with a victim deposit,
  3. deploy a reentrancy attacker and fire the exploit transaction,
  4. read the vault's real on-chain balance before and after, and the real
     transaction receipt (status + gasUsed),
  5. inspect the real EVM execution trace of the attack.

A node votes EXPLOIT_CONFIRMED only when the trace proves the reentrancy guard
was penetrated (the attacker re-entered withdraw() while the vault still read as
funded). It votes CLEAN when the re-entry was rejected at the balance guard.

HONEST SCOPE NOTE (read before trusting the numbers):
  * Net fund theft is NOT observable against these solc 0.8.24 fixtures. The
    vulnerable vault's `balances[msg.sender] -= amount` underflows on the
    reentrancy unwind, and 0.8 checked arithmetic reverts the whole transaction,
    so the vault's persisted balance is unchanged (no net drain) for BOTH the
    vulnerable and the secure contract. The before/after balances are recorded
    and reported, but they are the same by construction and are therefore NOT
    the vote signal.
  * The vote signal is the execution trace: whether the reentrant withdraw()
    passed the vault's balance guard and executed a further value transfer
    (vulnerable) or was rejected immediately (secure). This is a real property
    of the deployed bytecode, read from the real trace — not a guessed value.
  * The per-node "node_result_hash" is exactly that: a SHA-256 content hash
    binding one node's real observations. It is NOT a cryptographic signature
    and is NOT a threshold/BLS aggregate. No real per-validator signing key
    exists in this repo (bls_aggregation.py uses HMAC stand-ins derived from a
    public seed), so nothing here is labelled as a signature.

Writes reports/scanners/avs-consensus.json via the shared scanner_result
contract. status == ok only when all three nodes completed a full real run and
agreed; otherwise error / not_run. Not in pipeline-verdict's REQUIRED list yet.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from hashlib import sha256
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "lib"))
from scanner_result import ROOT, write_result  # noqa: E402

HARNESS = Path(__file__).resolve().parent / "exploit_harness" / "ReentrancyAttacker.sol"
CONTRACTS_DIR = ROOT / "contracts" / "solidity"

# Anvil's deterministic dev accounts (public, well-known test keys — never real
# funds, never a live network). acct0 is deployer + victim, acct1 is attacker.
ACCT0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ACCT1 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

PORTS = [8545, 8546, 8547]
VICTIM_DEPOSIT_WEI = 5 * 10**18
ATTACK_VALUE_WEI = 10**18


def find_bin(name):
    for cand in (shutil.which(name),
                 str(Path.home() / ".config/.foundry/bin" / name),
                 str(Path.home() / ".foundry/bin" / name)):
        if cand and Path(cand).exists():
            return cand
    return None


def run(cmd, timeout=90, cwd=None):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    return p.returncode, p.stdout, p.stderr


def port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


class ToolingError(RuntimeError):
    """A prerequisite (foundry binary, build) is missing or broke."""


class AnvilNode:
    """One ephemeral Anvil instance plus the deploy/exploit/observe sequence."""

    def __init__(self, node_id, name, port, anvil_bin, cast_bin, forge_bin, build_dir):
        self.node_id = node_id
        self.name = name
        self.port = port
        self.anvil_bin = anvil_bin
        self.cast_bin = cast_bin
        self.forge_bin = forge_bin
        self.build_dir = build_dir
        self.rpc = f"http://127.0.0.1:{port}"
        self.proc = None

    def start(self):
        if port_open(self.port):
            raise ToolingError(f"port {self.port} already in use; refusing to attach")
        self.proc = subprocess.Popen(
            [self.anvil_bin, "--port", str(self.port), "--silent", "--gas-limit", "30000000"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if port_open(self.port):
                return
            time.sleep(0.2)
        raise ToolingError(f"anvil did not come up on port {self.port}")

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except Exception:
                self.proc.kill()

    def _cast(self, *args, timeout=60):
        return run([self.cast_bin, *args, "--rpc-url", self.rpc], timeout=timeout)

    def _deploy(self, contract_path, name, *ctor_args, value=None):
        cmd = [self.forge_bin, "create", f"{contract_path}:{name}",
               "--rpc-url", self.rpc, "--private-key", self._key, "--broadcast", "--json"]
        if value:
            cmd += ["--value", str(value)]
        if ctor_args:  # --constructor-args is variadic, so it MUST come last
            cmd += ["--constructor-args", *ctor_args]
        rc, out, err = run(cmd, timeout=90, cwd=self.build_dir)
        if rc != 0:
            raise ToolingError(f"deploy {name} failed: {(err or out).strip()[:200]}")
        return json.loads(out)["deployedTo"]

    def validate(self, target_vault_src, vault_name):
        """Full real run on this node. Returns the node's observation dict."""
        self._key = ACCT0
        vault = self._deploy(target_vault_src, vault_name)

        rc, _, err = self._cast("send", vault, "deposit()", "--value", str(VICTIM_DEPOSIT_WEI),
                                "--private-key", ACCT0)
        if rc != 0:
            raise ToolingError(f"victim deposit failed: {err.strip()[:200]}")

        rc, before, _ = self._cast("balance", vault)
        balance_before = int(before.strip())

        self._key = ACCT1
        attacker = self._deploy(str(HARNESS), "ReentrancyAttacker", vault)

        attacker_from = run([self.cast_bin, "wallet", "address", "--private-key", ACCT1])[1].strip()

        # Real execution trace of the attack (reverts; the trace is the evidence).
        rc, trace, terr = self._cast("call", attacker, "attack()", "--value", str(ATTACK_VALUE_WEI),
                                     "--from", attacker_from, "--trace")
        trace_text = trace + terr

        # Real mined receipt: force a gas limit so the reverting tx is mined and
        # carries a real status + gasUsed instead of being rejected at estimation.
        rc, rcpt, _ = self._cast("send", attacker, "attack()", "--value", str(ATTACK_VALUE_WEI),
                                 "--private-key", ACCT1, "--gas-limit", "2000000", "--json")
        try:
            receipt = json.loads(rcpt)
            tx_status = int(receipt.get("status", "0x0"), 16)
            gas_used = int(receipt.get("gasUsed", "0x0"), 16)
            tx_hash = receipt.get("transactionHash", "")
        except (ValueError, json.JSONDecodeError):
            tx_status, gas_used, tx_hash = None, None, ""

        rc, after, _ = self._cast("balance", vault)
        balance_after = int(after.strip())

        # --- interpret the real trace -------------------------------------
        withdraw_frames = trace_text.count("::withdraw(")
        reentrant_withdraws = max(0, withdraw_frames - 1)  # minus the top-level call
        underflow = "arithmetic underflow" in trace_text
        guard_reject = "insufficient balance" in trace_text

        # Guard penetrated: the attacker re-entered withdraw() past the balance
        # check and triggered further nested value transfers (vulnerable vault),
        # or recursed deep enough to underflow the bookkeeping on unwind.
        penetrated = reentrant_withdraws >= 2 or underflow
        blocked = guard_reject and reentrant_withdraws <= 1 and not underflow

        if penetrated:
            vote = "EXPLOIT_CONFIRMED"
        elif blocked:
            vote = "CLEAN"
        else:
            vote = "INDETERMINATE"

        obs = {
            "node_id": self.node_id,
            "validator": self.name,
            "port": self.port,
            "rpc_live": port_open(self.port),
            "vault_address": vault,
            "attacker_address": attacker,
            "balance_before_wei": str(balance_before),
            "balance_after_wei": str(balance_after),
            "net_drain_wei": str(balance_before - balance_after),
            "attack_tx_hash": tx_hash,
            "attack_tx_status": tx_status,     # 0 = reverted (expected on 0.8)
            "attack_gas_used": gas_used,       # real, from the mined receipt
            "reentrant_withdraw_frames": reentrant_withdraws,
            "trace_underflow_panic": underflow,
            "trace_guard_reject": guard_reject,
            "vote": vote,
        }
        if vote == "INDETERMINATE":
            raise ToolingError(f"node {self.node_id}: trace not interpretable "
                               f"(frames={withdraw_frames}, underflow={underflow}, "
                               f"guard={guard_reject})")
        obs["node_result_hash"] = sha256(
            json.dumps({k: obs[k] for k in sorted(obs)}, sort_keys=True).encode()
        ).hexdigest()
        return obs


def build_harness(forge_bin):
    """Compile the attacker + both vault fixtures into one temp Foundry project.

    REAL BUG FOUND AND FIXED (Phase 4a, found live running the full real
    pipeline after migrating SecureVault.sol to OpenZeppelin's Ownable):
    this isolated temp project has no relationship to this repo's real
    node_modules/ at all, and Foundry does not look there by default
    regardless -- `forge build` failed outright on
    "@openzeppelin/contracts/access/Ownable.sol" not found. Fixed with an
    explicit remappings.txt pointing at this project's REAL, absolute
    node_modules path (the temp dir itself is elsewhere, so a relative
    remap would not resolve) -- the same real import Hardhat/Slither/
    solc already resolve elsewhere in this pipeline, not a second,
    different dependency.
    """
    build_dir = Path(tempfile.mkdtemp(prefix="avs-build-"))
    (build_dir / "src").mkdir()
    (build_dir / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nsolc_version = "0.8.24"\n')
    (build_dir / "remappings.txt").write_text(f"@openzeppelin/={ROOT}/node_modules/@openzeppelin/\n")
    shutil.copy(HARNESS, build_dir / "src" / HARNESS.name)
    for sol in CONTRACTS_DIR.glob("*.sol"):
        shutil.copy(sol, build_dir / "src" / sol.name)
    rc, out, err = run([forge_bin, "build", "--quiet"], timeout=180, cwd=build_dir)
    if rc != 0:
        shutil.rmtree(build_dir, ignore_errors=True)
        raise ToolingError(f"forge build failed: {(err or out).strip()[:300]}")
    return build_dir


def resolve_target():
    """The vault the pipeline targets, as 'src/<file>.sol' and contract name."""
    target = os.getenv("TARGET_CONTRACT", "contracts/solidity/VulnerableVault.sol")
    name = Path(target).stem
    return f"src/{Path(target).name}", name


def run_consensus():
    print("[+] [AVS CONSENSUS] 3-node Anvil reentrancy consensus (real execution)...")

    anvil_bin, cast_bin, forge_bin = find_bin("anvil"), find_bin("cast"), find_bin("forge")
    missing = [n for n, b in (("anvil", anvil_bin), ("cast", cast_bin), ("forge", forge_bin)) if not b]
    if missing:
        return write_result("avs-consensus", "anvil-bft", "not_run",
                            detail=f"foundry tooling missing: {', '.join(missing)}")
    if not HARNESS.is_file():
        return write_result("avs-consensus", "anvil-bft", "not_run",
                            detail=f"attacker harness not found: {HARNESS}")

    target_src, vault_name = resolve_target()
    build_dir = None
    nodes, votes = [], []
    try:
        build_dir = build_harness(forge_bin)
        if not (build_dir / "src" / f"{vault_name}.sol").is_file():
            return write_result("avs-consensus", "anvil-bft", "error",
                                target=target_src,
                                detail=f"target vault {vault_name}.sol not in contracts/solidity")

        nodes = [AnvilNode(i + 1, f"avs-validator-{n}", PORTS[i], anvil_bin, cast_bin, forge_bin, build_dir)
                 for i, n in enumerate(["alpha", "beta", "gamma"])]
        for node in nodes:
            node.start()
            obs = node.validate(target_src, vault_name)
            votes.append(obs)
            print(f"    [*] node {obs['node_id']} ({obs['validator']}) vault={obs['vault_address'][:10]}... "
                  f"vote={obs['vote']} reentrant_frames={obs['reentrant_withdraw_frames']} "
                  f"gas={obs['attack_gas_used']} net_drain={obs['net_drain_wei']} wei")
    except ToolingError as exc:
        return write_result("avs-consensus", "anvil-bft", "error",
                            target=target_src, detail=str(exc)[:250],
                            extra={"votes": votes})
    except subprocess.TimeoutExpired:
        return write_result("avs-consensus", "anvil-bft", "error",
                            target=target_src, detail="a node step timed out",
                            extra={"votes": votes})
    finally:
        for node in nodes:
            node.stop()
        if build_dir:
            shutil.rmtree(build_dir, ignore_errors=True)

    total = len(nodes)
    confirmed = sum(1 for v in votes if v["vote"] == "EXPLOIT_CONFIRMED")
    clean = sum(1 for v in votes if v["vote"] == "CLEAN")
    supermajority = confirmed > (2 * total) // 3

    # Unanimous one way or the other is the only trustworthy outcome for a
    # 3-node canary; a split means the nodes disagree on a deterministic fact.
    if confirmed == total:
        verdict = "EXPLOIT_PROVEN_HALT_DEPLOYMENT"
    elif clean == total:
        verdict = "NO_REENTRANCY_DEPLOYMENT_AUTHORIZED"
    else:
        verdict = "SPLIT_DECISION_INVESTIGATE"

    consistent = (confirmed == total or clean == total)
    status = "ok" if consistent else "error"
    detail = (f"{vault_name}: {confirmed}/{total} EXPLOIT_CONFIRMED, {clean}/{total} CLEAN "
              f"-> {verdict}. Net drain 0 by construction (solc 0.8 checked-math reverts "
              f"the reentrancy unwind); vote is from the real execution trace, not a balance delta.")

    report = {
        "protocol": "AVS reentrancy consensus over 3 independent Anvil nodes",
        "target": target_src,
        "vault_name": vault_name,
        "nodes_total": total,
        "exploit_confirmed_votes": confirmed,
        "clean_votes": clean,
        "supermajority_exploit": supermajority,
        "final_verdict": verdict,
        "vote_basis": "execution-trace reentrancy-guard penetration (NOT net balance drain)",
        "net_drain_note": "0 for both fixtures under solc 0.8.24 checked arithmetic",
        "signature_note": ("per-node field is 'node_result_hash', a SHA-256 content hash of real "
                           "observations; NOT a cryptographic/threshold signature (no real signing "
                           "key exists in this repo)"),
        "validator_observations": votes,
    }
    report_file = ROOT / "reports" / "avs-consensus-report.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    counts = {"exploit_confirmed": confirmed, "clean": clean, "nodes": total}
    write_result("avs-consensus", "anvil-bft", status, target=target_src, counts=counts,
                 raw_report=report_file, detail=detail,
                 extra={"final_verdict": verdict, "supermajority_exploit": supermajority})
    print(f"    -> verdict: {verdict} ({confirmed}/{total} confirmed)")
    return report


if __name__ == "__main__":
    run_consensus()
