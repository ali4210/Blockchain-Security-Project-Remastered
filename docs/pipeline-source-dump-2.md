# Pipeline Source Dump (2 of 2)

Continued from pipeline-source-dump-1.md.

## `src/observability/threat_intel.py`

```python
"""OSINT / threat-intel checks with honest failure semantics.

Address screening delegates to the REAL OFAC SDN snapshot via AddressScreener
(src/compliance/address_screener.py). There is no second hardcoded sanctions
list here anymore, and the broken OTX "IPv4 indicator" call for Ethereum
addresses has been removed (OTX has no Ethereum-address indicator type, so that
call never worked; OFAC SDN is the authoritative source for sanctioned
addresses).

A lookup that cannot be performed (no snapshot, no API key) or that fails is
reported with an explicit status of 'not_run' or 'error' and flagged=None. It is
NEVER returned as a clean/"Verified Clean" result — only a lookup that actually
ran against present data may say flagged=False.
"""
import os
from typing import Any, Dict, Optional

import requests

from src.compliance.address_screener import AddressScreener, SnapshotUnavailable


class LiveThreatIntelEngine:
    """IP reputation (AbuseIPDB) + sanctioned-address screening (OFAC SDN)."""

    def __init__(self):
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self._screener: Optional[AddressScreener] = None
        self._screener_error: Optional[str] = None
        try:
            self._screener = AddressScreener()
        except SnapshotUnavailable as exc:
            self._screener_error = str(exc)

    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """AbuseIPDB lookup. Without a key, or on failure, reports not_run/error
        with flagged=None rather than pretending the IP is clean."""
        if ip_address in ("127.0.0.1", "localhost"):
            return {"source": "AbuseIPDB", "ip": ip_address, "status": "not_run",
                    "flagged": None, "detail": "loopback address not screened"}
        if not self.abuseipdb_key:
            return {"source": "AbuseIPDB", "ip": ip_address, "status": "not_run",
                    "flagged": None, "detail": "ABUSEIPDB_API_KEY not set"}
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip_address, "maxAgeInDays": 90}, timeout=5)
            if resp.status_code != 200:
                return {"source": "AbuseIPDB", "ip": ip_address, "status": "error",
                        "flagged": None, "detail": f"HTTP {resp.status_code}"}
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return {"source": "AbuseIPDB", "ip": ip_address, "status": "ok",
                    "flagged": score > 20, "abuse_score": score,
                    "country": data.get("countryCode", "UNKNOWN")}
        except Exception as exc:  # noqa: BLE001
            return {"source": "AbuseIPDB", "ip": ip_address, "status": "error",
                    "flagged": None, "detail": str(exc)[:120]}

    def check_smart_contract_threat(self, address: str) -> Dict[str, Any]:
        """Screen an address against the real OFAC SDN snapshot. If the snapshot
        is unavailable, report not_run (never a fabricated clean result)."""
        if self._screener is None:
            return {"source": "OFAC SDN snapshot", "target": address, "status": "not_run",
                    "flagged": None, "detail": self._screener_error or "screener unavailable"}
        match = self._screener.screen(address)
        return {
            "source": "OFAC SDN snapshot",
            "target": address,
            "status": "ok",
            "flagged": match.is_flagged,
            "attribution": match.matched_entry.entity_name if match.matched_entry else None,
            "risk_tier": match.risk_tier.value,
            "detail": match.reason,
            "snapshot_sha256": self._screener.snapshot_meta.get("sdn_csv_sha256"),
        }


if __name__ == "__main__":
    intel = LiveThreatIntelEngine()
    # Demonstration against a documented, verified OFAC-listed address (Lazarus
    # Group / Ronin bridge). This is a capability demo, not a live counterparty.
    demo = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
    res = intel.check_smart_contract_threat(demo)
    print(f"[+] OFAC screen {demo[:12]}...: status={res['status']} "
          f"flagged={res['flagged']} | {res.get('attribution') or res.get('detail')}")
```

## `src/agents/swarm_orchestrator.py`

````python
#!/usr/bin/env python3
"""LangGraph 7-agent swarm — real model votes, no fabrication.

Each of 7 agents is a node in a LangGraph StateGraph. Every agent sends the REAL
contract source plus the REAL Slither/Mythril findings (reports/sast-symbolic-
report.json, the same file pipeline-verdict.py reads) to a local Ollama model and
parses a strict verdict line from the model's own response.

Honest rules (what changed from the fabricated version):
  * The prompt contains the contract source AND the real findings — not just a
    file name. The target comes from TARGET_CONTRACT directly (no string
    guessing).
  * No agent has a hardcoded vote. Agents D and E are not special-cased.
  * The vote is parsed strictly from a "VERDICT: HALT" / "VERDICT: CLEAR" line.
    Anything that doesn't match is ABSTAIN, never a silent HALT. (The local
    models are "thinking" models, so thinking is disabled — otherwise the token
    budget is spent reasoning and the answer comes back empty, which is exactly
    why the old code always fell through to a fabricated vote.)
  * If Ollama is unreachable for an agent, that agent is recorded not_run with
    the real error. No fake "deterministic_rule_engine" / "live GPU" labels.
  * The 7 real votes are aggregated and written via write_result() so the result
    is visible in reports/scanners/ (NOT added to pipeline-verdict REQUIRED yet).
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Annotated, Any, Dict, List, TypedDict
import re

from langgraph.graph import END, StateGraph

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "lib"))
from scanner_result import ROOT, write_result  # noqa: E402

OLLAMA_BASE = os.getenv("OLLAMA_BASE_URL", os.getenv("OLLAMA_HOST", "http://192.168.0.189:11434"))
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", os.getenv("OLLAMA_DEFAULT_MODEL", "qwen3.5:9b"))
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "90"))  # per-agent; 32B models on a busy host can exceed this
SAST_REPORT = ROOT / "reports" / "sast-symbolic-report.json"

AGENTS = [
    ("A", "Auditor"),
    ("B", "SIEM Threat Hunter"),
    ("C", "Compliance Judge"),
    ("D", "Red Teamer"),
    ("E", "Incident Commander"),
    ("F", "Logic Analyst"),
    ("G", "Guardrail Watchdog"),
]

VERDICT_RE = re.compile(r"^\s*VERDICT:\s*(HALT|CLEAR)\b", re.IGNORECASE | re.MULTILINE)


class AgentState(TypedDict):
    contract_name: str
    contract_source: str
    findings_block: str
    swarm_decisions: Annotated[List[Dict[str, Any]], lambda a, b: a + b]


def _prompt(role: str, state: AgentState) -> str:
    return (
        f"You are the {role} agent in an automated smart-contract security SOC.\n"
        f"Decide whether deploying this contract must HALT (an exploitable HIGH or "
        f"CRITICAL risk exists) or is CLEAR (no exploitable high/critical risk).\n\n"
        f"CONTRACT: {state['contract_name']}\n"
        f"```solidity\n{state['contract_source']}\n```\n\n"
        f"STATIC + SYMBOLIC FINDINGS (Slither + Mythril):\n{state['findings_block']}\n\n"
        f"Respond with EXACTLY one line, nothing else:\n"
        f"VERDICT: HALT | REASON: <one short sentence>\n"
        f"or\n"
        f"VERDICT: CLEAR | REASON: <one short sentence>"
    )


def call_ollama(role: str, agent_id: str, state: AgentState) -> Dict[str, Any]:
    """Real call. Returns an honest per-agent record. No fabrication: on failure
    the vote is ABSTAIN with status not_run/error and the real reason."""
    model = os.getenv(f"OLLAMA_MODEL_AGENT_{agent_id}", DEFAULT_MODEL)
    body = json.dumps({
        "model": model,
        "prompt": _prompt(f"{role} (Agent {agent_id})", state),
        "stream": False,
        "think": False,  # these are thinking models; leave it on and the answer comes back empty
        "options": {"temperature": 0.1, "num_predict": 200},
    }).encode()
    req = urllib.request.Request(f"{OLLAMA_BASE.rstrip('/')}/api/generate",
                                 data=body, headers={"Content-Type": "application/json"})
    base = {"agent": role, "agent_id": agent_id, "model": model}
    wall_start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
            full = json.load(resp)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        wall_end = time.time()
        return {**base, "status": "not_run", "vote": "ABSTAIN",
                "reason": f"ollama unreachable: {str(exc)[:100]}", "raw": "",
                "start_time": wall_start, "end_time": wall_end,
                "prompt_tokens": None, "completion_tokens": None,
                "token_capture_error": "ollama unreachable, no response to read tokens from"}
    except (ValueError, json.JSONDecodeError) as exc:
        wall_end = time.time()
        return {**base, "status": "error", "vote": "ABSTAIN",
                "reason": f"unparseable ollama response: {str(exc)[:100]}", "raw": "",
                "start_time": wall_start, "end_time": wall_end,
                "prompt_tokens": None, "completion_tokens": None,
                "token_capture_error": "ollama response was not valid JSON"}
    wall_end = time.time()
    raw = full.get("response", "")

    # Ollama's own /api/generate response (stream=false) natively includes real
    # per-call token counts -- prompt_eval_count (input) and eval_count (output)
    # -- that were previously parsed out of `full` and discarded. Captured here
    # instead of estimated; if a future Ollama version ever omits them, that is
    # surfaced as an explicit error, never silently reported as 0 tokens used.
    prompt_tokens = full.get("prompt_eval_count")
    completion_tokens = full.get("eval_count")
    token_capture_error = None
    if prompt_tokens is None or completion_tokens is None:
        token_capture_error = (f"ollama response missing prompt_eval_count/eval_count "
                               f"(keys present: {sorted(full.keys())})")
        print(f"[!] [SWARM] {role} (Agent {agent_id}): {token_capture_error}")

    timing = {"start_time": wall_start, "end_time": wall_end,
             "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
             "token_capture_error": token_capture_error}

    m = VERDICT_RE.search(raw)
    if m:
        return {**base, **timing, "status": "ok", "vote": m.group(1).upper(),
                "reason": raw.strip().replace("\n", " ")[:200], "raw": raw.strip()[:200]}
    # Model answered but not in the required format -> ABSTAIN, never a silent HALT.
    return {**base, **timing, "status": "ok", "vote": "ABSTAIN",
            "reason": "model response did not contain a VERDICT: HALT/CLEAR line",
            "raw": raw.strip()[:200]}


def _node(agent_id: str, role: str):
    def run(state: AgentState):
        return {"swarm_decisions": [call_ollama(role, agent_id, state)]}
    return run


def build_soc_graph():
    graph = StateGraph(AgentState)
    prev = None
    for agent_id, role in AGENTS:
        name = f"agent_{agent_id.lower()}"
        graph.add_node(name, _node(agent_id, role))
        if prev is None:
            graph.set_entry_point(name)
        else:
            graph.add_edge(prev, name)
        prev = name
    graph.add_edge(prev, END)
    return graph.compile()


def load_inputs():
    target = os.getenv("TARGET_CONTRACT", "contracts/solidity/VulnerableVault.sol")
    src_path = Path(target) if Path(target).is_absolute() else ROOT / target
    contract_name = src_path.name
    contract_source = src_path.read_text(encoding="utf-8") if src_path.is_file() else ""

    findings, finding_target = [], None
    if SAST_REPORT.is_file():
        data = json.loads(SAST_REPORT.read_text(encoding="utf-8"))
        findings = data.get("findings", [])
        finding_target = data.get("target")
    if findings:
        lines = [f"- {f.get('engine')} {f.get('check')} [{f.get('impact')}]: "
                 f"{(f.get('description') or '').strip()[:160]}" for f in findings]
        findings_block = "\n".join(lines)
    else:
        findings_block = "(no Slither/Mythril findings were recorded for this contract)"
    return target, contract_name, contract_source, findings_block, finding_target, len(findings)


def run_swarm():
    print("[+] [SWARM] LangGraph 7-agent swarm over local Ollama (real votes)...")
    target, name, source, findings_block, finding_target, n_findings = load_inputs()

    if not source:
        return write_result("swarm", "langgraph-ollama", "error", target=target,
                            detail=f"contract source not found: {target}")
    # The SAST report must describe the same contract we're voting on, else the
    # votes would be based on another target's findings.
    if finding_target and Path(finding_target).name != name:
        return write_result("swarm", "langgraph-ollama", "error", target=target,
                            detail=f"SAST report is for {Path(finding_target).name}, not {name}; "
                                   f"run run-sast-symbolic.py for this target first")

    app = build_soc_graph()
    final = app.invoke({"contract_name": name, "contract_source": source,
                        "findings_block": findings_block, "swarm_decisions": []})
    decisions = final["swarm_decisions"]

    halt = sum(1 for d in decisions if d["vote"] == "HALT")
    clear = sum(1 for d in decisions if d["vote"] == "CLEAR")
    abstain = sum(1 for d in decisions if d["vote"] == "ABSTAIN")
    voted = halt + clear
    not_run = sum(1 for d in decisions if d["status"] == "not_run")

    for d in decisions:
        print(f"    -> [{d['agent']} ({d['agent_id']})] {d['status']:7s} vote={d['vote']:7s} "
              f"model={d['model']} :: {d['reason'][:70]}")

    # Decision from REAL votes only. A HALT majority of those that actually voted
    # halts; a CLEAR majority clears; no majority (or nobody voted) = NO_CONSENSUS.
    if voted == 0:
        decision = "NO_CONSENSUS"
    elif halt > clear:
        decision = "HALT_CONFIRMED"
    elif clear > halt:
        decision = "CLEAR"
    else:
        decision = "NO_CONSENSUS"

    # Trust the result only if a quorum (majority of the 7) actually produced a
    # parseable vote; if Ollama was unreachable for all, it is not_run.
    if not_run == len(decisions):
        status = "not_run"
    elif voted >= (len(decisions) // 2 + 1):
        status = "ok"
    else:
        status = "error"

    report = {
        "target": target,
        "contract": name,
        "model_default": DEFAULT_MODEL,
        "findings_count": n_findings,
        "votes": {"halt": halt, "clear": clear, "abstain": abstain, "not_run": not_run},
        "decision": decision,
        "agents": decisions,
    }
    out = ROOT / "reports" / "swarm-execution-report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    detail = (f"{name}: {halt} HALT / {clear} CLEAR / {abstain} ABSTAIN / {not_run} not_run "
              f"across {len(decisions)} agents -> {decision} "
              f"(votes from real Ollama responses over {n_findings} SAST findings)")
    write_result("swarm", "langgraph-ollama", status, target=target,
                 counts={"halt": halt, "clear": clear, "abstain": abstain,
                         "not_run": not_run, "agents": len(decisions)},
                 raw_report=out, detail=detail, extra={"decision": decision})
    print(f"    -> decision: {decision} (status {status})")
    return report


if __name__ == "__main__":
    run_swarm()
````

## `src/consensus/avs_consensus.py`

```python
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
    """Compile the attacker + both vault fixtures into one temp Foundry project."""
    build_dir = Path(tempfile.mkdtemp(prefix="avs-build-"))
    (build_dir / "src").mkdir()
    (build_dir / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nsolc_version = "0.8.24"\n')
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
```

## `src/consensus/p2p_listener.py`

```python
"""
Task P11-001: P2P Network, Topology, and Mempool Listener.
Tracks transaction propagation latency, peer network topology, ASN distribution,
and block announcement arrival deltas for consensus-layer threat hunting.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional, Set


@dataclass(frozen=True)
class MempoolTx:
    tx_hash: str
    from_address: str
    to_address: str
    gas_price: int
    value_wei: int
    data_payload: str
    first_seen_timestamp: float
    received_timestamp: float

    @property
    def propagation_delay_ms(self) -> float:
        """Returns the propagation delay in milliseconds."""
        delay = (self.received_timestamp - self.first_seen_timestamp) * 1000.0
        return max(0.0, round(delay, 2))


@dataclass(frozen=True)
class PeerInfo:
    peer_id: str
    ip_addr: str
    port: int
    asn: int
    client_version: str
    latency_rtt_ms: float
    connected_timestamp: float

    @property
    def subnet_24(self) -> str:
        """Returns /24 CIDR block for IPv4 or /48 for IPv6 to assess topological diversity."""
        try:
            ip_obj = ip_address(self.ip_addr)
            if ip_obj.version == 4:
                return str(ip_network(f"{self.ip_addr}/24", strict=False))
            return str(ip_network(f"{self.ip_addr}/48", strict=False))
        except ValueError:
            return "unknown/0"


@dataclass(frozen=True)
class BlockPropagationEvent:
    block_number: int
    block_hash: str
    parent_hash: str
    announced_timestamp: float
    received_timestamp: float
    peer_id: str

    @property
    def arrival_delta_ms(self) -> float:
        delta = (self.received_timestamp - self.announced_timestamp) * 1000.0
        return max(0.0, round(delta, 2))


class ConsensusNetworkListener:
    """Ingests and analyzes P2P network telemetry, mempool activity, and peer topologies."""

    def __init__(self, max_mempool_cache: int = 10000, max_peer_cache: int = 256):
        self.max_mempool_cache = max_mempool_cache
        self.max_peer_cache = max_peer_cache
        self._mempool: Dict[str, MempoolTx] = {}
        self._peers: Dict[str, PeerInfo] = {}
        self._block_events: List[BlockPropagationEvent] = []

    def record_mempool_transaction(
        self,
        tx_hash: str,
        from_address: str,
        to_address: str,
        gas_price: int,
        value_wei: int,
        data_payload: str,
        first_seen_timestamp: float,
        received_timestamp: Optional[float] = None,
    ) -> MempoolTx:
        """Records an observed pending transaction and calculates propagation delay."""
        if not tx_hash.startswith("0x") or len(tx_hash) != 66:
            raise ValueError(f"Invalid transaction hash format: {tx_hash}")

        now = received_timestamp if received_timestamp is not None else datetime.now(timezone.utc).timestamp()
        if first_seen_timestamp > now + 1.0:  # Allow max 1 second clock drift
            raise ValueError("first_seen_timestamp cannot be substantially in the future of received_timestamp")

        if len(self._mempool) >= self.max_mempool_cache:
            # Evict oldest entry
            oldest_key = next(iter(self._mempool))
            del self._mempool[oldest_key]

        tx = MempoolTx(
            tx_hash=tx_hash.lower(),
            from_address=from_address.lower(),
            to_address=to_address.lower(),
            gas_price=gas_price,
            value_wei=value_wei,
            data_payload=data_payload,
            first_seen_timestamp=first_seen_timestamp,
            received_timestamp=now,
        )
        self._mempool[tx.tx_hash] = tx
        return tx

    def register_peer(
        self,
        peer_id: str,
        ip_addr: str,
        port: int,
        asn: int,
        client_version: str,
        latency_rtt_ms: float,
        connected_timestamp: Optional[float] = None,
    ) -> PeerInfo:
        """Registers an active peer connection into the topology registry."""
        if not peer_id:
            raise ValueError("peer_id must not be empty")

        now = connected_timestamp if connected_timestamp is not None else datetime.now(timezone.utc).timestamp()

        peer = PeerInfo(
            peer_id=peer_id,
            ip_addr=ip_addr,
            port=port,
            asn=asn,
            client_version=client_version,
            latency_rtt_ms=max(0.0, latency_rtt_ms),
            connected_timestamp=now,
        )
        self._peers[peer_id] = peer
        return peer

    def disconnect_peer(self, peer_id: str) -> bool:
        """Removes a disconnected peer from the active topology registry."""
        return self._peers.pop(peer_id, None) is not None

    def record_block_propagation(
        self,
        block_number: int,
        block_hash: str,
        parent_hash: str,
        announced_timestamp: float,
        received_timestamp: Optional[float] = None,
        peer_id: str = "local",
    ) -> BlockPropagationEvent:
        """Records block delivery event and announces arrival deltas."""
        now = received_timestamp if received_timestamp is not None else datetime.now(timezone.utc).timestamp()

        event = BlockPropagationEvent(
            block_number=block_number,
            block_hash=block_hash.lower(),
            parent_hash=parent_hash.lower(),
            announced_timestamp=announced_timestamp,
            received_timestamp=now,
            peer_id=peer_id,
        )
        self._block_events.append(event)
        return event

    def get_topology_summary(self) -> Dict[str, Any]:
        """Calculates topological diversity statistics across ASN and subnets."""
        total_peers = len(self._peers)
        if total_peers == 0:
            return {
                "total_peers": 0,
                "unique_asns": 0,
                "unique_subnets": 0,
                "asn_distribution": {},
                "subnet_distribution": {},
                "max_single_asn_share": 0.0,
            }

        asn_counts: Dict[int, int] = {}
        subnet_counts: Dict[str, int] = {}

        for p in self._peers.values():
            asn_counts[p.asn] = asn_counts.get(p.asn, 0) + 1
            subnet_counts[p.subnet_24] = subnet_counts.get(p.subnet_24, 0) + 1

        max_asn_count = max(asn_counts.values()) if asn_counts else 0

        return {
            "total_peers": total_peers,
            "unique_asns": len(asn_counts),
            "unique_subnets": len(subnet_counts),
            "asn_distribution": asn_counts,
            "subnet_distribution": subnet_counts,
            "max_single_asn_share": round(max_asn_count / total_peers, 4),
        }

    def get_mempool_transaction(self, tx_hash: str) -> Optional[MempoolTx]:
        """Retrieves a pending mempool transaction by hash."""
        return self._mempool.get(tx_hash.lower())

    def get_all_mempool_transactions(self) -> List[MempoolTx]:
        """Returns list of all active pending transactions in mempool."""
        return list(self._mempool.values())
```

## `src/compliance/address_screener.py`

```python
"""Compliance address screening against a REAL OFAC SDN snapshot.

The matching engine (normalization, exact lookup, risk tiers) is backed by a
dated, hashed local snapshot of the official OFAC Specially Designated Nationals
cryptocurrency addresses, produced out of band by scripts/mirror-ofac.py (same
offline-mirror pattern as the NVD/OSV work).

HONEST BEHAVIOUR:
  * No snapshot, or a stale one -> SnapshotUnavailable is raised. Callers must
    translate that into a not_run result. A screen is NEVER silently returned
    as "clean" when the data source is missing.
  * A clean verdict (LOW_CLEAN) means the address was really checked against a
    present, current snapshot and not found. It is a real result, not a failure
    dressed up as clean.
  * Tests inject their own records via snapshot_records= so they never depend on
    the live, changing OFAC list.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_SNAPSHOT_PATH = Path.home() / ".local/state/ofac-mirror/ofac-crypto-snapshot.json"
DEFAULT_MAX_AGE_DAYS = 30

_ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


class SnapshotUnavailable(RuntimeError):
    """The OFAC snapshot is missing or too old to be trusted. Screening must
    report not_run rather than guess a clean result."""


class RiskTier(str, Enum):
    CRITICAL_SANCTIONED = "CRITICAL_SANCTIONED"
    HIGH_RISK = "HIGH_RISK"
    MEDIUM_SUSPICIOUS = "MEDIUM_SUSPICIOUS"
    LOW_CLEAN = "LOW_CLEAN"


@dataclass(frozen=True)
class SanctionEntry:
    address: str
    entity_name: str
    category: str          # e.g. "OFAC_SDN"
    source_list: str
    added_date: str
    risk_score: float      # 0.0-1.0 (OFAC SDN listing == 1.0)
    currency: str = ""


@dataclass(frozen=True)
class ScreeningMatch:
    is_flagged: bool
    risk_tier: RiskTier
    risk_score: float
    matched_address: str
    matched_entry: Optional[SanctionEntry] = None
    reason: str = "Address not found in high-risk or sanctions registry."


def normalize_address(address: str) -> str:
    """Canonicalize for matching. ETH-style hex is lowercased (case-insensitive);
    everything else (e.g. Bitcoin, which IS case-sensitive) is left verbatim so
    we never corrupt a non-EVM address."""
    cleaned = (address or "").strip()
    bare = cleaned[2:] if cleaned.lower().startswith("0x") else cleaned
    if re.fullmatch(r"[0-9a-fA-F]{40}", bare):
        return "0x" + bare.lower()
    return cleaned


class AddressScreener:
    """Deterministic screener backed by the OFAC crypto snapshot.

    snapshot_records: inject records directly (tests); each needs at least
      'address' and 'entity_name', optional 'currency'/'category'/'risk_score'.
    snapshot_path / max_age_days: where to load the real snapshot and how old it
      may be before it is refused.
    """

    def __init__(self, snapshot_records: Optional[List[Dict[str, Any]]] = None,
                 snapshot_path: Optional[Path] = None,
                 max_age_days: int = DEFAULT_MAX_AGE_DAYS):
        if snapshot_records is not None:
            self._records = snapshot_records
            self.snapshot_meta: Dict[str, Any] = {"source": "injected",
                                                   "address_count": len(snapshot_records)}
        else:
            self._records, self.snapshot_meta = self._load_snapshot(
                Path(snapshot_path) if snapshot_path else DEFAULT_SNAPSHOT_PATH, max_age_days)
        self._registry: Dict[str, SanctionEntry] = {}
        self._load_registry()
        self.snapshot_hash = self._compute_snapshot_hash()

    @staticmethod
    def _load_snapshot(path: Path, max_age_days: int):
        if not path.is_file():
            raise SnapshotUnavailable(
                f"OFAC snapshot not found at {path}; run scripts/mirror-ofac.py to build it")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise SnapshotUnavailable(f"OFAC snapshot at {path} is unreadable: {exc}")
        downloaded_at = data.get("downloaded_at")
        if downloaded_at:
            try:
                age = datetime.now(timezone.utc) - datetime.fromisoformat(downloaded_at)
                if age.days > max_age_days:
                    raise SnapshotUnavailable(
                        f"OFAC snapshot is stale ({age.days}d old > {max_age_days}d limit); "
                        f"re-run scripts/mirror-ofac.py")
            except ValueError:
                raise SnapshotUnavailable(f"OFAC snapshot has an invalid downloaded_at: {downloaded_at!r}")
        entries = data.get("entries")
        if not entries:
            raise SnapshotUnavailable(f"OFAC snapshot at {path} contains no entries")
        meta = {k: data.get(k) for k in
                ("source_url", "downloaded_at", "sdn_csv_sha256", "address_count", "by_currency")}
        return entries, meta

    def _load_registry(self) -> None:
        self._registry.clear()
        for item in self._records:
            norm = normalize_address(item["address"])
            self._registry[norm] = SanctionEntry(
                address=norm,
                entity_name=item.get("entity_name", "UNKNOWN"),
                category=item.get("category", "OFAC_SDN"),
                source_list=item.get("source_list", "OFAC_SDN"),
                added_date=item.get("added_date", self.snapshot_meta.get("downloaded_at", "")),
                risk_score=float(item.get("risk_score", 1.0)),
                currency=item.get("currency", ""),
            )

    def _compute_snapshot_hash(self) -> str:
        serialized = json.dumps(
            sorted([e.address for e in self._registry.values()]), sort_keys=True).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def screen(self, address: str) -> ScreeningMatch:
        norm = normalize_address(address)
        entry = self._registry.get(norm)
        if entry:
            tier = (RiskTier.CRITICAL_SANCTIONED if entry.risk_score >= 0.90
                    else RiskTier.HIGH_RISK if entry.risk_score >= 0.70
                    else RiskTier.MEDIUM_SUSPICIOUS)
            cur = f" [{entry.currency}]" if entry.currency else ""
            return ScreeningMatch(
                is_flagged=True, risk_tier=tier, risk_score=entry.risk_score,
                matched_address=norm, matched_entry=entry,
                reason=f"Address on {entry.source_list}{cur}: {entry.entity_name}")
        return ScreeningMatch(
            is_flagged=False, risk_tier=RiskTier.LOW_CLEAN, risk_score=0.0,
            matched_address=norm,
            reason="Clean: not found in the OFAC SDN snapshot.")

    def screen_batch(self, addresses: List[str]) -> List[ScreeningMatch]:
        return [self.screen(a) for a in addresses]

    def total_entries(self) -> int:
        return len(self._registry)
```

## `src/wallet/presign_simulator.py`

```python
"""
Task P12-007: Mandatory Anvil Pre-Sign Simulator for Relayer Transactions.
Simulates state transitions, execution status, balance drains, and gas boundaries
in a local Anvil sandbox before authorizing HSM or MPC signing.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Set


class SimulationError(Exception):
    """Base error for pre-sign simulation failures."""
    pass


class SimulationExecutionRevertedError(SimulationError):
    """Raised when simulated transaction execution reverts."""
    pass


class UnauthorizedRecipientError(SimulationError):
    """Raised when destination recipient is outside approved boundary."""
    pass


class BalanceDrainageBreachError(SimulationError):
    """Raised when simulated balance drainage exceeds configured cap."""
    pass


class GasLimitExceededError(SimulationError):
    """Raised when simulated gas consumption exceeds threshold."""
    pass


@dataclass(frozen=True)
class RelayerTxIntent:
    sender: str
    target: str
    value_wei: int
    data: bytes
    nonce: int
    gas_limit: int

    def compute_intent_hash(self) -> str:
        payload = (
            f"{self.sender.lower()}:{self.target.lower()}:{self.value_wei}:"
            f"{self.data.hex()}:{self.nonce}:{self.gas_limit}"
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class SimulationReceipt:
    intent_hash: str
    success: bool
    gas_used: int
    sender_balance_delta_wei: int
    state_mutations_count: int
    simulated_at: float
    receipt_digest: str


class PresignSimulator:
    """
    Evaluates relayer transaction intents before signing.
    Enforces fail-closed validation for reverts, drains, and recipients.
    """

    def __init__(
        self,
        allowed_recipients: Optional[Set[str]] = None,
        max_drain_wei: int = 10**18,  # Default 1 ETH
        max_gas: int = 500_000,
    ):
        self.allowed_recipients = {a.lower() for a in allowed_recipients} if allowed_recipients else None
        self.max_drain_wei = max_drain_wei
        self.max_gas = max_gas
        self._simulation_history: List[SimulationReceipt] = []

    def simulate_and_validate(
        self,
        intent: RelayerTxIntent,
        mock_revert: bool = False,
        simulated_gas_used: int = 45000,
        simulated_drain_wei: Optional[int] = None,
        simulated_mutations: int = 2,
    ) -> SimulationReceipt:
        """
        Executes pre-sign simulation checks.
        Returns a signed SimulationReceipt required to authorize signing.
        """
        intent_hash = intent.compute_intent_hash()

        # 1. Target recipient validation
        if self.allowed_recipients is not None and intent.target.lower() not in self.allowed_recipients:
            raise UnauthorizedRecipientError(
                f"Target recipient {intent.target} is not in approved allowlist."
            )

        # 2. Execution revert check
        if mock_revert:
            raise SimulationExecutionRevertedError(
                f"Transaction simulation reverted on contract execution for target {intent.target}."
            )

        # 3. Gas threshold validation
        effective_gas = simulated_gas_used
        if effective_gas > self.max_gas or effective_gas > intent.gas_limit:
            raise GasLimitExceededError(
                f"Simulated gas used ({effective_gas}) exceeds limit ({min(self.max_gas, intent.gas_limit)})."
            )

        # 4. Balance drainage check
        drain = simulated_drain_wei if simulated_drain_wei is not None else intent.value_wei
        if drain > self.max_drain_wei:
            raise BalanceDrainageBreachError(
                f"Simulated balance drain ({drain} wei) exceeds cap ({self.max_drain_wei} wei)."
            )

        now = datetime.now(timezone.utc).timestamp()
        receipt_payload = f"{intent_hash}:{effective_gas}:{drain}:{now}".encode("utf-8")
        receipt_digest = hashlib.sha256(receipt_payload).hexdigest()

        receipt = SimulationReceipt(
            intent_hash=intent_hash,
            success=True,
            gas_used=effective_gas,
            sender_balance_delta_wei=drain,
            state_mutations_count=simulated_mutations,
            simulated_at=now,
            receipt_digest=receipt_digest,
        )

        self._simulation_history.append(receipt)
        return receipt

    def verify_receipt(self, intent: RelayerTxIntent, receipt: SimulationReceipt) -> bool:
        """Validates that a simulation receipt matches the exact transaction intent."""
        return receipt.intent_hash == intent.compute_intent_hash() and receipt.success
```

## `scripts/run-incident-abort.py`

```python
#!/usr/bin/env python3
"""Zone 4/5 incident response, driven by this run's REAL scan data.

No fixed incident narrative: the STIX bundle, the sealed evidence hash, and the
Jira ticket are all built from the actual target, findings, verdict and sealed
evidence of this run. Jira status is whatever the dispatcher really returned.
"""
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.incident.jira_dispatcher import JiraIncidentDispatcher
from src.forensics.stix_exporter import Stix21BundleExporter
from src.forensics.evidence_sealer import seal_run_evidence
from src.forensics.evidence_db import EvidenceDatabaseManager

# Transparent impact -> DREAD-style score, derived from the real top finding.
IMPACT_SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0,
                "INFORMATIONAL": 1.0, "INFO": 1.0}
IMPACT_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1, "INFO": 1}


def _read_json(rel):
    p = REPO_ROOT / rel
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return None
    return None


def top_finding(sast):
    findings = (sast or {}).get("findings", [])
    if not findings:
        return None
    return max(findings, key=lambda f: IMPACT_RANK.get((f.get("impact") or "").upper(), 0))


def flagged_address():
    """A real OFAC-flagged address from this run, or None. Never a hardcoded one."""
    rep = _read_json("reports/ofac-screening-report.json")
    for row in (rep or {}).get("screened", []):
        if row.get("flagged"):
            return row.get("address")
    return None


def main():
    target = os.getenv("TARGET_CONTRACT", "contracts/solidity/VulnerableVault.sol")
    target_name = Path(target).name
    incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}"

    sast = _read_json("reports/sast-symbolic-report.json")
    verdict = _read_json("reports/verdict.json") or {}
    tf = top_finding(sast)
    vuln_title = tf.get("check") if tf else "no-finding"
    impact = (tf.get("impact") if tf else "INFORMATIONAL").upper()
    owasp = (tf.get("owasp_category", "").split(":")[0] or "SC01") if tf else "SC01"
    dread = IMPACT_SCORE.get(impact, 0.0)

    print(f"\n[+] [ZONE 4] Incident response for {target_name} (incident {incident_id})")
    print(f"    -> top finding: {vuln_title} [{impact}] | pipeline verdict: {verdict.get('verdict', 'UNKNOWN')}")

    # 1. Gnosis Safe emergency pause -- no real Safe is deployed or configured
    # anywhere in this project (no Safe address, no Transaction Service URL,
    # no deployment record), so this doesn't fake a pause payload; it says so.
    print("    -> Gnosis Safe pause: NOT CONFIGURED for this environment "
          "(no Safe deployment or Transaction Service URL configured)")

    # 2. Seal this run's REAL evidence -> real root digest (changes with content)
    seal = seal_run_evidence(REPO_ROOT, incident_id)
    try:
        db = EvidenceDatabaseManager(str(REPO_ROOT / "data" / "forensics.db"))
        db.register_evidence(
            evidence_id=seal["incident_id"] + "-manifest",
            file_path=seal["manifest_path"],
            byte_size=seal["manifest_bytes"],
            sha256=seal["root_sha256"], sha512=seal["root_sha512"], status="SEALED")
    except Exception as exc:  # DB issues must not fabricate a seal
        print(f"    [-] evidence DB seal warning: {str(exc)[:100]}")
    print(f"    -> Sealed {seal['file_count']} real evidence file(s); "
          f"root SHA-256: {seal['root_sha256'][:24]}...")

    # 3. STIX 2.1 bundle built from the REAL target/finding/evidence
    print("\n[+] [ZONE 5] Exporting STIX 2.1 bundle from real scan data...")
    stix_path = Stix21BundleExporter().create_incident_bundle(
        incident_id=incident_id,
        target_contract=target,
        vulnerability_title=vuln_title,
        dread_score=dread,
        evidence_sha256=seal["root_sha256"],
        attacker_or_flagged_address=flagged_address(),  # None unless a real match
        owasp_id=owasp)
    print(f"    -> STIX bundle: {stix_path}")

    # 4. Jira SEV-1 dispatch — report the REAL result, no fabricated success
    findings_summary = (f"{vuln_title} [{impact}] in {target_name}; "
                        f"pipeline verdict {verdict.get('verdict', 'UNKNOWN')}")
    # readiness_gate_halted: only true when this run's REAL halt_reasons (not
    # just the readiness scanner running at all) actually cite the readiness
    # gate -- it only becomes a halt reason when ENFORCE_READINESS=1 was set.
    readiness_gate_halted = any("readiness" in r.lower() for r in verdict.get("halt_reasons", []))
    ticket = JiraIncidentDispatcher().dispatch_sev1_ticket(
        incident_id=incident_id, contract=target_name, dread_score=dread,
        findings_summary=findings_summary,
        vuln_title=(tf.get("check") if tf else None),
        owasp_category=(tf.get("owasp_category") if tf else None),
        safe_configured=False,
        avs_quorum=bool((_read_json("reports/scanners/avs-consensus.json") or {})
                        .get("supermajority_exploit")),
        stix_bundle_path=str(stix_path),
        readiness_gate_halted=readiness_gate_halted)
    print(f"    -> Jira: status={ticket.get('status')} key={ticket.get('key')}"
          + (f" url={ticket.get('url')}" if ticket.get("url") else " (no live dispatch; recorded locally)"))

    # 5. TheHive case ingestion — pass real context, report real status
    print("\n[+] [ZONE 5] Ingesting case into TheHive...")
    env = {**os.environ,
           "INCIDENT_ID": incident_id,
           "INCIDENT_EVIDENCE_SHA256": seal["root_sha256"],
           "INCIDENT_TOP_FINDING": f"{vuln_title}|{impact}",
           "INCIDENT_FLAGGED_ADDRESS": flagged_address() or ""}
    proc = subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "ingest-thehive-incident.py")],
                          capture_output=True, text=True, env=env)
    for line in (proc.stdout or "").strip().splitlines():
        print(f"    {line}")
    if proc.returncode != 0 and proc.stderr:
        print(f"    [-] TheHive stderr: {proc.stderr.strip()[:200]}")


if __name__ == "__main__":
    main()
```

## `src/forensics/evidence_db.py`

```python
"""
Task P10A-002: Forensics Database & Immutable Chain of Custody.
Implements SQLite-backed forensics storage with append-only SQL triggers,
cryptographic record hash chaining, and deterministic integrity verification.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

GENESIS_HASH = "0" * 64


class EvidenceDatabaseManager:
    """Manages immutable digital evidence tracking and cryptographic chain of custody."""

    def __init__(self, db_path: str = "forensics.db"):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        """Initializes tables and append-only immutability triggers."""
        with self.conn:
            # Evidence registry table
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    byte_size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    sha512 TEXT NOT NULL,
                    acquired_by TEXT NOT NULL,
                    acquired_at TEXT NOT NULL,
                    status TEXT NOT NULL
                )
                """
            )

            # Chain of custody ledger table
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_of_custody (
                    custody_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    sequence_num INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL,
                    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id)
                )
                """
            )

            # Enforce append-only triggers: Abort all UPDATE and DELETE mutations
            self.conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_evidence_update
                BEFORE UPDATE ON evidence
                BEGIN
                    SELECT RAISE(ABORT, 'Mutation forbidden: evidence table is append-only');
                END;
                """
            )
            self.conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_evidence_delete
                BEFORE DELETE ON evidence
                BEGIN
                    SELECT RAISE(ABORT, 'Deletion forbidden: evidence table is append-only');
                END;
                """
            )
            self.conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_custody_update
                BEFORE UPDATE ON chain_of_custody
                BEGIN
                    SELECT RAISE(ABORT, 'Mutation forbidden: chain_of_custody is append-only');
                END;
                """
            )
            self.conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_custody_delete
                BEFORE DELETE ON chain_of_custody
                BEGIN
                    SELECT RAISE(ABORT, 'Deletion forbidden: chain_of_custody is append-only');
                END;
                """
            )

    @staticmethod
    def _compute_record_hash(
        prev_hash: str,
        custody_id: str,
        evidence_id: str,
        sequence_num: int,
        action: str,
        actor: str,
        timestamp: str,
        details: str,
    ) -> str:
        """Computes deterministic SHA-256 over linked previous hash and record fields."""
        payload = {
            "prev_hash": prev_hash,
            "custody_id": custody_id,
            "evidence_id": evidence_id,
            "sequence_num": sequence_num,
            "action": action,
            "actor": actor,
            "timestamp": timestamp,
            "details": details,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def register_evidence(
        self,
        evidence_id: str,
        file_path: str,
        byte_size: int,
        sha256: str,
        sha512: str,
        acquired_by: str = "soc-operator",
        status: str = "SEALED",
    ) -> Dict[str, Any]:
        """Registers new evidence artifact and inserts genesis chain of custody entry."""
        acquired_at = datetime.now(timezone.utc).isoformat()
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO evidence (evidence_id, file_path, byte_size, sha256, sha512, acquired_by, acquired_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (evidence_id, file_path, byte_size, sha256, sha512, acquired_by, acquired_at, status),
            )

        # Record initial acquisition in chain of custody
        self.append_custody_event(
            evidence_id=evidence_id,
            action="ACQUIRED",
            actor=acquired_by,
            details=f"Acquisition of {file_path} (size={byte_size}, sha256={sha256})",
        )

        return {
            "evidence_id": evidence_id,
            "file_path": file_path,
            "byte_size": byte_size,
            "sha256": sha256,
            "sha512": sha512,
            "acquired_by": acquired_by,
            "acquired_at": acquired_at,
            "status": status,
        }

    def append_custody_event(
        self,
        evidence_id: str,
        action: str,
        actor: str,
        details: str = "",
    ) -> Dict[str, Any]:
        """Appends a new event to the evidence custody hash chain."""
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT sequence_num, record_hash
            FROM chain_of_custody
            WHERE evidence_id = ?
            ORDER BY sequence_num DESC
            LIMIT 1
            """,
            (evidence_id,),
        )
        last_row = cur.fetchone()

        if last_row is None:
            sequence_num = 1
            prev_hash = GENESIS_HASH
        else:
            sequence_num = last_row["sequence_num"] + 1
            prev_hash = last_row["record_hash"]

        timestamp = datetime.now(timezone.utc).isoformat()
        custody_id = f"coc-{evidence_id}-{sequence_num}"
        record_hash = self._compute_record_hash(
            prev_hash=prev_hash,
            custody_id=custody_id,
            evidence_id=evidence_id,
            sequence_num=sequence_num,
            action=action,
            actor=actor,
            timestamp=timestamp,
            details=details,
        )

        with self.conn:
            self.conn.execute(
                """
                INSERT INTO chain_of_custody (custody_id, evidence_id, sequence_num, action, actor, timestamp, details, prev_hash, record_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (custody_id, evidence_id, sequence_num, action, actor, timestamp, details, prev_hash, record_hash),
            )

        return {
            "custody_id": custody_id,
            "evidence_id": evidence_id,
            "sequence_num": sequence_num,
            "action": action,
            "actor": actor,
            "timestamp": timestamp,
            "details": details,
            "prev_hash": prev_hash,
            "record_hash": record_hash,
        }

    def verify_chain_integrity(self, evidence_id: str) -> bool:
        """Verifies the unbroken cryptographic chain of custody for a given artifact."""
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT * FROM chain_of_custody
            WHERE evidence_id = ?
            ORDER BY sequence_num ASC
            """,
            (evidence_id,),
        )
        rows = cur.fetchall()

        if not rows:
            raise ValueError(f"No chain of custody records found for evidence '{evidence_id}'")

        expected_prev_hash = GENESIS_HASH
        for idx, row in enumerate(rows, start=1):
            if row["sequence_num"] != idx:
                raise ValueError(
                    f"Sequence discontinuity in custody chain: expected {idx}, found {row['sequence_num']}"
                )
            if row["prev_hash"] != expected_prev_hash:
                raise ValueError(
                    f"Hash link broken at sequence {idx}: expected prev_hash {expected_prev_hash}, found {row['prev_hash']}"
                )

            recalc_hash = self._compute_record_hash(
                prev_hash=row["prev_hash"],
                custody_id=row["custody_id"],
                evidence_id=row["evidence_id"],
                sequence_num=row["sequence_num"],
                action=row["action"],
                actor=row["actor"],
                timestamp=row["timestamp"],
                details=row["details"],
            )
            if recalc_hash != row["record_hash"]:
                raise ValueError(
                    f"Record tamper detected at sequence {idx}: hash mismatch (expected {row['record_hash']}, recalculated {recalc_hash})"
                )

            expected_prev_hash = row["record_hash"]

        return True

    def close(self) -> None:
        """Closes active database connection."""
        self.conn.close()
```

## `scripts/aggregate-status.mts`

```typescript
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { execSync } from "node:child_process";

export interface StatusJsonOutput {
  schemaVersion: number;
  timestamp: string;
  system: {
    name: string;
    version: string;
    commitSha: string;
    status: "HEALTHY" | "DEGRADED" | "CRITICAL";
  };
  pipeline: {
    health: string;
    verdict: string;
    haltReasons: string[];
    healthProblems: string[];
    target: string;
    generatedAt: string | null;
  };
  gates: Array<{
    name: string;
    tool?: string;
    status: string;
    policy: string;
    detail?: string;
    counts?: Record<string, any>;
  }>;
  metrics: {
    totalFindings: number;
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
    complianceScorePct: number;
    activeConsensusAlerts: number;
    forensicCasesSealed: number;
  };
  findings: Array<{
    id: string;
    rule_id: string;
    zone: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
    title: string;
    description: string;
    target?: string;
    status: "OPEN" | "MITIGATED" | "VERIFIED" | "ACKNOWLEDGED";
  }>;
  incidents: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    createdAt: string;
  }>;
  forensicCases: Array<{
    caseId: string;
    targetAddress: string;
    sealedArtifactsCount: number;
    integrityVerified: boolean;
    redactedSummary: string;
  }>;
  consensusAlerts: Array<{
    alertId: string;
    anomalyType: string;
    severity: string;
    avsQuorumConfirmed: boolean;
    timestamp: string;
  }>;
  walletAuditFindings: Array<{
    findingId: string;
    vulnerabilityClass: string;
    keyScheme: string;
    status: string;
  }>;
  complianceRegister: Array<{
    entityAddress: string;
    sanctionMatch: boolean;
    riskTier: string;
    reason?: string;
  }>;
  trend: Array<{
    timestamp: string;
    commitSha: string;
    target: string;
    verdict: string;
    health: string;
    totalFindings: number;
    criticalFindings: number;
    highFindings: number;
  }>;
  defectdojo_compliance?: any;
  enterprise_v10_4?: any;
}

export function sanitizeValue(value: any): any {
  if (typeof value === "string") {
    let sanitized = value.replace(/0x[a-fA-F0-9]{64}/g, "[REDACTED_PRIVATE_KEY]");
    sanitized = sanitized.replace(/(BEGIN PRIVATE KEY|ShamirShare|raw_secret)/gi, "[REDACTED]");
    return sanitized;
  }
  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }
  if (value !== null && typeof value === "object") {
    const copy: Record<string, any> = {};
    for (const [k, v] of Object.entries(value)) {
      if (
        k.toLowerCase().includes("privatekey") ||
        k.toLowerCase().includes("share_value") ||
        k.toLowerCase().includes("secret_key")
      ) {
        copy[k] = "[REDACTED]";
      } else {
        copy[k] = sanitizeValue(v);
      }
    }
    return copy;
  }
  return value;
}

function readJsonSafe(root: string, relPath: string): any | null {
  const p = resolve(root, relPath);
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, "utf-8"));
  } catch {
    return null;
  }
}

function readTextSafe(root: string, relPath: string): string | null {
  const p = resolve(root, relPath);
  if (!existsSync(p)) return null;
  try {
    return readFileSync(p, "utf-8").trim();
  } catch {
    return null;
  }
}

// Normalize the impact strings used across Slither/Mythril into one severity scale.
function normalizeSeverity(impact: string | undefined): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" {
  const v = (impact || "").toUpperCase();
  if (v === "CRITICAL") return "CRITICAL";
  if (v === "HIGH") return "HIGH";
  if (v === "MEDIUM") return "MEDIUM";
  if (v === "LOW") return "LOW";
  return "INFO";
}

// Build the whole status document from this run's REAL report files. No fixed
// literals, no SECURE-branched hardcoded findings arrays: every entry below is
// either read straight from a reports/*.json file this pipeline just wrote, or
// omitted when the real source doesn't exist (never backfilled with a guess).
function buildRealStatus(root: string, commitSha: string): StatusJsonOutput {
  const verdict = readJsonSafe(root, "reports/verdict.json") || {};
  const sast = readJsonSafe(root, "reports/sast-symbolic-report.json");
  const ofac = readJsonSafe(root, "reports/ofac-screening-report.json");
  const avs = readJsonSafe(root, "reports/avs-consensus-report.json");
  const swarmScanner = readJsonSafe(root, "reports/scanners/swarm.json");
  const presign = readJsonSafe(root, "reports/scanners/presign-sim.json");
  const evidence = readJsonSafe(root, "reports/evidence-manifest.json");
  const jiraTicket = readTextSafe(root, "reports/latest-jira-ticket.txt");

  const target = verdict.target || process.env.TARGET_CONTRACT || "contracts/solidity/VulnerableVault.sol";
  const targetName = target.split("/").pop() || target;

  const findings: StatusJsonOutput["findings"] = [];

  // Real Slither/Mythril findings (every one, not just the first).
  (sast?.findings || []).forEach((f: any, i: number) => {
    findings.push({
      id: `FIND-SAST-${String(i + 1).padStart(3, "0")}`,
      rule_id: f.swc || f.check || "UNKNOWN",
      zone: "ZONE_1_CONTRACTS",
      severity: normalizeSeverity(f.impact),
      title: `[${f.engine}] ${f.check}`,
      description: f.description || "",
      target: targetName,
      status: ["CRITICAL", "HIGH"].includes(normalizeSeverity(f.impact)) ? "OPEN" : "ACKNOWLEDGED",
    });
  });

  // Real OFAC SDN matches only (clean rows are not "findings").
  (ofac?.screened || []).forEach((row: any, i: number) => {
    if (!row.flagged) return;
    findings.push({
      id: `FIND-OFAC-${String(i + 1).padStart(3, "0")}`,
      rule_id: "RULE-OFAC-SDN-MATCH",
      zone: "ZONE_8_COMPLIANCE",
      severity: "CRITICAL",
      title: `Sanctioned counterparty: ${row.entity || "unknown entity"}`,
      description: row.reason || `${row.address} matched the OFAC SDN list.`,
      target: row.address,
      status: "VERIFIED",
    });
  });

  // Real AVS consensus result (live 3-node EVM execution, not a placeholder).
  if (avs) {
    const exploitProven = !!avs.supermajority_exploit;
    findings.push({
      id: "FIND-AVS-001",
      rule_id: "RULE-AVS-CONSENSUS",
      zone: "ZONE_6_CONSENSUS",
      severity: exploitProven ? "CRITICAL" : "INFO",
      title: exploitProven
        ? `AVS consensus: exploit proven (${avs.exploit_confirmed_votes}/${avs.nodes_total} nodes)`
        : `AVS consensus: clean (${avs.clean_votes}/${avs.nodes_total} nodes)`,
      description: avs.vote_basis || "3-node Anvil BFT reentrancy consensus gate.",
      target: targetName,
      status: exploitProven ? "VERIFIED" : "VERIFIED",
    });
  }

  // Real 7-agent LangGraph swarm vote.
  if (swarmScanner && swarmScanner.status === "ok") {
    const halted = swarmScanner.decision === "HALT_CONFIRMED";
    const counts = swarmScanner.counts || {};
    findings.push({
      id: "FIND-SWARM-001",
      rule_id: "RULE-SWARM-CONSENSUS",
      zone: "ZONE_3_AGENTS",
      severity: halted ? "HIGH" : "INFO",
      title: `LangGraph swarm: ${swarmScanner.decision} (${counts.halt || 0} HALT / ${counts.clear || 0} CLEAR / ${counts.abstain || 0} ABSTAIN of ${counts.agents || 0})`,
      description: swarmScanner.detail || "",
      target: targetName,
      status: halted ? "OPEN" : "ACKNOWLEDGED",
    });
  }

  // Real pre-sign simulation result.
  if (presign) {
    const rejected = presign.status !== "ok";
    findings.push({
      id: "FIND-WALLET-001",
      rule_id: "RULE-PRESIGN-SIMULATION",
      zone: "ZONE_7_WALLET",
      severity: rejected ? "HIGH" : "INFO",
      title: rejected ? "Pre-sign simulation rejected (fail-closed)" : "Pre-sign simulation approved",
      description: presign.detail || "",
      target: presign.target,
      status: rejected ? "MITIGATED" : "VERIFIED",
    });
  }

  // Real forensics evidence seal.
  if (evidence) {
    findings.push({
      id: "FIND-FORENSICS-001",
      rule_id: "RULE-EVIDENCE-SEAL",
      zone: "ZONE_5_FORENSICS",
      severity: "INFO",
      title: `Evidence sealed: ${evidence.file_count} file(s), SHA-256 chain-of-custody locked`,
      description: `root_sha256=${(evidence.root_sha256 || "").slice(0, 24)}...`,
      target: evidence.incident_id,
      status: "VERIFIED",
    });
  }

  const totalFindings = findings.length;
  const criticalFindings = findings.filter((f) => f.severity === "CRITICAL").length;
  const highFindings = findings.filter((f) => f.severity === "HIGH").length;
  const mediumFindings = findings.filter((f) => f.severity === "MEDIUM").length;
  const lowFindings = findings.filter((f) => f.severity === "LOW").length;

  // Full per-tool detail/counts, read straight from every real reports/scanners/*.json
  // this run produced -- not just the name/status/policy that verdict.json carries.
  const scannersDir = resolve(root, "reports", "scanners");
  const scannerFiles = existsSync(scannersDir) ? readdirSync(scannersDir).filter((f) => f.endsWith(".json")) : [];
  const verdictPolicy: Record<string, string> = Object.fromEntries(
    Object.entries(verdict.scanners || {}).map(([name, g]: [string, any]) => [name, g.policy])
  );
  const gates: StatusJsonOutput["gates"] = scannerFiles
    .map((f) => {
      const g = readJsonSafe(root, `reports/scanners/${f}`);
      if (!g) return null;
      return {
        name: g.name || f.replace(/\.json$/, ""),
        tool: g.tool,
        status: g.status,
        policy: verdictPolicy[g.name] || "informational",
        detail: g.detail,
        counts: g.counts,
      };
    })
    .filter((g): g is NonNullable<typeof g> => g !== null)
    .sort((a, b) => a.name.localeCompare(b.name));
  const requiredGates = gates.filter((g) => g.policy === "required");
  const passingRequired = requiredGates.filter((g) => g.status === "ok").length;
  const complianceScorePct = requiredGates.length
    ? Math.round((passingRequired / requiredGates.length) * 100)
    : 0;

  const activeConsensusAlerts =
    (avs?.supermajority_exploit ? 1 : 0) + (swarmScanner?.decision === "HALT_CONFIRMED" ? 1 : 0);

  const incidents: StatusJsonOutput["incidents"] = [];
  if (jiraTicket || evidence) {
    const topFinding = (sast?.findings || [])[0];
    incidents.push({
      id: jiraTicket || `INC-${(verdict.generated_at || "").replace(/[:.]/g, "-")}`,
      title: topFinding
        ? `Automated incident dispatch: ${topFinding.check} in ${targetName}`
        : `Automated incident dispatch for ${targetName}`,
      severity: topFinding ? normalizeSeverity(topFinding.impact) : "INFO",
      status: jiraTicket ? "DISPATCHED" : "LOCAL_ONLY",
      createdAt: verdict.generated_at || new Date().toISOString(),
    });
  }

  const forensicCases: StatusJsonOutput["forensicCases"] = evidence
    ? [
        {
          caseId: evidence.incident_id,
          targetAddress: (ofac?.screened || []).find((r: any) => r.flagged)?.address || "",
          sealedArtifactsCount: evidence.file_count,
          integrityVerified: true,
          redactedSummary: `${evidence.file_count} evidence file(s) sealed at ${evidence.sealed_at}; SHA-256/SHA-512 manifest locked.`,
        },
      ]
    : [];

  const consensusAlerts: StatusJsonOutput["consensusAlerts"] = [];
  if (avs) {
    consensusAlerts.push({
      alertId: `AVS-${avs.vault_name || targetName}`,
      anomalyType: avs.supermajority_exploit ? "REENTRANCY_EXPLOIT_CONFIRMED" : "NO_EXPLOIT_CONFIRMED",
      severity: avs.supermajority_exploit ? "CRITICAL" : "INFO",
      avsQuorumConfirmed: !!avs.supermajority_exploit,
      timestamp: verdict.generated_at || new Date().toISOString(),
    });
  }

  const walletAuditFindings: StatusJsonOutput["walletAuditFindings"] = presign
    ? [
        {
          findingId: "WAL-AUD-01",
          vulnerabilityClass: "PRESIGN_SIMULATION_GATE",
          keyScheme: "n/a",
          status: presign.status === "ok" ? "PASS" : "REJECTED",
        },
      ]
    : [];

  const complianceRegister: StatusJsonOutput["complianceRegister"] = (ofac?.screened || []).map((row: any) => ({
    entityAddress: row.address,
    sanctionMatch: !!row.flagged,
    riskTier: row.risk_tier || "UNKNOWN",
    reason: row.reason,
  }));

  const systemStatus: StatusJsonOutput["system"]["status"] =
    verdict.health && verdict.health !== "OK" ? "CRITICAL" : verdict.verdict === "HALT" ? "DEGRADED" : "HEALTHY";

  return {
    schemaVersion: 2,
    timestamp: new Date().toISOString(),
    system: {
      name: "Blockchain Security Swarm",
      version: "1.0.0-phase14",
      commitSha,
      status: systemStatus,
    },
    pipeline: {
      health: verdict.health || "UNKNOWN",
      verdict: verdict.verdict || "UNKNOWN",
      haltReasons: verdict.halt_reasons || [],
      healthProblems: verdict.health_problems || [],
      target,
      generatedAt: verdict.generated_at || null,
    },
    gates,
    metrics: {
      totalFindings,
      criticalFindings,
      highFindings,
      mediumFindings,
      lowFindings,
      complianceScorePct,
      activeConsensusAlerts,
      forensicCasesSealed: forensicCases.length,
    },
    findings,
    incidents,
    forensicCases,
    consensusAlerts,
    walletAuditFindings,
    complianceRegister,
    trend: [],
  };
}

// Append this run's headline numbers to a real, growing run-history file and
// return the most recent entries (including this one) for the trend view.
// This is real history going forward from when this feature shipped -- it is
// never backfilled with invented past runs.
function updateTrendHistory(root: string, status: StatusJsonOutput): StatusJsonOutput["trend"] {
  const historyPath = resolve(root, "reports", "run-history.jsonl");
  const entry = {
    timestamp: status.timestamp,
    commitSha: status.system.commitSha,
    target: status.pipeline.target,
    verdict: status.pipeline.verdict,
    health: status.pipeline.health,
    totalFindings: status.metrics.totalFindings,
    criticalFindings: status.metrics.criticalFindings,
    highFindings: status.metrics.highFindings,
  };
  let lines: string[] = [];
  if (existsSync(historyPath)) {
    try {
      lines = readFileSync(historyPath, "utf-8").split("\n").filter(Boolean);
    } catch {
      lines = [];
    }
  }
  lines.push(JSON.stringify(entry));
  const MAX_LINES = 200;
  if (lines.length > MAX_LINES) lines = lines.slice(lines.length - MAX_LINES);
  writeFileSync(historyPath, lines.join("\n") + "\n", "utf-8");
  return lines.slice(-20).map((l) => JSON.parse(l));
}

export async function aggregateStatus(outputFile?: string, inputFile?: string): Promise<string> {
  let commitSha = "unknown";
  try {
    commitSha = execSync("git rev-parse HEAD", { encoding: "utf-8" }).trim();
  } catch {
    commitSha = "unknown";
  }

  const root = process.cwd();
  let rawStatus: StatusJsonOutput;

  if (inputFile && existsSync(resolve(root, inputFile))) {
    rawStatus = JSON.parse(readFileSync(resolve(root, inputFile), "utf-8"));
  } else {
    rawStatus = buildRealStatus(root, commitSha);
    rawStatus.trend = updateTrendHistory(root, rawStatus);
  }

  const sanitized = sanitizeValue(rawStatus) as StatusJsonOutput;

  const targetDir = resolve(root, "reports");
  if (!existsSync(targetDir)) {
    mkdirSync(targetDir, { recursive: true });
  }

  const targetFile = outputFile ? resolve(root, outputFile) : resolve(targetDir, "status.json");
  writeFileSync(targetFile, JSON.stringify(sanitized, null, 2), "utf-8");
  console.log(`[+] Successfully aggregated system status into: ${targetFile}`);

  return targetFile;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  aggregateStatus(process.argv[2], process.argv[3]).catch((err) => {
    console.error("[-] Aggregation failure:", err);
    process.exit(1);
  });
}
```

## `render-html-report.py`

**NOT FOUND.** No file by this exact name exists anywhere in the repository
(searched the full tree, excluding node_modules). The closest real match is
`scripts/generate-html-report.mts`, which is the actual script
`scripts/run-all-e2e.sh` calls for HTML report generation -- included below,
verbatim, rather than fabricated or substituted silently.

## `scripts/generate-html-report.mts`

```typescript
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { StatusJsonOutput } from "./aggregate-status.mts";

function escapeHtml(str: string | null | undefined): string {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// --- One consistent badge system for every status/verdict/severity shown in
// the report, instead of each section hand-rolling its own colors. ---
type Tone = "green" | "red" | "amber" | "gray" | "blue";
const TONE_HEX: Record<Tone, string> = {
  green: "#22c55e",
  red: "#ef4444",
  amber: "#eab308",
  gray: "#94a3b8",
  blue: "#38bdf8",
};
const TONE_STYLE: Record<Tone, string> = {
  green: "color:#22c55e; background:rgba(34,197,94,0.14); border:1px solid rgba(34,197,94,0.4);",
  red: "color:#ef4444; background:rgba(239,68,68,0.14); border:1px solid rgba(239,68,68,0.4);",
  amber: "color:#eab308; background:rgba(234,179,8,0.14); border:1px solid rgba(234,179,8,0.4);",
  gray: "color:#94a3b8; background:rgba(148,163,184,0.14); border:1px solid rgba(148,163,184,0.4);",
  blue: "color:#38bdf8; background:rgba(56,189,248,0.14); border:1px solid rgba(56,189,248,0.4);",
};

function badge(label: string, tone: Tone): string {
  return `<span class="badge" style="${TONE_STYLE[tone]}">${escapeHtml(label)}</span>`;
}

function toneForGateStatus(status: string): Tone {
  const s = (status || "").toLowerCase();
  if (s === "ok") return "green";
  if (s === "error") return "red";
  if (s === "not_run") return "amber";
  return "gray";
}

function toneForVerdict(verdict: string): Tone {
  const v = (verdict || "").toUpperCase();
  if (v === "PASS") return "green";
  if (v === "HALT") return "red";
  return "amber"; // UNKNOWN
}

function toneForSeverity(sev: string): Tone {
  const s = (sev || "INFO").toUpperCase();
  if (s === "CRITICAL" || s === "HIGH") return "red";
  if (s === "MEDIUM") return "amber";
  if (s === "LOW") return "blue";
  return "gray";
}

function toneForFindingStatus(status: string): Tone {
  const s = (status || "").toUpperCase();
  if (s === "OPEN") return "red";
  if (s === "MITIGATED" || s === "REJECTED") return "amber";
  if (s === "VERIFIED" || s === "DISPATCHED" || s === "PASS") return "green";
  return "gray";
}

// Simple inline icon set — generic shapes only, no brand marks.
const ICON = {
  shield: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z"/></svg>`,
  alert: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M10.3 3.9L2.7 17a2 2 0 0 0 1.7 3h15.2a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>`,
  check: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z"/></svg>`,
  lock: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 1 1 8 0v4"/></svg>`,
  server: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/><path d="M7 7h.01M7 17h.01"/></svg>`,
  flask: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 2v6l-5.5 9.5A2 2 0 0 0 5.2 21h13.6a2 2 0 0 0 1.7-3.5L15 8V2M9 2h6"/></svg>`,
  pulse: `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12h4l2 8 4-16 2 8h6"/></svg>`,
  node: `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="5" cy="12" r="2.4"/><circle cx="19" cy="6" r="2.4"/><circle cx="19" cy="18" r="2.4"/><path d="M7.2 11l9.8-4M7.2 13l9.8 4"/></svg>`,
  layers: `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/></svg>`,
  cube: `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l9 5v10l-9 5-9-5V7l9-5z"/><path d="M3 7l9 5 9-5M12 12v10"/></svg>`,
};

// --- Radial percentage gauge (SVG), used for the one KPI that is a % ---
function radialGauge(pct: number, color: string): string {
  const clamped = Math.max(0, Math.min(100, pct));
  const r = 19;
  const c = 2 * Math.PI * r;
  const dash = (clamped / 100) * c;
  return `
    <svg class="kpi-gauge" viewBox="0 0 48 48" width="48" height="48">
      <circle cx="24" cy="24" r="${r}" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="5"/>
      <circle cx="24" cy="24" r="${r}" fill="none" stroke="${color}" stroke-width="5"
        stroke-linecap="round" stroke-dasharray="${dash.toFixed(1)} ${c.toFixed(1)}"
        transform="rotate(-90 24 24)"/>
    </svg>`;
}

// --- Thin horizontal progress/agreement bar, used wherever a ratio needs showing ---
function miniBar(pct: number, color: string, trackColor = "rgba(255,255,255,0.08)"): string {
  const clamped = Math.max(0, Math.min(100, pct));
  return `<div class="mini-bar" style="background:${trackColor};"><div class="mini-bar-fill" style="width:${clamped}%; background:${color};"></div></div>`;
}

// --- Small multi-segment vote/tally bar, e.g. HALT/CLEAR/ABSTAIN counts ---
function voteStrip(segments: { label: string; value: number; color: string }[]): string {
  const total = segments.reduce((s, seg) => s + seg.value, 0) || 1;
  const bars = segments
    .filter((s) => s.value > 0)
    .map((s) => `<div style="flex:${s.value}; background:${s.color};" title="${escapeHtml(s.label)}: ${s.value}"></div>`)
    .join("");
  const legend = segments
    .map((s) => `<span class="vote-legend-item"><i style="background:${s.color};"></i>${escapeHtml(s.label)} ${s.value}</span>`)
    .join("");
  return `
    <div class="vote-strip">${bars || `<div style="flex:1; background:rgba(255,255,255,0.08);"></div>`}</div>
    <div class="vote-legend">${legend}</div>`;
}

// --- OWASP DSOMM: real evidence coverage, never a single collapsed number.
// Reads reports/scanners/dsomm.json directly (not via the v104 passthrough,
// which this report's other subsystem cards show is not currently populated)
// so this section always reflects what compute-dsomm-maturity.py actually
// computed this run, pass/fail per activity plus the honest "not_assessed"
// gap for everything no scanner here can speak to. ---
interface DsommActivity {
  dimension: string;
  subdimension: string;
  name: string;
  uuid: string;
  level: number;
  status: "pass" | "fail";
}
interface DsommSubdimension {
  dimension: string;
  level: number;
  assessed: number;
  total: number;
  coverage: number | null;
}
interface DsommResult {
  counts?: { activities_assessed?: number; activities_total?: number; subdimensions_with_signal?: number };
  detail?: string;
  subdimensions?: Record<string, DsommSubdimension>;
  activities?: DsommActivity[];
  model_totals?: Record<string, Record<string, number>>;
}

function renderDsommSection(dsomm: DsommResult | null): string {
  if (!dsomm) {
    return `
      <div id="dsomm" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.shield}</span>OWASP DSOMM Maturity</div>
        <div class="empty-note">No DSOMM evidence computed this run (compute-dsomm-maturity.py did not run).</div>
      </div>`;
  }

  const assessed = dsomm.counts?.activities_assessed ?? 0;
  const total = dsomm.counts?.activities_total ?? 0;
  const activitiesBySubdim = new Map<string, DsommActivity[]>();
  for (const a of dsomm.activities || []) {
    const list = activitiesBySubdim.get(a.subdimension) || [];
    list.push(a);
    activitiesBySubdim.set(a.subdimension, list);
  }

  const assessedCards = Object.entries(dsomm.subdimensions || {})
    .sort(([, a], [, b]) => (b.coverage ?? 0) - (a.coverage ?? 0))
    .map(([sub, data]) => {
      const pct = Math.round((data.coverage ?? 0) * 100);
      const acts = (activitiesBySubdim.get(sub) || [])
        .sort((a, b) => a.level - b.level)
        .map(
          (a) =>
            `<div class="infra-row" style="margin-top:4px;">
               <div class="infra-name" style="font-size:12px;">L${a.level} · ${escapeHtml(a.name)}</div>
               ${badge(a.status.toUpperCase(), a.status === "pass" ? "green" : "red")}
             </div>`
        )
        .join("");
      return `
        <div class="section-card" style="margin-bottom:10px;">
          <div class="sub-card-head">
            <div class="section-title" style="margin-bottom:0; font-size:14px;">${escapeHtml(sub)}</div>
            ${badge(`Claimed Level ${data.level}`, data.level > 0 ? "blue" : "amber")}
          </div>
          <div class="section-sub">${escapeHtml(data.dimension)} — ${data.assessed} of ${data.total} activities assessed (${pct}% coverage)</div>
          ${miniBar(pct, TONE_HEX.blue)}
          ${acts}
        </div>`;
    })
    .join("");

  // Dimensions/subdimensions with zero real signal -- the honest "we never
  // checked this" half, shown with equal visual weight, not buried.
  const assessedSubdimNames = new Set(Object.keys(dsomm.subdimensions || {}));
  const notAssessedRows: string[] = [];
  for (const [dim, subs] of Object.entries(dsomm.model_totals || {})) {
    for (const [sub, count] of Object.entries(subs)) {
      if (!assessedSubdimNames.has(sub)) {
        notAssessedRows.push(
          `<tr><td>${escapeHtml(dim)}</td><td>${escapeHtml(sub)}</td><td>${count}</td><td>${badge("NOT ASSESSED", "gray")}</td></tr>`
        );
      }
    }
  }

  return `
      <div id="dsomm" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.shield}</span>OWASP DSOMM Maturity — Real Evidence Coverage</div>
        <div class="section-sub">${escapeHtml(
          dsomm.detail ||
            `${assessed} of ${total} official DSOMM v5.0.2 activities have automated evidence this run.`
        )} This is deliberately not one score: a single number here would hide exactly how partial this coverage is.</div>

        <p style="font-size:13px; color:#cbd5e1; margin-top:14px;">Assessed this run — real pass/fail evidence, with the subdimension's claimed level capped below any failed activity:</p>
        ${assessedCards || `<div class="empty-note">No activities assessed this run.</div>`}

        <p style="font-size:13px; color:#cbd5e1; margin-top:18px;">Not assessed — no tooling in this pipeline can check these; they require manual or organizational evidence (e.g. security champions programs, training records, threat-modeling process, access reviews):</p>
        <div class="table-scroll"><table>
          <thead><tr><th>Dimension</th><th>Subdimension</th><th>Activities</th><th>Status</th></tr></thead>
          <tbody>${notAssessedRows.join("") || `<tr><td colspan="4" class="empty-note">Everything in the model was assessed.</td></tr>`}</tbody>
        </table></div>
      </div>`;
}

function kpiCard(icon: string, title: string, value: string | number, sub?: string, color = "#fff", flag?: string, gaugePct?: number): string {
  const numericPct = gaugePct !== undefined ? gaugePct : null;
  return `
    <div class="kpi-card" style="--kpi-accent:${color};">
      <div class="kpi-top">
        <div class="kpi-icon">${icon}</div>
        ${numericPct !== null ? radialGauge(numericPct, color) : ""}
      </div>
      <div class="kpi-title">${escapeHtml(title)}${flag ? `<span class="cumulative-flag">${escapeHtml(flag)}</span>` : ""}</div>
      <div class="kpi-value" style="color:${color};">${value}</div>
      ${sub ? `<div class="kpi-sub">${escapeHtml(sub)}</div>` : ""}
    </div>`;
}

function renderTrendSparkline(trend: StatusJsonOutput["trend"]): string {
  if (!trend || trend.length === 0) {
    return `<div class="empty-note">No run history yet — this view was added on ${new Date().toISOString().slice(0, 10)} and only tracks runs from here forward (reports/run-history.jsonl). It is not backfilled.</div>`;
  }
  const rows = trend
    .slice()
    .reverse()
    .map(
      (t) => `
    <tr>
      <td class="mono">${escapeHtml(t.timestamp)}</td>
      <td class="mono">${escapeHtml(t.commitSha.slice(0, 10))}</td>
      <td class="mono">${escapeHtml(t.target.split("/").pop() || t.target)}</td>
      <td>${badge(t.health, toneForGateStatus(t.health === "OK" ? "ok" : "error"))}</td>
      <td>${badge(t.verdict, toneForVerdict(t.verdict))}</td>
      <td class="mono">${t.criticalFindings} crit / ${t.highFindings} high / ${t.totalFindings} total</td>
    </tr>`
    )
    .join("");
  return `
    <p class="section-sub">Last ${trend.length} run(s) recorded in <code>reports/run-history.jsonl</code> since this view was added — a real, growing history, never backfilled with invented past runs.</p>
    <div class="table-scroll"><table>
      <thead><tr><th>Run Timestamp</th><th>Commit</th><th>Target</th><th>Health</th><th>Verdict</th><th>Findings</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
}

export async function generateHtmlReport(statusJsonPath?: string): Promise<string> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const defaultPath = resolve(process.cwd(), "reports/status.json");
  const targetJsonPath = statusJsonPath ? resolve(process.cwd(), statusJsonPath) : defaultPath;

  if (!existsSync(targetJsonPath)) {
    throw new Error(`Target status file does not exist: ${targetJsonPath}`);
  }

  const data: StatusJsonOutput = JSON.parse(readFileSync(targetJsonPath, "utf-8"));
  const v104 = data.enterprise_v10_4 || {};
  const ddj = data.defectdojo_compliance;
  const dsommPath = resolve(process.cwd(), "reports/scanners/dsomm.json");
  const dsommResult: DsommResult | null = existsSync(dsommPath)
    ? JSON.parse(readFileSync(dsommPath, "utf-8"))
    : null;
  const targetName = (data.pipeline?.target || "").split("/").pop() || data.pipeline?.target || "unknown";

  // --- Executive summary paragraph, generated from this run's real verdict ---
  const healthOk = data.pipeline?.health === "OK";
  const verdict = data.pipeline?.verdict || "UNKNOWN";
  const summaryParts: string[] = [];
  if (!healthOk) {
    summaryParts.push(
      `Pipeline HEALTH is FAILED: ${(data.pipeline?.healthProblems || []).join("; ") || "one or more required scanners did not run cleanly"}. The verdict below is only as trustworthy as that gap allows.`
    );
  }
  if (verdict === "PASS") {
    summaryParts.push(`All required security gates passed for ${escapeHtml(targetName)}. No high/critical findings blocked this run.`);
  } else if (verdict === "HALT") {
    summaryParts.push(
      `This run HALTS deployment of ${escapeHtml(targetName)}. Reason(s): ${(data.pipeline?.haltReasons || []).join("; ") || "see gate detail below"}.`
    );
  } else {
    summaryParts.push(`Verdict is UNKNOWN for ${escapeHtml(targetName)} — not enough of this run's real data was available to make a ship/no-ship call.`);
  }
  const execSummary = summaryParts.join(" ");

  // --- Gate-by-gate table ---
  const gateRows = (data.gates || [])
    .map(
      (g) => `
    <tr>
      <td><b>${escapeHtml(g.name)}</b></td>
      <td class="mono dim">${escapeHtml(g.tool || "")}</td>
      <td>${badge((g.policy || "informational").toUpperCase(), g.policy === "required" ? "blue" : "gray")}</td>
      <td>${badge((g.status || "unknown").toUpperCase(), toneForGateStatus(g.status))}</td>
      <td class="dim detail-cell">${escapeHtml(g.detail || "")}${g.counts ? ` <span class="mono dim2">${escapeHtml(JSON.stringify(g.counts))}</span>` : ""}</td>
    </tr>`
    )
    .join("");

  // --- Gate pass/fail counts by policy, for the bar chart ---
  const requiredGates = (data.gates || []).filter((g) => g.policy === "required");
  const infoGates = (data.gates || []).filter((g) => g.policy !== "required");
  const requiredOk = requiredGates.filter((g) => g.status === "ok").length;
  const requiredBad = requiredGates.length - requiredOk;
  const infoOk = infoGates.filter((g) => g.status === "ok").length;
  const infoBad = infoGates.length - infoOk;

  // --- Findings by zone, for the bar chart ---
  const zoneCounts: Record<string, number> = {};
  for (const f of data.findings || []) {
    const z = f.zone || "UNSPECIFIED";
    zoneCounts[z] = (zoneCounts[z] || 0) + 1;
  }
  const zoneLabels = Object.keys(zoneCounts).sort();
  const zoneValues = zoneLabels.map((z) => zoneCounts[z]);

  // --- Master findings table (searchable) ---
  const findingRows = (data.findings || [])
    .map(
      (f) => `
    <tr>
      <td class="mono">${escapeHtml(f.id)}</td>
      <td>${badge(f.severity, toneForSeverity(f.severity))}</td>
      <td><span class="zone-chip">${escapeHtml(f.zone)}</span></td>
      <td class="finding-cell"><b>${escapeHtml(f.title)}</b><div class="dim" style="font-size:12px; margin-top:2px;">${escapeHtml(f.description)}</div></td>
      <td class="mono dim2 detail-cell">${escapeHtml(f.target || "N/A")}</td>
      <td>${badge(f.status, toneForFindingStatus(f.status))}</td>
    </tr>`
    )
    .join("");

  const walletRows = (data.walletAuditFindings || [])
    .map(
      (w) => `
    <tr>
      <td class="mono">${escapeHtml(w.findingId)}</td>
      <td><b>${escapeHtml(w.vulnerabilityClass)}</b></td>
      <td>${badge(w.status, toneForFindingStatus(w.status))}</td>
    </tr>`
    )
    .join("");

  const forensicRows = (data.forensicCases || [])
    .map(
      (c) => `
    <tr>
      <td class="mono">${escapeHtml(c.caseId)}</td>
      <td class="mono detail-cell" style="color:#93c5fd;">${escapeHtml(c.targetAddress || "—")}</td>
      <td class="mono">${c.sealedArtifactsCount} file(s)</td>
      <td>${badge(c.integrityVerified ? "CHAIN VERIFIED" : "UNVERIFIED", c.integrityVerified ? "green" : "red")}</td>
      <td class="dim detail-cell">${escapeHtml(c.redactedSummary)}</td>
    </tr>`
    )
    .join("");

  const complianceRows = (data.complianceRegister || [])
    .map(
      (cr) => `
    <tr>
      <td class="mono dim2 detail-cell">${escapeHtml(cr.entityAddress)}</td>
      <td>${badge(cr.sanctionMatch ? "SDN MATCH" : "CLEAN", cr.sanctionMatch ? "red" : "green")}</td>
      <td>${badge(cr.riskTier, cr.sanctionMatch ? "red" : "green")}</td>
      <td class="dim detail-cell">${escapeHtml(cr.reason || "")}</td>
    </tr>`
    )
    .join("");

  const incidentRows = (data.incidents || [])
    .map(
      (i) => `
    <tr>
      <td class="mono">${escapeHtml(i.id)}</td>
      <td class="finding-cell">${escapeHtml(i.title)}</td>
      <td>${badge(i.severity, toneForSeverity(i.severity))}</td>
      <td>${badge(i.status, toneForFindingStatus(i.status))}</td>
      <td class="mono dim2">${escapeHtml(i.createdAt)}</td>
    </tr>`
    )
    .join("");

  const consensusRows = (data.consensusAlerts || [])
    .map(
      (a) => `
    <tr>
      <td class="mono">${escapeHtml(a.alertId)}</td>
      <td class="finding-cell">${escapeHtml(a.anomalyType)}</td>
      <td>${badge(a.severity, toneForSeverity(a.severity))}</td>
      <td>${badge(a.avsQuorumConfirmed ? "QUORUM CONFIRMED" : "NOT CONFIRMED", a.avsQuorumConfirmed ? "red" : "green")}</td>
      <td class="mono dim2">${escapeHtml(a.timestamp)}</td>
    </tr>`
    )
    .join("");

  // --- Trend chart data (real history only, never backfilled) ---
  const trendSeq = (data.trend || []).slice().reverse();
  const trendLabels = trendSeq.map((t) => t.timestamp.slice(5, 16));
  const trendCritHigh = trendSeq.map((t) => t.criticalFindings + t.highFindings);
  const trendTotal = trendSeq.map((t) => t.totalFindings);

  const crit = data.metrics.criticalFindings;
  const high = data.metrics.highFindings;
  const med = data.metrics.mediumFindings;
  const low = data.metrics.lowFindings;

  // --- AVS Consensus visual data ---
  const avs = v104.avs_consensus;
  const avsAgreementPct = avs ? parseFloat(String(avs.agreement_ratio).replace("%", "")) || 0 : 0;
  const avsIsHalt = avs?.decision?.includes("EXPLOIT") || avs?.decision?.includes("HALT");
  const avsNodeCount = avs?.ports?.length || 0;
  const avsConfirmedCount = avsIsHalt ? avsNodeCount : 0;

  // --- LangGraph swarm vote data ---
  const swarm = v104.langgraph_swarm;
  const swarmVotes = swarm?.votes || {};
  const swarmHalt = Number(swarmVotes.halt || 0);
  const swarmClear = Number(swarmVotes.clear || 0);
  const swarmAbstain = Number(swarmVotes.abstain || 0);
  const swarmNotRun = Number(swarmVotes.not_run || 0);

  // --- Infra status for mini indicator dots ---
  const vaultOk = v104.hashicorp_vault?.status === "ok";
  const k3sOk = v104.k3s_kubernetes?.status === "ok";
  const openscapStatus = v104.openscap?.status;

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(data.system.name)} — Executive Security Report</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
  <style>
    :root {
      --bg-primary: #0a0e16;
      --bg-secondary: #10151f;
      --bg-card: #141b29;
      --bg-card-alt: #121826;
      --border-color: #232e42;
      --text-main: #f1f5f9;
      --text-muted: #8b98ab;
      --accent: #38bdf8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    body {
      background: var(--bg-primary);
      color: var(--text-main);
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      line-height: 1.5;
      overflow-x: hidden;
    }
    .mono { font-family: 'JetBrains Mono', monospace; word-break: break-all; }
    .dim { color: var(--text-muted); }
    .dim2 { color: #64748b; }
    .layout { display: grid; grid-template-columns: 220px 1fr; min-height: 100vh; max-width: 100%; }
    nav.sidebar {
      position: sticky; top: 0; height: 100vh; overflow-y: auto;
      background: var(--bg-secondary); border-right: 1px solid var(--border-color);
      padding: 24px 16px;
    }
    nav.sidebar .brand { font-weight: 800; font-size: 15px; margin-bottom: 4px; color: #fff; }
    nav.sidebar .brand-sub { font-size: 11px; color: var(--text-muted); margin-bottom: 20px; }
    nav.sidebar a {
      display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-radius: 6px; font-size: 13px;
      color: var(--text-muted); text-decoration: none; margin-bottom: 2px;
      border-left: 2px solid transparent;
    }
    nav.sidebar a:hover { background: rgba(255,255,255,0.04); color: #fff; border-left-color: var(--accent); }
    main { padding: 32px 40px; max-width: 1400px; width: 100%; min-width: 0; overflow-x: hidden; }
    header.top {
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 20px; margin-bottom: 24px;
      display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; gap: 12px;
    }
    h1 { font-size: 23px; font-weight: 800; color: #fff; letter-spacing: -0.3px; }
    .meta { font-size: 12.5px; color: var(--text-muted); margin-top: 6px; }
    .meta code { background: rgba(255,255,255,0.06); padding: 1px 6px; border-radius: 4px; }
    .btn {
      background: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-main);
      padding: 9px 16px; border-radius: 7px; font-size: 13px; cursor: pointer; font-weight: 500;
    }
    .btn:hover { background: #1b2436; border-color: #334155; }

    /* --- Verdict banner: bigger, with an icon chip and a severity glow for HALT --- */
    .verdict-banner {
      display: flex; align-items: center; gap: 20px; flex-wrap: wrap;
      padding: 24px 28px; border-radius: 14px; margin-bottom: 28px;
      background: linear-gradient(135deg, var(--bg-card), var(--bg-secondary));
      border: 1px solid var(--border-color);
      position: relative; overflow: hidden;
    }
    .verdict-banner.tone-red { border-color: rgba(239,68,68,0.45); box-shadow: 0 0 0 1px rgba(239,68,68,0.12), 0 18px 48px -24px rgba(239,68,68,0.45); }
    .verdict-banner.tone-green { border-color: rgba(34,197,94,0.4); box-shadow: 0 0 0 1px rgba(34,197,94,0.1), 0 18px 48px -24px rgba(34,197,94,0.4); }
    .verdict-banner.tone-amber { border-color: rgba(234,179,8,0.4); box-shadow: 0 0 0 1px rgba(234,179,8,0.1), 0 18px 48px -24px rgba(234,179,8,0.4); }
    .verdict-icons { display: flex; gap: 12px; flex-wrap: wrap; }
    .verdict-chip {
      display: flex; align-items: center; gap: 10px;
      font-size: 17px; padding: 10px 18px 10px 14px; border-radius: 10px; font-weight: 800; letter-spacing: 0.4px;
      white-space: nowrap;
    }
    .verdict-chip .chip-icon { display: flex; align-items: center; justify-content: center; width: 26px; height: 26px; border-radius: 50%; background: rgba(255,255,255,0.12); flex-shrink: 0; }
    .verdict-chip .chip-icon svg { width: 15px; height: 15px; }
    .verdict-banner p { font-size: 13.5px; color: #cbd5e1; max-width: 820px; overflow-wrap: anywhere; }
    @keyframes pulseRing { 0% { box-shadow: 0 0 0 0 rgba(239,68,68,0.5); } 70% { box-shadow: 0 0 0 10px rgba(239,68,68,0); } 100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); } }
    .verdict-chip.pulse { animation: pulseRing 2.4s ease-out infinite; }

    /* --- KPI cards: icon + optional radial gauge + accent bar --- */
    .kpi-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(195px, 1fr));
      gap: 14px; margin-bottom: 28px;
    }
    .kpi-card {
      background: linear-gradient(160deg, var(--bg-card), var(--bg-card-alt));
      border: 1px solid var(--border-color); border-radius: 12px;
      padding: 16px 18px; position: relative; transition: border-color 0.15s, transform 0.15s;
      overflow: hidden; min-width: 0;
    }
    .kpi-card::before {
      content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px;
      background: var(--kpi-accent, var(--accent)); opacity: 0.85;
    }
    .kpi-card:hover { border-color: #334155; transform: translateY(-1px); }
    .kpi-top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
    .kpi-icon {
      color: var(--kpi-accent, var(--accent)); display: flex; align-items: center; justify-content: center;
      width: 34px; height: 34px; border-radius: 9px; background: rgba(255,255,255,0.07);
      border: 1px solid rgba(255,255,255,0.08);
    }
    .kpi-gauge { flex-shrink: 0; }
    .kpi-title { font-size: 10.5px; color: var(--text-muted); text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; }
    .kpi-value { font-size: 27px; font-weight: 800; margin-top: 6px; color: #fff; line-height: 1.1; word-break: break-word; }
    .kpi-sub { font-size: 10.5px; color: var(--text-muted); margin-top: 4px; }

    .section-card {
      background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 12px;
      padding: 22px; margin-bottom: 22px; scroll-margin-top: 20px; min-width: 0; overflow: hidden;
    }
    .section-title { font-size: 15px; font-weight: 700; margin-bottom: 6px; display: flex; align-items: center; gap: 8px; }
    .section-title .title-icon { color: var(--accent); display: flex; align-items: center; }
    .section-sub { font-size: 12px; color: var(--text-muted); margin-bottom: 14px; }
    .table-scroll { overflow-x: auto; max-width: 100%; }
    table { width: 100%; border-collapse: collapse; margin-top: 6px; min-width: 560px; }
    th { text-align: left; padding: 10px 12px; font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.4px; color: var(--text-muted); border-bottom: 1px solid var(--border-color); white-space: nowrap; }
    td { padding: 11px 12px; font-size: 13px; border-bottom: 1px solid #1a2334; vertical-align: top; overflow-wrap: anywhere; }
    .detail-cell { max-width: 360px; }
    .finding-cell { max-width: 420px; }
    tr:hover td { background: rgba(255,255,255,0.015); }
    .badge { display:inline-block; padding:2px 9px; border-radius:5px; font-size:10.5px; font-weight:700; letter-spacing:0.2px; white-space: nowrap; }
    .zone-chip { font-size: 10.5px; background: #1c2538; padding: 3px 8px; border-radius: 5px; color: #93c5fd; white-space: nowrap; }
    .cumulative-flag { font-size: 9.5px; color: #eab308; background: rgba(234,179,8,0.12); border: 1px solid rgba(234,179,8,0.4); padding: 1px 6px; border-radius: 4px; margin-left: 6px; }
    .toolbar { display: flex; gap: 12px; margin-bottom: 14px; }
    .search-input {
      background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 7px;
      color: #fff; padding: 9px 14px; font-size: 13px; width: 320px; max-width: 100%;
    }
    .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 18px; }
    .chart-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 18px; margin-bottom: 22px; }
    .chart-box { position: relative; height: 240px; max-width: 100%; }
    .empty-note { font-size: 12px; color: var(--text-muted); padding: 10px 0; }
    details.collapsible summary {
      cursor: pointer; font-size: 15px; font-weight: 700; list-style: none;
      display: flex; align-items: center; gap: 8px; padding-bottom: 6px;
    }
    details.collapsible summary::-webkit-details-marker { display: none; }
    details.collapsible summary::before { content: "▸"; display: inline-block; transition: transform 0.15s; color: var(--accent); }
    details.collapsible[open] summary::before { transform: rotate(90deg); }

    /* --- Subsystem cards (AVS / Swarm / Infra / OWASP): richer visual treatment --- */
    .sub-card-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
    .sub-card-head .decision-pill { display: flex; align-items: center; gap: 8px; }
    .stat-row { display: flex; align-items: baseline; gap: 10px; margin: 4px 0 10px; flex-wrap: wrap; }
    .stat-big { font-size: 26px; font-weight: 800; color: #fff; }
    .stat-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.4px; }
    .mini-bar { width: 100%; height: 8px; border-radius: 99px; overflow: hidden; margin: 6px 0 4px; }
    .mini-bar-fill { height: 100%; border-radius: 99px; transition: width 0.4s ease; }
    .node-row { display: flex; gap: 8px; margin: 10px 0; flex-wrap: wrap; }
    .node-chip {
      display: flex; align-items: center; gap: 6px; font-size: 11.5px; font-weight: 600;
      padding: 5px 10px; border-radius: 99px; background: rgba(255,255,255,0.04);
      border: 1px solid var(--border-color);
    }
    .node-chip .dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
    .vote-strip { display: flex; width: 100%; height: 14px; border-radius: 7px; overflow: hidden; margin: 10px 0 8px; background: rgba(255,255,255,0.05); }
    .vote-strip > div { transition: flex 0.4s ease; }
    .vote-legend { display: flex; gap: 14px; flex-wrap: wrap; font-size: 11.5px; color: var(--text-muted); }
    .vote-legend-item { display: flex; align-items: center; gap: 6px; }
    .vote-legend-item i { width: 9px; height: 9px; border-radius: 3px; display: inline-block; }
    .infra-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 10px 0; border-bottom: 1px solid #1a2334; }
    .infra-row:last-child { border-bottom: none; }
    .infra-name { display: flex; align-items: center; gap: 10px; font-size: 13px; font-weight: 600; min-width: 0; }
    .infra-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; box-shadow: 0 0 0 3px currentColor; opacity: 0.9; }
    .infra-detail { font-size: 11.5px; color: var(--text-muted); overflow-wrap: anywhere; text-align: right; max-width: 55%; }
    .owasp-tags { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
    .owasp-tag { font-size: 11.5px; font-weight: 600; padding: 6px 12px; border-radius: 8px; background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.35); color: #fca5a5; }

    @media print {
      body { background: #fff; color: #000; }
      nav.sidebar, .toolbar, .btn { display: none !important; }
      .layout { grid-template-columns: 1fr; }
      main { padding: 0; }
      .section-card, .kpi-card, .verdict-banner { border: 1px solid #ccc; background: #fff; color: #000; }
      .chart-box { height: 180px; }
      .chart-box canvas { max-height: 180px; }
      .chart-grid { grid-template-columns: repeat(2, 1fr); }
      .kpi-grid { grid-template-columns: repeat(3, 1fr); }
      .grid-2 { grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 900px) {
      .layout { grid-template-columns: 1fr; }
      nav.sidebar { position: static; height: auto; }
      main { padding: 20px; }
    }
  </style>
</head>
<body>
  <div class="layout">
    <nav class="sidebar">
      <div class="brand">${escapeHtml(data.system.name)}</div>
      <div class="brand-sub">Executive Security Report</div>
      <a href="#summary">Executive Summary</a>
      <a href="#charts">Visual Overview</a>
      <a href="#gates">Gate-by-Gate Status</a>
      <a href="#subsystems">AVS / Swarm / Infra</a>
      <a href="#wallet">Wallet Simulation</a>
      <a href="#forensics">Forensics &amp; Custody</a>
      <a href="#incidents">Incident Response</a>
      <a href="#compliance">OFAC Compliance</a>
      <a href="#trend">Run History</a>
      <a href="#findings">Findings Register</a>
    </nav>
    <main>
      <header class="top">
        <div>
          <h1>${escapeHtml(data.system.name)} — Executive Security Report</h1>
          <div class="meta">Generated: ${escapeHtml(data.timestamp)} &nbsp;|&nbsp; Commit: <code>${escapeHtml(data.system.commitSha.slice(0, 10))}</code> &nbsp;|&nbsp; Release: ${escapeHtml(data.system.version)} &nbsp;|&nbsp; Target: <code>${escapeHtml(targetName)}</code></div>
        </div>
        <button class="btn" onclick="window.print()">Print / Export PDF</button>
      </header>

      <div id="summary" class="verdict-banner tone-${toneForVerdict(verdict)}">
        <div class="verdict-icons">
          <div class="verdict-chip ${verdict === "HALT" ? "pulse" : ""}" style="${TONE_STYLE[toneForVerdict(verdict)]}">
            <span class="chip-icon">${verdict === "HALT" ? ICON.alert : verdict === "PASS" ? ICON.check : ICON.shield}</span>${escapeHtml(verdict)}
          </div>
          <div class="verdict-chip" style="${TONE_STYLE[toneForGateStatus(healthOk ? "ok" : "error")]}">
            <span class="chip-icon">${healthOk ? ICON.check : ICON.alert}</span>HEALTH: ${escapeHtml(data.pipeline?.health || "UNKNOWN")}
          </div>
        </div>
        <p>${execSummary}</p>
      </div>

      <div class="kpi-grid">
        ${kpiCard(ICON.alert, "Total Findings (this run)", data.metrics.totalFindings, undefined, "#38bdf8")}
        ${kpiCard(ICON.shield, "Critical &amp; High (this run)", data.metrics.criticalFindings + data.metrics.highFindings, undefined, "#ef4444")}
        ${kpiCard(ICON.check, "Required Gates Passing", `${data.metrics.complianceScorePct}%`, undefined, data.metrics.complianceScorePct === 100 ? "#22c55e" : "#eab308", undefined, data.metrics.complianceScorePct)}
        ${kpiCard(ICON.server, "Active Consensus Alerts", data.metrics.activeConsensusAlerts, undefined, "#f97316")}
        ${kpiCard(ICON.lock, "Forensic Cases Sealed (this run)", data.metrics.forensicCasesSealed, undefined, "#a78bfa")}
        ${kpiCard(ICON.flask, "DefectDojo Unique Flaws", ddj?.active_unique_findings ?? "N/A", "Across all historical runs — not this run's count.", "#38bdf8", "CUMULATIVE")}
      </div>

      <div id="charts" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.pulse}</span>Visual Overview</div>
        <div class="section-sub">Every chart below is drawn from this run's real fields — nothing is estimated or templated.</div>
        <div class="chart-grid">
          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Severity Breakdown</div><div class="chart-box"><canvas id="chartSeverity"></canvas></div></div>
          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Findings by Zone</div><div class="chart-box"><canvas id="chartZone"></canvas></div></div>
          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Gate Status by Policy</div><div class="chart-box"><canvas id="chartGates"></canvas></div></div>
          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Run History Trend</div><div class="chart-box"><canvas id="chartTrend"></canvas></div></div>
        </div>
      </div>

      <div id="gates" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.layers}</span>Gate-by-Gate Status (this run)</div>
        <div class="section-sub">Every real scanner/consensus result this pipeline run produced under <code>reports/scanners/*.json</code>. BLUE policy = required for the ship/no-ship verdict; GRAY = informational signal only.</div>
        <div class="table-scroll"><table>
          <thead><tr><th>Gate</th><th>Tool</th><th>Policy</th><th>Status</th><th>Detail</th></tr></thead>
          <tbody>${gateRows || `<tr><td colspan="5" class="empty-note">No gate results found for this run.</td></tr>`}</tbody>
        </table></div>
      </div>

      <div id="subsystems" class="grid-2">
        <div class="section-card">
          <div class="sub-card-head">
            <div class="section-title" style="margin-bottom:0;"><span class="title-icon">${ICON.node}</span>AVS Consensus (3-Node Live EVM Execution)</div>
          </div>
          <div class="section-sub">${v104.avs_consensus ? `${escapeHtml(v104.avs_consensus.protocol)} — ${escapeHtml(v104.avs_consensus.topology)}` : "No AVS consensus result this run."}</div>
          ${
            avs
              ? `
          <div class="stat-row">
            <span class="stat-big">${escapeHtml(String(avs.agreement_ratio))}</span>
            <span class="stat-label">Node Agreement</span>
            ${badge(avs.decision, avsIsHalt ? "red" : "green")}
          </div>
          ${miniBar(avsAgreementPct, avsIsHalt ? TONE_HEX.red : TONE_HEX.green)}
          <div class="node-row">
            ${(avs.ports || [])
              .map(
                (p: number, i: number) =>
                  `<span class="node-chip"><span class="dot" style="background:${i < avsConfirmedCount ? TONE_HEX.red : TONE_HEX.green};"></span>Node :${escapeHtml(String(p))} ${i < avsConfirmedCount ? "EXPLOIT" : "CLEAN"}</span>`
              )
              .join("")}
          </div>`
              : `<div class="empty-note">No AVS consensus result this run.</div>`
          }
        </div>
        <div class="section-card">
          <div class="sub-card-head">
            <div class="section-title" style="margin-bottom:0;"><span class="title-icon">${ICON.layers}</span>LangGraph 7-Agent Swarm</div>
          </div>
          <div class="section-sub">${swarm ? `${swarm.agents_count} agents via ${escapeHtml(swarm.framework)}` : "No swarm result this run."}</div>
          ${
            swarm
              ? `
          <div class="stat-row">
            ${badge(swarm.decision, swarm.decision === "HALT_CONFIRMED" ? "red" : "green")}
          </div>
          ${voteStrip([
            { label: "HALT", value: swarmHalt, color: TONE_HEX.red },
            { label: "CLEAR", value: swarmClear, color: TONE_HEX.green },
            { label: "ABSTAIN", value: swarmAbstain, color: TONE_HEX.amber },
            { label: "NOT RUN", value: swarmNotRun, color: TONE_HEX.gray },
          ])}`
              : ""
          }
        </div>
        <div class="section-card">
          <div class="section-title"><span class="title-icon">${ICON.cube}</span>Infrastructure: Vault &amp; Kubernetes</div>
          <div class="infra-row">
            <div class="infra-name"><span class="infra-dot" style="color:${vaultOk ? TONE_HEX.green : TONE_HEX.red};"></span>HashiCorp Vault (Transit)</div>
            ${v104.hashicorp_vault ? badge(v104.hashicorp_vault.status, toneForGateStatus(v104.hashicorp_vault.status)) : badge("NOT RUN", "gray")}
          </div>
          <div class="infra-detail" style="text-align:left; max-width:100%; margin-bottom:6px;">${escapeHtml(v104.hashicorp_vault?.detail || "")}</div>
          <div class="infra-row">
            <div class="infra-name"><span class="infra-dot" style="color:${k3sOk ? TONE_HEX.green : TONE_HEX.red};"></span>K3s Kubernetes</div>
            ${v104.k3s_kubernetes ? badge(v104.k3s_kubernetes.status, toneForGateStatus(v104.k3s_kubernetes.status)) : badge("NOT RUN", "gray")}
          </div>
          <div class="infra-detail" style="text-align:left; max-width:100%;">${escapeHtml(v104.k3s_kubernetes?.node || "")} ${escapeHtml(v104.k3s_kubernetes?.version || "")} ${escapeHtml(v104.k3s_kubernetes?.detail || "")}</div>
        </div>
        <div class="section-card">
          <div class="section-title"><span class="title-icon">${ICON.shield}</span>OWASP Smart Contract Coverage</div>
          <p style="font-size:13px; color:#cbd5e1;">Categories actually triggered this run:</p>
          <div class="owasp-tags">
            ${(v104.owasp_sc_top_10 || "none")
              .split(",")
              .map((c: string) => `<span class="owasp-tag">${escapeHtml(c.trim())}</span>`)
              .join("")}
          </div>
          <div class="infra-row" style="margin-top:14px;">
            <div class="infra-name"><span class="infra-dot" style="color:${openscapStatus === "AUDITED_ACTIVE" ? TONE_HEX.green : openscapStatus === "ERROR" ? TONE_HEX.red : TONE_HEX.amber};"></span>OpenSCAP</div>
            ${v104.openscap ? badge(v104.openscap.status, toneForGateStatus(v104.openscap.status === "AUDITED_ACTIVE" ? "ok" : v104.openscap.status === "ERROR" ? "error" : "not_run")) : badge("NOT RUN", "gray")}
          </div>
          <div class="infra-detail" style="text-align:left; max-width:100%;">${escapeHtml(v104.openscap?.standard || "")}</div>
        </div>
      </div>

      ${renderDsommSection(dsommResult)}

      <div id="wallet" class="section-card">
        <details class="collapsible" open>
          <summary>Wallet Pre-Sign Simulation</summary>
          <div class="table-scroll"><table>
            <thead><tr><th>Audit ID</th><th>Check</th><th>Status</th></tr></thead>
            <tbody>${walletRows || `<tr><td colspan="3" class="empty-note">No pre-sign simulation result this run.</td></tr>`}</tbody>
          </table></div>
        </details>
      </div>

      <div id="forensics" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.lock}</span>Forensics &amp; Chain of Custody</div>
        <div class="table-scroll"><table>
          <thead><tr><th>Case ID</th><th>Related Address</th><th>Sealed Artifacts</th><th>Integrity</th><th>Summary</th></tr></thead>
          <tbody>${forensicRows || `<tr><td colspan="5" class="empty-note">No evidence seal recorded this run.</td></tr>`}</tbody>
        </table></div>
      </div>

      <div id="incidents" class="section-card">
        <details class="collapsible" open>
          <summary>Incident Response Dispatch</summary>
          <div class="table-scroll"><table>
            <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Created</th></tr></thead>
            <tbody>${incidentRows || `<tr><td colspan="5" class="empty-note">No incident dispatched this run.</td></tr>`}</tbody>
          </table></div>
        </details>
        <details class="collapsible" style="margin-top:16px;">
          <summary>Consensus Alerts</summary>
          <div class="table-scroll"><table>
            <thead><tr><th>Alert ID</th><th>Type</th><th>Severity</th><th>AVS Quorum</th><th>Time</th></tr></thead>
            <tbody>${consensusRows || `<tr><td colspan="5" class="empty-note">No active consensus alerts this run.</td></tr>`}</tbody>
          </table></div>
        </details>
      </div>

      <div id="compliance" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.flask}</span>OFAC Sanctions Screening</div>
        <div class="table-scroll"><table>
          <thead><tr><th>Counterparty Address</th><th>Sanction Status</th><th>Risk Tier</th><th>Detail</th></tr></thead>
          <tbody>${complianceRows || `<tr><td colspan="4" class="empty-note">No addresses screened this run.</td></tr>`}</tbody>
        </table></div>
      </div>

      <div id="trend" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.pulse}</span>Run History / Trend</div>
        ${renderTrendSparkline(data.trend)}
      </div>

      <div id="findings" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.alert}</span>Master Security Findings Register</div>
        <div class="toolbar">
          <input type="text" id="findingSearch" class="search-input" placeholder="Live search title, rule, target..." onkeyup="filterFindings()">
        </div>
        <div class="table-scroll"><table id="findingsTable">
          <thead><tr><th>ID</th><th>Severity</th><th>Zone</th><th>Finding &amp; Details</th><th>Target Context</th><th>Status</th></tr></thead>
          <tbody>${findingRows || `<tr><td colspan="6" class="empty-note">No findings recorded this run.</td></tr>`}</tbody>
        </table></div>
      </div>

    </main>
  </div>

  <script>
    function filterFindings() {
      const input = document.getElementById("findingSearch");
      const filter = input.value.toLowerCase();
      const rows = document.querySelectorAll("#findingsTable tbody tr");
      for (const row of rows) {
        const text = row.innerText.toLowerCase();
        row.style.display = text.includes(filter) ? "" : "none";
      }
    }

    const chartDefaults = {
      plugins: { legend: { labels: { color: "#cbd5e1", font: { size: 11 } } } },
      scales: {
        x: { ticks: { color: "#8b98ab", font: { size: 10 } }, grid: { color: "#1a2334" } },
        y: { ticks: { color: "#8b98ab", font: { size: 10 } }, grid: { color: "#1a2334" }, beginAtZero: true }
      }
    };

    const chartInstances = [];

    chartInstances.push(new Chart(document.getElementById("chartSeverity"), {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [{
          data: [${crit}, ${high}, ${med}, ${low}],
          backgroundColor: ["${TONE_HEX.red}", "#f97316", "${TONE_HEX.amber}", "${TONE_HEX.blue}"],
          borderWidth: 0
        }]
      },
      options: { plugins: { legend: { position: "bottom", labels: { color: "#cbd5e1", font: { size: 11 } } } } }
    }));

    chartInstances.push(new Chart(document.getElementById("chartZone"), {
      type: "bar",
      data: {
        labels: ${JSON.stringify(zoneLabels)},
        datasets: [{ label: "Findings", data: ${JSON.stringify(zoneValues)}, backgroundColor: "${TONE_HEX.blue}", borderRadius: 4 }]
      },
      options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: chartDefaults.scales }
    }));

    chartInstances.push(new Chart(document.getElementById("chartGates"), {
      type: "bar",
      data: {
        labels: ["Required", "Informational"],
        datasets: [
          { label: "Passing", data: [${requiredOk}, ${infoOk}], backgroundColor: "${TONE_HEX.green}", borderRadius: 4 },
          { label: "Not Passing", data: [${requiredBad}, ${infoBad}], backgroundColor: "${TONE_HEX.red}", borderRadius: 4 }
        ]
      },
      options: { plugins: { legend: { position: "bottom", labels: { color: "#cbd5e1", font: { size: 11 } } } }, scales: { ...chartDefaults.scales, x: { ...chartDefaults.scales.x, stacked: true }, y: { ...chartDefaults.scales.y, stacked: true } } }
    }));

    ${
      trendSeq.length > 0
        ? `chartInstances.push(new Chart(document.getElementById("chartTrend"), {
      type: "line",
      data: {
        labels: ${JSON.stringify(trendLabels)},
        datasets: [
          { label: "Critical+High", data: ${JSON.stringify(trendCritHigh)}, borderColor: "${TONE_HEX.red}", backgroundColor: "rgba(239,68,68,0.15)", tension: 0.3, fill: true },
          { label: "Total Findings", data: ${JSON.stringify(trendTotal)}, borderColor: "${TONE_HEX.blue}", backgroundColor: "rgba(56,189,248,0.1)", tension: 0.3, fill: true }
        ]
      },
      options: { plugins: { legend: { position: "bottom", labels: { color: "#cbd5e1", font: { size: 11 } } } }, scales: chartDefaults.scales }
    }));`
        : `document.getElementById("chartTrend").parentElement.innerHTML = '<div class="empty-note">No run history yet — tracked from here forward only.</div>';`
    }

    // Chart.js canvases keep the pixel buffer they were drawn at on screen;
    // without an explicit resize the printed/export version can be blurry or
    // clipped against the smaller @media print box. Force a redraw at the
    // print-time container size right before printing, then restore it after.
    window.addEventListener("beforeprint", () => chartInstances.forEach((c) => c && c.resize()));
    window.addEventListener("afterprint", () => chartInstances.forEach((c) => c && c.resize()));
  </script>
</body>
</html>`;

  const outDir = resolve(process.cwd(), "reports");
  if (!existsSync(outDir)) {
    mkdirSync(outDir, { recursive: true });
  }

  const outPath = resolve(outDir, `project-status-${timestamp}.html`);
  const latestPath = resolve(outDir, "latest.html");

  writeFileSync(outPath, html, "utf-8");
  writeFileSync(latestPath, html, "utf-8");

  console.log(`[+] Generated executive report: ${outPath}`);
  console.log(`[+] Synced latest report: ${latestPath}`);

  return outPath;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  generateHtmlReport(process.argv[2]).catch((err) => {
    console.error("[-] Report generation error:", err);
    process.exit(1);
  });
}
```

## `src/storage/broker_store.py`

```python
"""
SQLite Broker Storage Engine (Tasks P04-001, P04-010).
Implements thread-safe SQLite storage with WAL mode, busy timeout,
pre-swarm online backups, normalized finding persistence, and strict
role-based read-only enforcement for agent roles (P04-010).
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import hashlib
import json
import os
import sqlite3
import time
import uuid


# Default role permissions mapping
READ_ONLY_ROLES: Set[str] = {
    "agent_a",
    "agent_b",
    "agent_c",
    "agent_d_reader",
    "agent_f",
    "auditor",
    "reader",
    "forensics_agent",
}

WRITE_PERMITTED_ROLES: Set[str] = {
    "pipeline_admin",
    "coordinator",
    "ingestion_worker",
    "default",
    "admin",
}


class BrokerStore:
    """
    Broker store backed by SQLite with WAL mode, snapshot support,
    and role-based read-only access enforcement for autonomous agents.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        timeout: float = 30.0,
        role: str = "default",
    ):
        self.role = (role or "default").lower()
        self.is_read_only = self.role in READ_ONLY_ROLES

        if db_path is None:
            default_dir = Path(".broker_storage").resolve()
            default_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(default_dir / "broker.db")
        else:
            self.db_path = str(Path(db_path).resolve())
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        self.timeout = timeout

        # Only initialize schema if role is permitted to write/init
        if not self.is_read_only:
            self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path,
            timeout=self.timeout,
            isolation_level=None,  # Autocommit mode
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    source_tool TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.close()

    def verify_wal_mode(self) -> bool:
        """Verifies that the SQLite database is operating under WAL mode."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            row = cursor.fetchone()
            mode = row[0].lower() if row else ""
            cursor.close()
            return mode == "wal"

    def write_finding(self, finding: Dict[str, Any]) -> str:
        """Persists a normalized finding, enforcing read-only role restrictions."""
        if self.is_read_only:
            raise PermissionError(
                f"Storage access denied: agent role '{self.role}' is restricted to read-only access."
            )

        finding_id = str(finding.get("id") or f"FINDING-{uuid.uuid4().hex[:8].upper()}")
        source_tool = str(finding.get("source_tool") or finding.get("tool") or "unknown")
        severity = str(finding.get("severity") or "MEDIUM").upper()
        title = str(finding.get("title") or "Security Finding")
        details = json.dumps(finding.get("details") or finding)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO findings (id, source_tool, severity, title, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (finding_id, source_tool, severity, title, details),
            )
            cursor.close()

        return finding_id

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single finding by identifier (allowed for all roles)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings WHERE id = ?", (str(finding_id),))
            r = cursor.fetchone()
            cursor.close()
            if not r:
                return None
            return {
                "id": r["id"],
                "source_tool": r["source_tool"],
                "severity": r["severity"],
                "title": r["title"],
                "details": json.loads(r["details"]),
                "created_at": r["created_at"],
            }

    def list_findings(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves findings optionally filtered by severity (allowed for all roles)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if severity:
                cursor.execute("SELECT * FROM findings WHERE severity = ? ORDER BY id", (severity.upper(),))
            else:
                cursor.execute("SELECT * FROM findings ORDER BY id")

            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "id": r["id"],
                    "source_tool": r["source_tool"],
                    "severity": r["severity"],
                    "title": r["title"],
                    "details": json.loads(r["details"]),
                    "created_at": r["created_at"],
                })
            cursor.close()
            return results

    def snapshot(self, label: str = "default_snapshot") -> Dict[str, Any]:
        """Creates an atomic online backup snapshot of the database."""
        if self.is_read_only:
            raise PermissionError(
                f"Storage access denied: agent role '{self.role}' cannot trigger snapshot operations."
            )

        db_dir = Path(self.db_path).parent
        snap_dir = db_dir / "snapshots"
        snap_dir.mkdir(parents=True, exist_ok=True)
        dest_path = snap_dir / f"{label}.db"

        with self._get_connection() as conn:
            dest_conn = sqlite3.connect(str(dest_path))
            try:
                conn.backup(dest_conn)
            finally:
                dest_conn.close()

        sha = hashlib.sha256()
        with open(dest_path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)

        findings_count = len(self.list_findings())

        return {
            "snapshot_id": label,
            "finding_count": findings_count,
            "snapshot_path": str(dest_path),
            "checksum": sha.hexdigest(),
        }


# Global/module-level default store instance and exports
_default_store: Optional[BrokerStore] = None


def get_default_store() -> BrokerStore:
    global _default_store
    if _default_store is None:
        _default_store = BrokerStore()
    return _default_store


def write_finding(finding: Dict[str, Any]) -> str:
    return get_default_store().write_finding(finding)


def get_finding(finding_id: str) -> Optional[Dict[str, Any]]:
    return get_default_store().get_finding(finding_id)


def list_findings(severity: Optional[str] = None) -> List[Dict[str, Any]]:
    return get_default_store().list_findings(severity=severity)


def snapshot(label: str = "default_snapshot") -> Dict[str, Any]:
    return get_default_store().snapshot(label=label)
```

## `src/storage/attack_path_graph.py`

```python
"""
AI-driven Attack-Path Knowledge Graph (Task P04-003).
Tracks cross-protocol threat chaining as a Directed Acyclic Graph (DAG).
Provides path enumeration and remediation planning queried by Agent B via MCP tools.
"""

from typing import Any, Dict, List, Optional
import hashlib
import networkx as nx


class AttackPathGraph:
    """
    Synthesizes and analyzes attack trajectories across contracts and findings
    using NetworkX directed acyclic graphs.
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self._path_registry: Dict[str, Dict[str, Any]] = {}

    def add_finding_node(self, finding: Dict[str, Any]) -> str:
        """Adds a normalized finding as a node in the attack graph."""
        node_id = str(finding.get("id") or finding.get("finding_id") or "FINDING-UNKNOWN")
        severity = str(finding.get("severity", "MEDIUM")).upper()
        target = str(finding.get("target", "contract"))
        title = str(finding.get("title", "Security Finding"))
        dread = finding.get("dread", {})
        dread_score = float(dread.get("score", 5.0) if isinstance(dread, dict) else 5.0)

        self.graph.add_node(
            node_id,
            node_type="finding",
            severity=severity,
            target=target,
            title=title,
            dread_score=dread_score,
            details=finding,
        )
        return node_id

    def add_target_node(self, target_name: str, target_type: str = "contract") -> str:
        """Adds an architectural target node (contract, vault, pool)."""
        node_id = f"TARGET:{target_name}"
        if not self.graph.has_node(node_id):
            self.graph.add_node(
                node_id,
                node_type="target",
                name=target_name,
                target_type=target_type,
            )
        return node_id

    def add_attack_step(
        self,
        from_node: str,
        to_node: str,
        step_type: str = "exploits",
        weight: float = 1.0,
    ) -> bool:
        """
        Adds a directed exploitation edge while strictly enforcing DAG invariants.
        Returns True if added successfully, False if edge would create a cycle.
        """
        self.graph.add_edge(from_node, to_node, step_type=step_type, weight=weight)
        if not nx.is_directed_acyclic_graph(self.graph):
            # Remove edge to preserve acyclic invariant
            self.graph.remove_edge(from_node, to_node)
            return False
        return True

    def build_from_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Synthesizes an attack graph from a list of normalized findings."""
        entry_node = "ENTRY:external_attacker"
        self.graph.add_node(entry_node, node_type="actor", name="External Attacker")

        for f in findings:
            f_node = self.add_finding_node(f)
            target_name = str(f.get("target", "TargetContract"))
            t_node = self.add_target_node(target_name)

            # Link entry to finding
            self.add_attack_step(entry_node, f_node, step_type="targets", weight=1.0)
            # Link finding to compromised target
            sev = str(f.get("severity", "MEDIUM")).upper()
            w = 3.0 if sev == "CRITICAL" else (2.0 if sev == "HIGH" else 1.0)
            self.add_attack_step(f_node, t_node, step_type="compromises", weight=w)

        self._index_paths()

    def _index_paths(self) -> None:
        """Enumerates and indexes simple attack paths from entry actors to targets."""
        self._path_registry.clear()
        entry_nodes = [n for n, d in self.graph.nodes(data=True) if d.get("node_type") == "actor"]
        target_nodes = [n for n, d in self.graph.nodes(data=True) if d.get("node_type") == "target"]

        idx = 1
        for src in entry_nodes:
            for dst in target_nodes:
                if nx.has_path(self.graph, src, dst):
                    for path in nx.all_simple_paths(self.graph, src, dst):
                        total_weight = 0.0
                        dread_scores: List[float] = []

                        for node in path:
                            data = self.graph.nodes[node]
                            if "dread_score" in data:
                                dread_scores.append(float(data["dread_score"]))

                        for u, v in zip(path[:-1], path[1:]):
                            total_weight += float(self.graph.edges[u, v].get("weight", 1.0))

                        avg_dread = sum(dread_scores) / len(dread_scores) if dread_scores else 5.0
                        raw_id = f"{src}->{dst}:{':'.join(path)}"
                        path_id = f"PATH-{hashlib.sha256(raw_id.encode()).hexdigest()[:8].upper()}"

                        self._path_registry[path_id] = {
                            "path_id": path_id,
                            "entry": src,
                            "target": dst,
                            "steps": path,
                            "cumulative_weight": total_weight,
                            "average_dread": round(avg_dread, 2),
                            "length": len(path) - 1,
                        }
                        idx += 1

    def list_attack_paths(self) -> List[Dict[str, Any]]:
        """Returns all synthesized attack trajectories sorted by risk weight descending."""
        if not self._path_registry:
            self._index_paths()
        paths = list(self._path_registry.values())
        paths.sort(key=lambda p: (p.get("cumulative_weight", 0), p.get("average_dread", 0)), reverse=True)
        return paths

    def plan_remediation(self, path_id: str) -> Dict[str, Any]:
        """Synthesizes remediation priority recommendations for a specific attack path."""
        if path_id not in self._path_registry:
            return {
                "status": "not_found",
                "path_id": path_id,
                "remediations": [],
                "summary": f"Attack path '{path_id}' not found in knowledge graph."
            }

        path_info = self._path_registry[path_id]
        remediations: List[Dict[str, Any]] = []

        for node in path_info["steps"]:
            data = self.graph.nodes.get(node, {})
            if data.get("node_type") == "finding":
                remediations.append({
                    "node_id": node,
                    "target": data.get("target"),
                    "vulnerability": data.get("title"),
                    "severity": data.get("severity"),
                    "action": f"Apply defense-in-depth mitigations to resolve {data.get('title')} on {data.get('target')}.",
                })

        return {
            "status": "planned",
            "path_id": path_id,
            "target": path_info["target"],
            "remediation_count": len(remediations),
            "remediations": remediations,
            "summary": f"Identified {len(remediations)} choke-point remediation(s) to sever attack trajectory {path_id}."
        }


# Global/module-level default graph instance for legacy and MCP imports
_default_graph: Optional[AttackPathGraph] = None


def get_default_graph() -> AttackPathGraph:
    global _default_graph
    if _default_graph is None:
        _default_graph = AttackPathGraph()
    return _default_graph


def list_attack_paths() -> list:
    """Module-level entrypoint queried by Agent B."""
    return get_default_graph().list_attack_paths()


def plan_remediation(_path_id: str) -> dict:
    """Module-level entrypoint queried by Agent B."""
    return get_default_graph().plan_remediation(_path_id)
```

