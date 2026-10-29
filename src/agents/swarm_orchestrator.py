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
from src.agents.swarm_memory import record_run, retrieve_similar  # noqa: E402

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
    retrieval_context: str
    swarm_decisions: Annotated[List[Dict[str, Any]], lambda a, b: a + b]


def _prompt(role: str, state: AgentState) -> str:
    # retrieval_context is "" on the honest-degrade path (no embedding model,
    # empty store, or a failed embedding call) -- the prompt below is then
    # byte-identical to the pre-RAG version, never a fabricated retrieved
    # example. See src/agents/swarm_memory.py's module docstring.
    retrieval_section = f"\n{state['retrieval_context']}\n" if state.get("retrieval_context") else ""
    return (
        f"You are the {role} agent in an automated smart-contract security SOC.\n"
        f"Decide whether deploying this contract must HALT (an exploitable HIGH or "
        f"CRITICAL risk exists) or is CLEAR (no exploitable high/critical risk).\n\n"
        f"CONTRACT: {state['contract_name']}\n"
        f"```solidity\n{state['contract_source']}\n```\n\n"
        f"STATIC + SYMBOLIC FINDINGS (Slither + Mythril):\n{state['findings_block']}\n"
        f"{retrieval_section}\n"
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

    # Phase 3a RAG: retrieve real similar past cases from this pipeline's own
    # history (src/agents/swarm_memory.py), once per run, shared by all 7
    # agents -- never fabricated, never silently skipped without saying so.
    retrieval_context, rag_retrieval_status = retrieve_similar(source, findings_block)
    print(f"    -> [RAG] retrieval: {rag_retrieval_status['status']} :: {rag_retrieval_status.get('detail', '')}")

    app = build_soc_graph()
    final = app.invoke({"contract_name": name, "contract_source": source,
                        "findings_block": findings_block, "retrieval_context": retrieval_context,
                        "swarm_decisions": []})
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

    # Phase 3a RAG write-back: only ever store a genuinely completed run --
    # status=="ok" means a real quorum (majority of 7) actually voted. A
    # not_run/error run has nothing real worth remembering and is never
    # written (see src/agents/swarm_memory.py's record_run() docstring for
    # why embedding failure alone does not also block this).
    rag_write_status = None
    if status == "ok":
        rag_write_status = record_run(name, source, findings_block, decision)
        print(f"    -> [RAG] store: {rag_write_status['status']} :: {rag_write_status.get('detail', '')}")

    report = {
        "target": target,
        "contract": name,
        "model_default": DEFAULT_MODEL,
        "findings_count": n_findings,
        "votes": {"halt": halt, "clear": clear, "abstain": abstain, "not_run": not_run},
        "decision": decision,
        "agents": decisions,
        "rag": {"retrieval": rag_retrieval_status, "write": rag_write_status},
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
