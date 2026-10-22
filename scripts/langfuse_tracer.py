#!/usr/bin/env python3
"""Streams one real Langfuse trace per run, built entirely from this run's
real reports/*.json files. No fabricated executive summary, no fixed
Tornado Cash address, no invented per-agent durations/token counts (none of
that is captured anywhere in this pipeline, so none of it is claimed here)."""
import os
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import write_result  # noqa: E402

_IMPACT_SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0,
                 "INFORMATIONAL": 1.0, "INFO": 1.0}
_IMPACT_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1, "INFO": 1}


def _read_json(rel):
    try:
        with open(rel) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _top_finding(sast):
    findings = (sast or {}).get("findings", [])
    if not findings:
        return None
    return max(findings, key=lambda f: _IMPACT_RANK.get((f.get("impact") or "").upper(), 0))


def stream_verification_trace():
    env = {}
    config_path = "config/.langfuse.env"
    if os.path.exists(config_path):
        with open(config_path) as f:
            for line in f:
                if "=" in line and not line.startswith("#"):
                    k, v = line.strip().split("=", 1)
                    env[k] = v.strip('"').strip("'")

    pk = env.get("LANGFUSE_PUBLIC_KEY")
    sk = env.get("LANGFUSE_SECRET_KEY")
    host = env.get("LANGFUSE_HOST", "http://127.0.0.1:3100")
    if not pk or not sk:
        print("[!] Langfuse keys missing. Skipping trace stream.")
        write_result("langfuse", "langfuse", "not_run", detail="no LANGFUSE_PUBLIC_KEY/LANGFUSE_SECRET_KEY in config/.langfuse.env")
        return
    import requests  # imported here so missing keys short-circuit without needing it

    target = os.getenv("TARGET_CONTRACT", "contracts/solidity/VulnerableVault.sol")
    target_name = target.split("/")[-1]

    verdict = _read_json("reports/verdict.json") or {}
    sast = _read_json("reports/sast-symbolic-report.json")
    swarm = _read_json("reports/swarm-execution-report.json") or {}
    avs = _read_json("reports/scanners/avs-consensus.json") or {}
    ofac = _read_json("reports/ofac-screening-report.json") or {}
    jira_ticket = None
    if os.path.isfile("reports/latest-jira-ticket.txt"):
        jira_ticket = open("reports/latest-jira-ticket.txt").read().strip()

    top = _top_finding(sast)
    dread = _IMPACT_SCORE.get((top.get("impact") or "").upper(), 0.0) if top else 0.0
    ofac_flag = next((r for r in ofac.get("screened", []) if r.get("flagged")), None)

    now = datetime.now(timezone.utc)
    trace_id = str(uuid.uuid4())
    user_id = "saleemali.mohammad@gmail.com"

    pipeline_verdict = verdict.get("verdict", "UNKNOWN")
    pipeline_health = verdict.get("health", "UNKNOWN")

    executive_summary = (
        f"Pipeline health {pipeline_health}, verdict {pipeline_verdict} for {target_name}. "
        + (f"Top finding: {top.get('check')} ({top.get('impact')})." if top else "No SAST findings.")
        + (f" AVS consensus: {avs.get('final_verdict', 'no result')} "
           f"({avs.get('counts', {}).get('exploit_confirmed', 0)}/{avs.get('counts', {}).get('nodes', 0)} nodes)."
           if avs else " No AVS consensus result this run.")
        + (f" OFAC: {ofac_flag.get('entity')} flagged." if ofac_flag else " No OFAC match this run.")
    )

    plain_english_verdict = {
        "status": pipeline_verdict,
        "pipeline_health": pipeline_health,
        "executive_summary": executive_summary,
        "halt_reasons": verdict.get("halt_reasons", []),
        "vulnerability_analysis": (
            {
                "category": (top.get("owasp_category") or "unknown") if top else "none",
                "check": top.get("check") if top else None,
                "description": top.get("description") if top else None,
            } if top else {"category": "none", "check": None, "description": "No SAST findings this run."}
        ),
    }

    batch = [
        {
            "id": str(uuid.uuid4()),
            "type": "trace-create",
            "timestamp": now.isoformat(),
            "body": {
                "id": trace_id,
                "name": "Autonomous-Blockchain-SOC-Production-Run",
                "userId": user_id,
                "input": {
                    "target_asset": target,
                    "suspected_vector": (top.get("owasp_category") if top else "none"),
                    "flagged_counterparty": ofac_flag.get("address") if ofac_flag else None,
                    "jira_ticket": jira_ticket,
                },
                "output": plain_english_verdict,
                "metadata": {
                    "avs_nodes_total": avs.get("counts", {}).get("nodes", 0),
                    "avs_exploit_confirmed": avs.get("counts", {}).get("exploit_confirmed", 0),
                    "dread_score": dread,
                },
                "tags": ["Production-SOC", "LangGraph-Swarm", pipeline_verdict],
            },
        }
    ]

    if avs:
        batch.append({
            "id": str(uuid.uuid4()),
            "type": "span-create",
            "timestamp": now.isoformat(),
            "body": {
                "id": str(uuid.uuid4()),
                "traceId": trace_id,
                "name": "Tool_Anvil_BFT_Sandbox_Execution",
                "startTime": now.isoformat(),
                "endTime": now.isoformat(),
                "input": {"ports": [8545, 8546, 8547]},
                "output": {
                    "final_verdict": avs.get("final_verdict"),
                    "consensus": f"{avs.get('counts', {}).get('exploit_confirmed', 0)}/{avs.get('counts', {}).get('nodes', 0)}",
                },
            },
        })

    # Real per-agent votes from this run's actual swarm execution. No
    # fabricated duration/token counts: this pipeline doesn't capture
    # per-agent timing or token usage anywhere, so none is claimed here --
    # all agent spans share this run's one real completion timestamp.
    for ag in swarm.get("agents", []):
        batch.append({
            "id": str(uuid.uuid4()),
            "type": "generation-create",
            "timestamp": now.isoformat(),
            "body": {
                "id": str(uuid.uuid4()),
                "traceId": trace_id,
                "name": ag.get("agent", "unknown-agent"),
                "startTime": now.isoformat(),
                "endTime": now.isoformat(),
                "model": ag.get("model"),
                "input": {"task": f"Analyze {target_name}"},
                "output": {"status": ag.get("status"), "vote": ag.get("vote"), "reason": ag.get("reason")},
            },
        })

    # Real scores only. "Guardrail_Determinism" from the old template is
    # dropped -- no NeMo Guardrail or equivalent integration exists anywhere
    # in this codebase, so there is no real signal to score.
    avs_total = avs.get("counts", {}).get("nodes", 0)
    scores = [
        {
            "name": "AVS_Exploit_Confidence",
            "value": (avs.get("counts", {}).get("exploit_confirmed", 0) / avs_total) if avs_total else 0.0,
            "comment": "Fraction of real AVS validator nodes that voted EXPLOIT_CONFIRMED this run",
        },
        {
            "name": "OFAC_Sanction_Taint",
            "value": 1.0 if ofac_flag else 0.0,
            "comment": f"{ofac_flag.get('entity')} flagged" if ofac_flag else "No real OFAC SDN match this run",
        },
        {
            "name": "Reentrancy_Severity_DREAD",
            "value": dread,
            "comment": f"Real DREAD score for top finding: {top.get('check')}" if top else "No SAST finding this run",
        },
    ]
    for sc in scores:
        batch.append({
            "id": str(uuid.uuid4()),
            "type": "score-create",
            "timestamp": now.isoformat(),
            "body": {
                "id": str(uuid.uuid4()),
                "traceId": trace_id,
                "name": sc["name"],
                "value": sc["value"],
                "comment": sc["comment"],
            },
        })

    try:
        r = requests.post(f"{host}/api/public/ingestion", auth=(pk, sk), json={"batch": batch}, timeout=10)
        if r.status_code in [200, 201, 207]:
            print(f"[+] Langfuse: streamed real trace ({trace_id[:8]}...). Verdict: {pipeline_verdict}")
            write_result("langfuse", "langfuse", "ok",
                         counts={"events_sent": len(batch)},
                         detail=f"trace {trace_id} ({pipeline_verdict})",
                         extra={"trace_id": trace_id})
        else:
            print(f"[!] Langfuse returned status {r.status_code}: {r.text}")
            write_result("langfuse", "langfuse", "error", detail=f"HTTP {r.status_code}: {r.text[:200]}")
    except Exception as err:
        print(f"[!] Langfuse stream error: {err}")
        write_result("langfuse", "langfuse", "error", detail=f"stream error: {str(err)[:200]}")


if __name__ == "__main__":
    stream_verification_trace()
