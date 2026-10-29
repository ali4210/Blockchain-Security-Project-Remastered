#!/usr/bin/env python3
"""Two separate answers, never merged:

  HEALTH  did every REQUIRED scanner really run?   (ok / not_run / error from reports/scanners/*.json)
  VERDICT is the target safe to ship?              (PASS / HALT / UNKNOWN: PASS only if health is OK)

Exit code: 0 health OK (verdict may be PASS or HALT) | 2 health FAILED.
GitOps is allowed only when health is OK and verdict is PASS
(ALLOW_GITOPS_ON_HALT=1 overrides for demo runs of the vulnerable contract).

Env:
  SOC_OPTIONAL            comma list of scanners that may be missing (default: none)
  SOC_MAX_HIGH            allowed HIGH+ findings for trivy/zap/npm-audit (default 0)
  ENFORCE_READINESS=1     a 'block' decision from the readiness gate becomes a HALT reason
  ALLOW_GITOPS_ON_HALT=1  allow GitOps even when verdict is HALT
"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import ROOT, load_all  # noqa: E402

REQUIRED = ["slither", "mythril", "sast-canary", "trivy", "zap",
            "sca", "openscap", "sonar", "readiness"]


def main():
    optional = {s.strip() for s in os.getenv("SOC_OPTIONAL", "").split(",") if s.strip()}
    max_high = int(os.getenv("SOC_MAX_HIGH", "0"))
    results = load_all()

    health_problems, rows = [], []
    for name in REQUIRED:
        r = results.get(name)
        if r is None:
            status, detail = "error", "no result recorded (step did not run)"
        else:
            status, detail = r.get("status", "error"), r.get("detail")
        req = name not in optional
        if status != "ok" and req:
            health_problems.append(f"{name}: {status}" + (f" ({detail})" if detail else ""))
        rows.append((name, status, "required" if req else "optional", detail or ""))

    reasons = []
    sast = ROOT / "reports" / "sast-symbolic-report.json"
    if results.get("slither", {}).get("status") == "ok" and sast.is_file():
        data = json.loads(sast.read_text(encoding="utf-8"))
        hi = [f for f in data.get("findings", []) if f.get("impact") in ("HIGH", "CRITICAL")]
        if hi:
            kinds = sorted({f.get("check") or "unknown" for f in hi})
            reasons.append(f"contract {data.get('target')}: {len(hi)} high/critical finding(s): {', '.join(kinds)}")

    def count(name, key):
        return int((results.get(name, {}).get("counts") or {}).get(key, 0))

    if results.get("trivy", {}).get("status") == "ok":
        n = count("trivy", "critical") + count("trivy", "high")
        if n > max_high:
            reasons.append(f"trivy: {n} HIGH/CRITICAL finding(s)")
    if results.get("zap", {}).get("status") == "ok" and count("zap", "high") > max_high:
        reasons.append(f"zap: {count('zap', 'high')} high-risk alert(s)")
    if results.get("sca", {}).get("status") == "ok":
        n = count("sca", "npmAuditHigh") + count("sca", "npmAuditCritical")
        if n > max_high:
            reasons.append(f"sca: {n} high/critical npm advisories")
    if results.get("sonar", {}).get("status") == "ok" and results["sonar"].get("gate") == "ERROR":
        reasons.append("sonarqube: quality gate ERROR")
    if os.getenv("ENFORCE_READINESS") == "1" and results.get("readiness", {}).get("decision") == "block":
        reasons.append(f"readiness gate: block ({results['readiness'].get('detail')})")
    # AVS consensus and the LangGraph swarm are real signals (live 3-node EVM
    # exploit execution; 7-agent LLM vote over real findings) but neither tool
    # is in REQUIRED: AVS needs a local Foundry toolchain and swarm needs a
    # reachable Ollama host, and pipeline HEALTH should not depend on that
    # infra being up. A confirmed exploit/halt from either can still force a
    # HALT verdict when it genuinely fires, independent of health.
    if results.get("avs-consensus", {}).get("status") == "ok" and results["avs-consensus"].get("supermajority_exploit"):
        reasons.append(f"avs-consensus: {results['avs-consensus'].get('final_verdict', 'EXPLOIT_PROVEN_HALT_DEPLOYMENT')} "
                       f"({results['avs-consensus'].get('counts', {}).get('exploit_confirmed', '?')}/"
                       f"{results['avs-consensus'].get('counts', {}).get('nodes', '?')} nodes)")
    if results.get("swarm", {}).get("status") == "ok" and results["swarm"].get("decision") == "HALT_CONFIRMED":
        reasons.append(f"swarm: HALT_CONFIRMED "
                       f"({results['swarm'].get('counts', {}).get('halt', '?')}/"
                       f"{results['swarm'].get('counts', {}).get('agents', '?')} agents)")

    # flashloan-detector / rugpull-detector (src/defi/): both are genuinely
    # TARGET_CONTRACT-specific (real solc AST per target, verified directly:
    # VulnerableVault.sol produces 1 flash-loan + 1 front-running finding and
    # 2 failing rug-pull checks; SecureVault.sol produces zero of either).
    # Any real non-zero finding count HALTs, same "status==ok + real content
    # condition" pattern as avs-consensus/swarm above.
    if results.get("flashloan-detector", {}).get("status") == "ok":
        n_flash = count("flashloan-detector", "flashloan_findings")
        n_front = count("flashloan-detector", "frontrunning_findings")
        if n_flash + n_front > 0:
            reasons.append(f"flashloan-detector: {n_flash} flash-loan-shape + "
                           f"{n_front} front-running finding(s)")
    if results.get("rugpull-detector", {}).get("status") == "ok":
        n = count("rugpull-detector", "failing_checks")
        if n > 0:
            reasons.append(f"rugpull-detector: {n} failing rug-pull check(s)")

    # chain_attack_monitor.py (consensus-attack) is DELIBERATELY NOT gated
    # here, even though it reports real CRITICAL-level findings on every
    # single run: verified directly against reports/scanners/consensus-
    # attack.json, its reorg/concentration/eclipse/selfish-mining checks are
    # a fixed, scripted single-node Anvil demo scenario (see that module's
    # own HONEST SCOPE NOTE) that never reads TARGET_CONTRACT at all -- it
    # fires identically (7/7 checks triggered, all CRITICAL/CRITICAL_ATTACK)
    # whether the target is VulnerableVault.sol or SecureVault.sol. Gating
    # on it would HALT every run unconditionally and tell a ship/no-ship
    # decision nothing about the actual contract under test -- this
    # exclusion is intentional, not an oversight.

    # Echidna (run-echidna.sh): gate ONLY on
    # echidna_internal_balance_never_exceeds_contract_eth, the one property
    # confirmed (by actually running Echidna against both harnesses) to
    # measure real solvency and pass on both targets today -- a genuine,
    # currently-dormant safety net, not a vacuous always-pass gate: if a
    # future contract's checked-math didn't mask an insolvency path, this
    # would catch it for real.
    # echidna_withdraw_never_reentered is deliberately EXCLUDED: verified by
    # actually running Echidna against SecureVaultEchidnaHarness.sol, it
    # fails there too (real counterexample: fuzzDeposit() -> fuzzAttack(1)),
    # because neither harness installs a reentrancy mutex -- SecureVault
    # only fixes the checks-effects-interactions ORDER. The property counts
    # whether withdraw() was ever recursed into at all, not whether that
    # recursion was exploitable, so it is structurally guaranteed to fail on
    # every target regardless of real safety and would make a vacuous
    # always-HALT gate.
    echidna_report_path = ROOT / "reports" / "echidna-report.json"
    if results.get("echidna", {}).get("status") == "ok" and echidna_report_path.is_file():
        echidna_data = json.loads(echidna_report_path.read_text(encoding="utf-8"))
        balance_prop = next((p for p in echidna_data.get("properties", [])
                             if p.get("name") == "echidna_internal_balance_never_exceeds_contract_eth"), None)
        if balance_prop is not None and not balance_prop.get("passed", True):
            reasons.append("echidna: echidna_internal_balance_never_exceeds_contract_eth FALSIFIED "
                           "(real fuzzer-found insolvency counterexample)")

    health = "OK" if not health_problems else "FAILED"
    # PASS may only be claimed when everything really ran; otherwise the safe answer is UNKNOWN.
    verdict = "HALT" if reasons else ("PASS" if health == "OK" else "UNKNOWN")
    gitops = health == "OK" and (verdict == "PASS" or os.getenv("ALLOW_GITOPS_ON_HALT") == "1")

    out = {"health": health, "verdict": verdict, "gitops_allowed": gitops,
           "health_problems": health_problems, "halt_reasons": reasons,
           "scanners": {n: {"status": s, "policy": p} for n, s, p, _ in rows},
           "target": os.getenv("TARGET_CONTRACT", "contracts/solidity/VulnerableVault.sol"),
           "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "verdict.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")

    print("\n[+] ================= PIPELINE VERDICT =================")
    for n, s, p, d in rows:
        print(f"    {({'ok': '[+]', 'not_run': '[!]', 'error': '[-]'}.get(s, '[?]'))} {n:<12} {s:<8} {p:<8} {d[:90]}")
    print(f"    HEALTH : {health}")
    for p in health_problems:
        print(f"      - {p}")
    print(f"    VERDICT: {verdict}")
    for r in reasons:
        print(f"      - {r}")
    print(f"    GITOPS : {'allowed' if gitops else 'BLOCKED'}")
    print("[+] ====================================================")
    sys.exit(0 if health == "OK" else 2)


if __name__ == "__main__":
    main()
