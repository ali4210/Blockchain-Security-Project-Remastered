#!/usr/bin/env python3
"""
Section C (EduQual L6 Topic 124): rug-pull risk-pattern detection.

Reuses flashloan_detector.py's real solc AST helpers (one solc --combined-json
ast call per target; see that module's HONEST SCOPE NOTE) rather than
duplicating AST plumbing.

Four checks, each returning pass / fail / not_applicable with a real
justification (never a guessed verdict when the relevant surface is simply
absent from the contract):

  unrestricted_mint              -- a mint-like function with no access
                                     control and no supply cap check
  missing_ownership_protection    -- privileged (owner-gated) functions exist,
                                     but the contract has neither a renounce-
                                     ownership path nor any timelock/delay
  missing_liquidity_lock          -- the contract deals in liquidity/LP
                                     tokens but has no lock/vesting mechanism
  owner_only_withdraw_all          -- a withdrawAll/sweep/drain/rescue-shaped
                                     function that empties the contract's
                                     entire balance to a caller-chosen address

HONEST SCOPE NOTE: these are keyword/shape heuristics over a real AST, not a
dataflow proof. "not_applicable" is reported, not a fabricated pass/fail, when
a contract has no mint/ownership-enforcement/liquidity surface at all -- e.g. a
contract that declares an `owner` variable but never actually checks it
anywhere is reported as not_applicable for missing_ownership_protection (there
is no enforced privilege to protect), not as a false "pass".

Writes reports/rugpull-findings.json. Purely additive/informational, like
avs-consensus.py and run-ofac-screening.py: NOT added to pipeline-verdict's
REQUIRED list.
"""
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "lib"))
from scanner_result import ROOT, write_result  # noqa: E402
from src.defi.flashloan_detector import get_ast, _iter_nodes, _collect_text, _function_defs, _param_names  # noqa: E402

MINT_NAME_RE = re.compile(r"^mint", re.I)
OWNER_MODIFIER_RE = re.compile(r"onlyowner|onlyadmin|restricted|onlygovernance", re.I)
OWNER_CHECK_RE = re.compile(r"owner", re.I)
CAP_RE = re.compile(r"cap|maxsupply|totalsupply", re.I)
RENOUNCE_RE = re.compile(r"renounceownership|renounce", re.I)
TIMELOCK_RE = re.compile(r"timelock|delay|scheduledat|executeafter|executionwindow", re.I)
LIQUIDITY_RE = re.compile(r"liquidity|\blp\b|addliquidity|removeliquidity", re.I)
LOCK_RE = re.compile(r"\block\b|vesting|unlocktime|locked_until", re.I)
WITHDRAW_ALL_NAME_RE = re.compile(r"withdrawall|emergency|rescue|sweep|drain", re.I)
# _collect_text joins individual AST name/memberName tokens (a bag of words,
# not literal source syntax), so this matches the word "balance" rather than
# the literal "address(this).balance" syntax a source-text regex would need.
FULL_BALANCE_RE = re.compile(r"\bbalance\b", re.I)


def _fn_modifier_names(fn):
    return [((m.get("modifierName") or {}).get("name", "")) for m in (fn.get("modifiers") or [])]


def _contract_text(ast):
    return _collect_text(ast)


def check_unrestricted_mint(ast, functions):
    mint_fns = [f for f in functions if MINT_NAME_RE.search(f.get("name", ""))
                and f.get("visibility") in ("external", "public")]
    if not mint_fns:
        return {"check": "unrestricted_mint", "result": "not_applicable",
                "justification": "no mint-like external/public function exists in this contract"}
    for fn in mint_fns:
        name = fn["name"]
        mods = _fn_modifier_names(fn)
        body_text = _collect_text(fn.get("body") or {})
        has_access_control = any(OWNER_MODIFIER_RE.search(m) for m in mods) or \
            ("require" in body_text.lower() and OWNER_CHECK_RE.search(body_text))
        has_cap = bool(CAP_RE.search(body_text))
        if not has_access_control:
            return {"check": "unrestricted_mint", "result": "fail",
                    "justification": f"{name}() is callable by any address with no access-control "
                                     f"modifier or owner check in its body" +
                                     ("" if has_cap else ", and enforces no supply cap")}
    return {"check": "unrestricted_mint", "result": "pass",
            "justification": f"mint function(s) found ({', '.join(f['name'] for f in mint_fns)}) "
                             "but all are access-controlled"}


def check_ownership_protection(functions, contract_text):
    privileged = []
    for fn in functions:
        mods = _fn_modifier_names(fn)
        body_text = _collect_text(fn.get("body") or {})
        if any(OWNER_MODIFIER_RE.search(m) for m in mods) or \
           ("require" in body_text.lower() and OWNER_CHECK_RE.search(body_text)):
            privileged.append(fn["name"])
    if not privileged:
        return {"check": "missing_ownership_protection", "result": "not_applicable",
                "justification": "no function in this contract actually enforces an owner/admin "
                                 "check (an unused 'owner' variable, if declared, is not an "
                                 "enforced privilege and has nothing to renounce or time-lock)"}
    has_renounce = bool(RENOUNCE_RE.search(contract_text))
    has_timelock = bool(TIMELOCK_RE.search(contract_text))
    if has_renounce or has_timelock:
        return {"check": "missing_ownership_protection", "result": "pass",
                "justification": f"privileged function(s) {privileged} exist, and the contract "
                                 f"has {'a renounce-ownership path' if has_renounce else ''}"
                                 f"{' and ' if has_renounce and has_timelock else ''}"
                                 f"{'a timelock/delay mechanism' if has_timelock else ''}"}
    return {"check": "missing_ownership_protection", "result": "fail",
            "justification": f"privileged function(s) {privileged} exist with no renounceOwnership "
                             "path and no timelock/delay mechanism anywhere in the contract"}


def check_liquidity_lock(contract_text):
    if not LIQUIDITY_RE.search(contract_text):
        return {"check": "missing_liquidity_lock", "result": "not_applicable",
                "justification": "this contract has no liquidity/LP-token surface at all"}
    if LOCK_RE.search(contract_text):
        return {"check": "missing_liquidity_lock", "result": "pass",
                "justification": "contract deals in liquidity and references a lock/vesting mechanism"}
    return {"check": "missing_liquidity_lock", "result": "fail",
            "justification": "contract deals in liquidity/LP tokens but has no lock, vesting, or "
                             "time-based unlock mechanism anywhere in the source"}


def check_owner_only_withdraw_all(functions):
    hits = []
    for fn in functions:
        name = fn.get("name", "")
        if not WITHDRAW_ALL_NAME_RE.search(name) or fn.get("visibility") not in ("external", "public"):
            continue
        body_text = _collect_text(fn.get("body") or {})
        if not FULL_BALANCE_RE.search(body_text):
            continue
        mods = _fn_modifier_names(fn)
        # bool(...) matters here: Python's `and`/`or` return the actual
        # operand, not a coerced bool, so without it `protected` can hold a
        # raw re.Match object (truthy, but not a clean bool) whenever the
        # second branch is what's true -- which then leaks its repr (e.g.
        # "<re.Match object; span=(11, 16), match='owner'>") into this
        # function's justification string below via the f-string. Harmless
        # for the `if`-only uses of this same pattern elsewhere in this file,
        # but this is the one place the value is actually stored and printed.
        protected = bool(any(OWNER_MODIFIER_RE.search(m) for m in mods) or
                         ("require" in body_text.lower() and OWNER_CHECK_RE.search(body_text)))
        hits.append({"function": name, "access_controlled": protected})
    if not hits:
        return {"check": "owner_only_withdraw_all", "result": "not_applicable",
                "justification": "no withdrawAll/emergency/rescue/sweep/drain-shaped function that "
                                 "empties the full contract balance was found"}
    unprotected = [h for h in hits if not h["access_controlled"]]
    detail = f"full-balance-drain function(s) found: {hits}"
    if unprotected:
        return {"check": "owner_only_withdraw_all", "result": "fail",
                "justification": detail + " -- at least one has NO access control at all, "
                                 "which is worse than an owner-restricted rug-pull vector: "
                                 "anyone can drain the contract"}
    return {"check": "owner_only_withdraw_all", "result": "fail",
            "justification": detail + " -- access-controlled, but a single-EOA-callable full-balance "
                             "withdraw is itself the classic rug-pull surface this check flags"}


def analyze_contract(target: Path):
    ast = get_ast(target)
    functions = list(_function_defs(ast))
    contract_text = _contract_text(ast)
    return [
        check_unrestricted_mint(ast, functions),
        check_ownership_protection(functions, contract_text),
        check_liquidity_lock(contract_text),
        check_owner_only_withdraw_all(functions),
    ]


def main():
    print("[+] [ZONE 2] Rug-pull risk-pattern detection...")
    target_env = os.getenv("TARGET_CONTRACT")
    targets = [Path(target_env)] if target_env else [Path("contracts/solidity/VulnerableVault.sol")]

    report = {"targets": []}
    total_fail = 0
    for target in targets:
        try:
            checks = analyze_contract(target)
        except Exception as exc:  # noqa: BLE001
            report["targets"].append({"target": str(target), "status": "error", "detail": str(exc)[:200]})
            continue
        fails = sum(1 for c in checks if c["result"] == "fail")
        total_fail += fails
        report["targets"].append({"target": str(target), "status": "ok", "checks": checks})
        print(f"    -> {target}: " + " | ".join(f"{c['check']}={c['result']}" for c in checks))

    report_file = ROOT / "reports" / "rugpull-findings.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    any_error = any(t["status"] == "error" for t in report["targets"])
    status = "error" if any_error else "ok"
    detail = f"{len(targets)} target(s) analysed via real solc AST, {total_fail} failing check(s)"
    return write_result("rugpull-detector", "rugpull-detector", status,
                        counts={"targets": len(targets), "failing_checks": total_fail},
                        raw_report=report_file, detail=detail)


if __name__ == "__main__":
    main()
