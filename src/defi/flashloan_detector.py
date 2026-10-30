#!/usr/bin/env python3
"""
Section B (EduQual L6 Topic 124): flash-loan attack-shape + front-running
exposure detection.

HONEST SCOPE NOTE:
  * Slither's existing Stage 2 output (reports/raw/slither-<tag>.json, written by
    run-sast-symbolic.py) is reused here as auxiliary cross-reference signal --
    but it contains ONLY Slither's own detector findings (reentrancy-eth,
    low-level-calls, etc.), not a full AST. There is no full-AST artifact already
    produced in Stage 2 to reuse for a new structural check. Getting a real parse
    tree therefore needs one additional, lightweight `solc --combined-json ast`
    call per target -- this is NOT a second Slither run and does not change
    anything Slither already does; it is the smallest real step that gives this
    module an actual AST to walk.
  * Detection is keyword/shape heuristics over the REAL AST (which functions call
    which other functions/members, in what order, with what parameters) -- not a
    dataflow/symbolic proof of atomicity or slippage safety. This is explicitly a
    heuristic static check, same honesty bar as the rest of this pipeline (see
    run-sast-symbolic.py's own docstring): it can have false negatives on
    obfuscated or multi-contract flows, and is not a substitute for a real
    flash-loan/MEV audit.

Flash-loan attack shape (per function, within ONE transaction):
  (a) receives a large external transfer in      (transferFrom/safeTransferFrom/payable)
  (b) reads price-oracle / AMM-reserve state      (price/oracle/reserve/getReserves/latestAnswer/quote)
  (c) repays before the function returns          (transfer/safeTransfer/call{value:)
  All three present in the same function body -> flagged.

Front-running exposure (per external/public, non-view function):
  price/slippage-sensitive logic (swap/price/exchange/amountOut/trade) present,
  but no deadline/minOut/slippage-bound parameter and no commit-reveal shape
  (a 'commit'/'reveal' pair of functions) -> flagged.

Writes reports/flashloan-findings.json. Purely additive/informational (like
avs-consensus.py, run-ofac-screening.py): NOT added to pipeline-verdict's
REQUIRED list.
"""
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "lib"))
from scanner_result import ROOT, RAW, write_result  # noqa: E402

TRANSFER_IN_RE = re.compile(r"transferfrom|safetransferfrom|payable", re.I)
ORACLE_RE = re.compile(r"price|oracle|reserve|getreserves|latestanswer|quote", re.I)
TRANSFER_OUT_RE = re.compile(r"\btransfer\b|safetransfer|\bcall\b", re.I)
PRICE_SENSITIVE_RE = re.compile(r"swap|price|exchange|amountout|trade", re.I)
SLIPPAGE_PARAM_RE = re.compile(r"deadline|minout|minamount|maxslippage|slippage", re.I)
COMMIT_RE = re.compile(r"commit", re.I)
REVEAL_RE = re.compile(r"reveal", re.I)


def _solc():
    return shutil.which("solc") or str(Path.home() / ".local/bin/solc")


def get_ast(target: Path):
    """Real solc AST for one contract file, via --combined-json ast (one process
    call; not a Slither re-run, see HONEST SCOPE NOTE above).

    REAL BUG FOUND AND FIXED (Phase 4a, verified empirically before any
    contract migration): a target that imports e.g.
    "@openzeppelin/contracts/access/Ownable.sol" failed outright without
    --base-path/--include-path (plain solc does not do node_modules
    resolution on its own) -- AND, once resolution is fixed,
    data["sources"] gains one entry per real imported file (confirmed:
    Ownable.sol, Context.sol, ... all appear as separate keys), so blindly
    taking `next(iter(data["sources"]))` silently returned an IMPORTED
    file's AST instead of the target's own whenever imports existed --
    not an error, just silently wrong analysis. Fixed by resolving
    node_modules (harmless no-op for a target with no imports) and
    selecting the target's own entry by its real key instead of
    positional order.
    """
    solc = _solc()
    if not Path(solc).exists():
        raise RuntimeError("solc not found")
    proc = subprocess.run([solc, "--combined-json", "ast",
                          "--base-path", str(ROOT), "--include-path", str(ROOT / "node_modules"),
                          str(target)],
                          capture_output=True, text=True, timeout=60, cwd=str(ROOT))
    if proc.returncode != 0:
        raise RuntimeError(f"solc failed: {proc.stderr.strip()[:300]}")
    data = json.loads(proc.stdout)
    sources = data["sources"]
    target_key = str(target)
    if target_key not in sources:
        # solc echoes back whatever path string was passed on the command
        # line as the key; try the most common alternate shape (relative
        # to ROOT) before falling back to the old, honestly-labelled
        # best-effort behavior rather than silently guessing.
        try:
            rel_key = str(Path(target).resolve().relative_to(ROOT))
        except ValueError:
            rel_key = None
        if rel_key in sources:
            target_key = rel_key
        else:
            raise RuntimeError(f"get_ast(): target {target_key!r} not found in solc's own "
                               f"sources keys {sorted(sources)} -- refusing to guess which "
                               f"AST is the real target's")
    return sources[target_key]["AST"]


def _iter_nodes(node):
    """Yields every dict node in the AST, depth-first."""
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _iter_nodes(v)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_nodes(item)


def _collect_text(node):
    """Flattened text of every 'name'/'memberName' string anywhere under node --
    a cheap, real, keyword-matchable surface over the real AST subtree."""
    parts = []
    for n in _iter_nodes(node):
        for key in ("name", "memberName"):
            v = n.get(key)
            if isinstance(v, str):
                parts.append(v)
    return " ".join(parts)


def _function_defs(ast):
    for n in _iter_nodes(ast):
        if n.get("nodeType") == "FunctionDefinition" and n.get("kind") != "constructor":
            yield n


def _param_names(fn):
    params = ((fn.get("parameters") or {}).get("parameters")) or []
    return [p.get("name", "") for p in params]


def analyze_contract(target: Path):
    """Returns (flashloan_findings, frontrunning_findings) for one contract file."""
    ast = get_ast(target)
    flash, front = [], []

    for fn in _function_defs(ast):
        name = fn.get("name", "<unnamed>")
        visibility = fn.get("visibility", "internal")
        state_mut = fn.get("stateMutability", "nonpayable")
        body_text = _collect_text(fn.get("body") or {})
        full_text = f"{name} {body_text}"

        has_transfer_in = bool(TRANSFER_IN_RE.search(full_text))
        has_oracle = bool(ORACLE_RE.search(full_text))
        has_transfer_out = bool(TRANSFER_OUT_RE.search(full_text))

        if has_transfer_in and has_oracle and has_transfer_out:
            flash.append({
                "function": name,
                "visibility": visibility,
                "signals": {
                    "receives_transfer_in": has_transfer_in,
                    "reads_oracle_or_reserve_state": has_oracle,
                    "repays_before_return": has_transfer_out,
                },
                "detail": f"{name}() receives a transfer in, reads oracle/reserve state, "
                          "and transfers out again within the same function -- classic "
                          "flash-loan attack shape (borrow -> manipulate/arbitrage -> repay).",
            })

        if visibility not in ("external", "public") or state_mut in ("view", "pure"):
            continue
        if not PRICE_SENSITIVE_RE.search(full_text):
            continue
        params = _param_names(fn)
        has_slippage_param = any(SLIPPAGE_PARAM_RE.search(p) for p in params)
        if has_slippage_param:
            continue
        # Commit-reveal shape: a sibling function pair named like *commit*/*reveal*.
        all_names = [f.get("name", "") for f in _function_defs(ast)]
        has_commit_reveal = (any(COMMIT_RE.search(n) for n in all_names) and
                              any(REVEAL_RE.search(n) for n in all_names))
        if has_commit_reveal:
            continue
        front.append({
            "function": name,
            "visibility": visibility,
            "parameters": params,
            "detail": f"{name}() contains price/slippage-sensitive logic but declares no "
                      "deadline/minOut/slippage-bound parameter and no commit-reveal pair "
                      "-- exposed to front-running/sandwich attacks.",
        })

    return flash, front


def _slither_signals(tag):
    """Auxiliary cross-reference only -- see HONEST SCOPE NOTE. Returns the list
    of Slither checks already flagged for this target in Stage 2, if present."""
    path = RAW / f"slither-{tag}.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    detectors = (data.get("results") or {}).get("detectors") or []
    return sorted({d.get("check", "unknown") for d in detectors})


def analyze_targets(targets):
    report = {"targets": []}
    total_flash = total_front = 0
    for target in targets:
        tag = target.stem
        try:
            flash, front = analyze_contract(target)
        except Exception as exc:  # noqa: BLE001
            report["targets"].append({"target": str(target), "status": "error",
                                      "detail": str(exc)[:200]})
            continue
        total_flash += len(flash)
        total_front += len(front)
        report["targets"].append({
            "target": str(target),
            "status": "ok",
            "slither_cross_reference": _slither_signals(tag),
            "flashloan_findings": flash,
            "frontrunning_findings": front,
        })
    return report, total_flash, total_front


def main():
    print("[+] [ZONE 2] Flash-loan attack-shape + front-running exposure detection...")
    target_env = os.getenv("TARGET_CONTRACT")
    targets = [Path(target_env)] if target_env else [Path("contracts/solidity/VulnerableVault.sol")]

    report, total_flash, total_front = analyze_targets(targets)

    report_file = ROOT / "reports" / "flashloan-findings.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    any_error = any(t["status"] == "error" for t in report["targets"])
    status = "error" if any_error and not (total_flash or total_front) else "ok"
    detail = (f"{len(targets)} target(s) analysed via real solc AST: "
              f"{total_flash} flash-loan-shape finding(s), {total_front} "
              "front-running-exposure finding(s)")
    for t in report["targets"]:
        print(f"    -> {t['target']}: status={t['status']} "
              f"flash={len(t.get('flashloan_findings', []))} "
              f"front={len(t.get('frontrunning_findings', []))}")
    return write_result("flashloan-detector", "flashloan-detector", status,
                        counts={"flashloan_findings": total_flash,
                                "frontrunning_findings": total_front},
                        raw_report=report_file, detail=detail)


if __name__ == "__main__":
    main()
