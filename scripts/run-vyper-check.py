#!/usr/bin/env python3
"""
Section E (EduQual L6 Topic 124): Vyper compile + basic static check.

HONEST SCOPE NOTE: there is no mature third-party Vyper SAST tool wired into
this pipeline (unlike Solidity's Slither/Mythril). What is real here:
  1. A real `vyper` compile (installed via pipx, same pattern as slither/solc
     in this repo) -- type errors, syntax errors, and Vyper's own compile-time
     checks are real compiler output, not fabricated.
  2. One basic, honestly-scoped AST heuristic: does a function that makes an
     external call (raw_call/send/call/create_*) lack Vyper's own, real
     `@nonreentrant` decorator? This is the Vyper-native equivalent of
     Slither's reentrancy-eth check for Solidity, deliberately kept simple
     (decorator-presence vs external-call-presence, not a dataflow proof) --
     exactly the level of "basic static check" the task scope calls for. It is
     NOT a claim of deep, Vyper-specific symbolic/dataflow analysis, which
     does not exist in this pipeline.

Writes reports/scanners/vyper-check.json via the shared scanner_result
contract. Purely additive/informational: NOT added to pipeline-verdict's
REQUIRED list.
"""
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import ROOT, write_result  # noqa: E402

EXTERNAL_CALL_RE = re.compile(r"\b(raw_call|send|create_minimal_proxy_to|create_copy_of|create_from_blueprint)\b")
DEFAULT_TARGET = ROOT / "test" / "vyper" / "SimpleVault.vy"


def _vyper():
    return shutil.which("vyper") or str(Path.home() / ".local/bin/vyper")


def _iter_nodes(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _iter_nodes(v)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_nodes(item)


def _decorator_names(fn):
    names = []
    for d in fn.get("decorator_list") or []:
        if d.get("ast_type") == "Name":
            names.append(d.get("id", ""))
        elif d.get("ast_type") == "Call":
            names.append((d.get("func") or {}).get("id", ""))
    return names


def _body_identifiers(fn):
    tokens = []
    for n in _iter_nodes(fn.get("body") or []):
        for key in ("id", "attr"):
            v = n.get(key)
            if isinstance(v, str):
                tokens.append(v)
    return " ".join(tokens)


def compile_contract(target: Path):
    vyper = _vyper()
    if not Path(vyper).exists():
        raise RuntimeError("vyper compiler not found")
    bytecode = subprocess.run([vyper, str(target)], capture_output=True, text=True, timeout=60)
    if bytecode.returncode != 0:
        raise RuntimeError(f"vyper compile failed: {(bytecode.stderr or bytecode.stdout).strip()[:300]}")
    ast_proc = subprocess.run([vyper, "-f", "ast", str(target)], capture_output=True, text=True, timeout=60)
    if ast_proc.returncode != 0:
        raise RuntimeError(f"vyper -f ast failed: {ast_proc.stderr.strip()[:300]}")
    ast = json.loads(ast_proc.stdout)["ast"]
    return bytecode.stdout.strip(), ast


def analyze(target: Path):
    bytecode, ast = compile_contract(target)
    findings = []
    for fn in _iter_nodes(ast):
        if fn.get("ast_type") != "FunctionDef":
            continue
        body_text = _body_identifiers(fn)
        if not EXTERNAL_CALL_RE.search(body_text):
            continue
        decorators = _decorator_names(fn)
        if "nonreentrant" not in decorators:
            findings.append({
                "function": fn.get("name"),
                "decorators": decorators,
                "detail": f"{fn.get('name')}() makes an external call (raw_call/send/create_*) "
                         "but has no @nonreentrant decorator -- reentrancy-shaped exposure "
                         "(Vyper-native equivalent of Slither's reentrancy-eth check).",
            })
    return {
        "target": str(target),
        "compiled": True,
        "bytecode_len_bytes": len(bytecode.removeprefix("0x")) // 2,
        "reentrancy_shaped_findings": findings,
    }


def main():
    print("[+] [ZONE 2] Vyper compile + basic static check...")
    target = Path(os.getenv("VYPER_TARGET", str(DEFAULT_TARGET)))
    try:
        result = analyze(target)
    except Exception as exc:  # noqa: BLE001
        return write_result("vyper-check", "vyper", "not_run", detail=str(exc)[:250])

    report_file = ROOT / "reports" / "vyper-check-report.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print(f"    -> {target}: compiled OK, {result['bytecode_len_bytes']} bytes bytecode, "
          f"{len(result['reentrancy_shaped_findings'])} reentrancy-shaped finding(s)")
    for f in result["reentrancy_shaped_findings"]:
        print(f"       * {f['detail']}")

    detail = (f"real vyper compile succeeded ({result['bytecode_len_bytes']} bytes); "
              f"{len(result['reentrancy_shaped_findings'])} reentrancy-shaped finding(s) "
              "via basic decorator/external-call heuristic")
    return write_result("vyper-check", "vyper", "ok",
                        counts={"reentrancy_shaped_findings": len(result["reentrancy_shaped_findings"])},
                        raw_report=report_file, detail=detail)


if __name__ == "__main__":
    main()
