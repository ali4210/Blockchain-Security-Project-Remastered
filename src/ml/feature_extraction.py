"""Tabular feature extraction for the Phase 4c triage classifier.

HONEST SCOPE: a real GNN trained on AST-derived graphs was considered and
rejected for this project -- the only human-labeled smart-contract
vulnerability dataset found (SmartBugs curated) has just 143 contracts,
far too few to train a graph model that generalizes. The larger
slither-audited-smart-contracts dataset (467k rows) was also rejected: its
labels come from Slither itself, not humans, so training on it would just
be a circular, expensive re-derivation of a tool already live in this
pipeline. This module instead extracts plain NUMERIC/tabular features a
human could also read straight off the tools' own output:

  * REAL Slither finding counts (reports/raw/slither-<tag>.json, the exact
    JSON run-sast-symbolic.py already produces for the live target) --
    by severity, plus total/unique-check counts.
  * REAL structural metrics computed directly from solc's own AST
    (`solc --combined-json ast`, same mechanism as
    src/defi/flashloan_detector.py's get_ast(), reused here) -- function
    counts, external-call counts, modifier counts, state-variable counts,
    and a cyclomatic-complexity approximation (branch nodes + 1, summed
    across all functions). No learned embedding, no graph representation.

Mythril is deliberately NOT a feature here. It was evaluated for Phase 4c
and excluded from training: `myth` is not installed natively on this host,
and running real symbolic execution against all 143 SmartBugs-curated
training contracts via the local `mythril/myth` docker image (confirmed
present) would run for hours even at a reduced per-contract timeout --
disproportionate to this explicitly "light" triage step. Keeping Mythril
out of the trained feature set also keeps train/inference parity honest:
the live pipeline's mythril result for TARGET_CONTRACT is recorded
separately in the triage report for a human to read, but it is never fed
into this model's score.

FEATURE_SCHEMA_VERSION bumps whenever FEATURE_NAMES changes shape or order.
A trained model's sidecar records the schema version and a feature-name
hash it was trained against; the runtime scorer refuses to use a model
whose sidecar schema doesn't match this module's current schema (see
src/ml/triage_classifier.py) -- a silent column-order mismatch would
produce a confident-looking but meaningless prediction, which this project's
honesty model treats as worse than refusing to score at all.
"""
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

FEATURE_SCHEMA_VERSION = 1

FEATURE_NAMES: List[str] = [
    # Slither-derived (counts over reports/raw/slither-<tag>.json's own
    # detector list -- the exact severities Slither itself assigns)
    "slither_total_findings",
    "slither_high",
    "slither_medium",
    "slither_low",
    "slither_informational",
    "slither_unique_checks",
    # Structural, computed directly from solc's AST
    "function_count",
    "external_function_count",
    "payable_function_count",
    "modifier_def_count",
    "modifier_use_count",
    "state_var_count",
    "external_call_count",
    "total_function_calls",
    "cyclomatic_complexity",
    "source_lines",
]


def schema_hash() -> str:
    """Hash of the ordered feature-name list -- changes the instant a column
    is added, removed, or reordered, so a stale model can never silently
    score against the wrong columns."""
    return hashlib.sha256(json.dumps(FEATURE_NAMES).encode()).hexdigest()


BRANCH_NODE_TYPES = {
    "IfStatement", "WhileStatement", "DoWhileStatement", "ForStatement",
    "Conditional",
}
EXTERNAL_CALL_MEMBERS = {"call", "delegatecall", "staticcall", "send", "transfer"}


def _iter_nodes(node: Any):
    """Yields every dict node in a solc AST subtree, depth-first (same
    traversal as src/defi/flashloan_detector.py's own helper)."""
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _iter_nodes(v)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_nodes(item)


def _supports_base_path(solc_version: str) -> bool:
    """--base-path/--include-path (needed to resolve node_modules-style
    imports like @openzeppelin/...) don't exist at all on pre-0.6 solc --
    confirmed empirically: `solc-0.4.9 --help` and `solc-0.5.0 --help` have
    no such flags, while `solc-0.8.24 --help` does. SmartBugs-curated's own
    143 training contracts are all 0.4.x/0.5.0 and self-contained (no
    imports), so this never needs the flags; a live TARGET_CONTRACT that
    imports OpenZeppelin (e.g. SecureVault.sol) is always scored against a
    modern solc (0.8.x by default) that does support them. Gating on the
    real version avoids crashing the >=1 legacy case that could otherwise
    hit this function with an unrecognized-flag error."""
    try:
        major, minor = (int(p) for p in solc_version.split(".")[:2])
    except ValueError:
        return False
    return (major, minor) >= (0, 6)


def get_ast_for_version(target: Path, solc_version: str, root: Path) -> dict:
    """Real solc AST for one contract file, using the solc-select artifact
    binary pinned to solc_version directly -- NOT the global `solc` shim,
    so this never mutates the host's global solc-select version (the
    SmartBugs-curated training set spans 16 distinct 0.4.x/0.5.0 pragmas;
    switching the global version per-call would be a real, if reversible,
    side effect on a shared tool every other pipeline step also uses).

    Resolves node_modules-style imports (e.g. @openzeppelin/contracts/...)
    the same way run-sast-symbolic.py's slither_scan() and
    src/defi/flashloan_detector.py's own get_ast() already do -- confirmed
    broken without this: SecureVault.sol's real `import
    "@openzeppelin/contracts/access/Ownable.sol"` failed AST extraction
    outright before this fix (live-verified 2026-10-30)."""
    solc_bin = Path.home() / ".solc-select" / "artifacts" / f"solc-{solc_version}" / f"solc-{solc_version}"
    if not solc_bin.is_file():
        raise RuntimeError(f"solc {solc_version} not installed via solc-select at {solc_bin}")
    cmd = [str(solc_bin), "--combined-json", "ast"]
    if _supports_base_path(solc_version):
        cmd += ["--base-path", str(root), "--include-path", str(root / "node_modules")]
    cmd.append(str(target))
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=60, cwd=str(root),
    )
    if proc.returncode != 0:
        raise RuntimeError(f"solc {solc_version} failed: {proc.stderr.strip()[:300]}")
    data = json.loads(proc.stdout)
    sources = data["sources"]
    target_key = str(target)
    if target_key not in sources:
        try:
            rel_key = str(Path(target).resolve().relative_to(root))
        except ValueError:
            rel_key = None
        if rel_key in sources:
            target_key = rel_key
        else:
            # Older solc (0.4.x) sometimes echoes back a bare filename.
            matches = [k for k in sources if k.endswith(Path(target).name)]
            if len(matches) == 1:
                target_key = matches[0]
            else:
                raise RuntimeError(
                    f"get_ast_for_version(): target {target_key!r} not found in solc's own "
                    f"sources keys {sorted(sources)} -- refusing to guess which AST is the real target's"
                )
    return sources[target_key]["AST"]


def _node_type(n: dict) -> Optional[str]:
    return n.get("nodeType") or n.get("name")


def _attrs(n: dict) -> dict:
    """Modern solc AST (0.5+) puts a node's own properties directly on the
    node; legacy solc (0.4.x, used by all of SmartBugs curated's training
    contracts) nests them under an 'attributes' dict instead. Verified
    empirically against real solc 0.4.9-0.4.25 and 0.8.24 output -- see
    src/ml/feature_extraction.py's module docstring / Phase 4c notes."""
    a = n.get("attributes")
    return a if isinstance(a, dict) else n


def _callee_expr(fc_node: dict) -> dict:
    """The expression being called in a FunctionCall node. Modern AST has
    an explicit 'expression' key; legacy AST has no such key and the
    callee is simply children[0] (verified empirically)."""
    if "expression" in fc_node:
        expr = fc_node.get("expression") or {}
    else:
        children = fc_node.get("children") or []
        expr = children[0] if children else {}
    # `x.call{value: v}(...)` wraps the real MemberAccess one level deeper
    # inside a FunctionCallOptions node (verified against VulnerableVault.sol's
    # own flashSwap()/emergencySweep() reentrancy call) -- unwrap it so
    # `.call`/`.delegatecall` are still counted as external calls.
    if _node_type(expr) == "FunctionCallOptions":
        expr = expr.get("expression") or {}
    return expr


def _member_name(member_access_node: dict) -> Optional[str]:
    return member_access_node.get("memberName") or _attrs(member_access_node).get("member_name")


def _direct_members(contract_node: dict) -> list:
    """A ContractDefinition's immediate members: modern AST lists them under
    'nodes', legacy AST under 'children' (verified against real solc 0.4.9
    and 0.8.24 output -- 0.4.9's VariableDeclaration attributes don't even
    carry a 'stateVariable' key, so that flag can't be trusted; being a
    DIRECT child of ContractDefinition is the one structural signal that
    holds across every version checked)."""
    return contract_node.get("nodes") or contract_node.get("children") or []


def _count_state_vars(ast: dict) -> int:
    count = 0
    for n in _iter_nodes(ast):
        if isinstance(n, dict) and _node_type(n) == "ContractDefinition":
            for child in _direct_members(n):
                if isinstance(child, dict) and _node_type(child) == "VariableDeclaration":
                    count += 1
    return count


def structural_features_from_ast(ast: dict, source_text: str) -> Dict[str, float]:
    """Plain counts over the real AST -- every one of these a human could
    verify by reading the contract; nothing here is a learned feature."""
    function_count = 0
    external_function_count = 0
    payable_function_count = 0
    modifier_def_count = 0
    modifier_use_count = 0
    external_call_count = 0
    total_function_calls = 0
    cyclomatic_complexity = 0

    for n in _iter_nodes(ast):
        if not isinstance(n, dict):
            continue
        node_type = _node_type(n)
        if node_type == "FunctionDefinition":
            function_count += 1
            a = _attrs(n)
            if a.get("visibility") in ("external", "public"):
                external_function_count += 1
            if a.get("payable") is True or a.get("stateMutability") == "payable":
                payable_function_count += 1
        elif node_type == "ModifierDefinition":
            modifier_def_count += 1
        elif node_type == "ModifierInvocation":
            modifier_use_count += 1
        elif node_type == "FunctionCall":
            total_function_calls += 1
            expr = _callee_expr(n)
            if _node_type(expr) == "MemberAccess" and _member_name(expr) in EXTERNAL_CALL_MEMBERS:
                external_call_count += 1
        elif node_type in BRANCH_NODE_TYPES:
            cyclomatic_complexity += 1

    cyclomatic_complexity += max(function_count, 1)  # +1 per function, floor 1
    return {
        "function_count": float(function_count),
        "external_function_count": float(external_function_count),
        "payable_function_count": float(payable_function_count),
        "modifier_def_count": float(modifier_def_count),
        "modifier_use_count": float(modifier_use_count),
        "state_var_count": float(_count_state_vars(ast)),
        "external_call_count": float(external_call_count),
        "total_function_calls": float(total_function_calls),
        "cyclomatic_complexity": float(cyclomatic_complexity),
        "source_lines": float(source_text.count("\n") + 1),
    }


def slither_features_from_report(slither_json: Optional[dict]) -> Dict[str, float]:
    """Counts over Slither's own --json output (results.detectors[]).
    slither_json=None (tool not_run/error) -> an explicit all-zero vector,
    never a guessed/interpolated value."""
    if not slither_json:
        return {k: 0.0 for k in (
            "slither_total_findings", "slither_high", "slither_medium",
            "slither_low", "slither_informational", "slither_unique_checks",
        )}
    detectors = (slither_json.get("results") or {}).get("detectors", [])
    by_impact = {"high": 0, "medium": 0, "low": 0, "informational": 0}
    checks = set()
    for d in detectors:
        impact = str(d.get("impact", "")).lower()
        if impact in by_impact:
            by_impact[impact] += 1
        checks.add(d.get("check", "unknown"))
    return {
        "slither_total_findings": float(len(detectors)),
        "slither_high": float(by_impact["high"]),
        "slither_medium": float(by_impact["medium"]),
        "slither_low": float(by_impact["low"]),
        "slither_informational": float(by_impact["informational"]),
        "slither_unique_checks": float(len(checks)),
    }


def feature_vector(struct_feats: Dict[str, float], slither_feats: Dict[str, float]) -> List[float]:
    """Combine into the FEATURE_NAMES-ordered vector -- order matters, this
    is what guarantees train/inference column alignment."""
    merged = {**slither_feats, **struct_feats}
    return [merged[name] for name in FEATURE_NAMES]
