#!/usr/bin/env bash
# Section F (EduQual L6 Topic 124): real Echidna property-based fuzzing.
#
# Runs the ghcr.io/crytic/echidna/echidna docker image (same docker-heavy
# tooling pattern already used by this pipeline, e.g. run-sonar.sh) against
# the harness matching TARGET_CONTRACT/SECURE -- the SAME real target
# resolution run-all-e2e.sh itself uses (TARGET_CONTRACT, if already set,
# wins as-is; else SECURE=1 selects SecureVault.sol; else VulnerableVault.sol)
# -- and fuzzes two invariants:
#   echidna_internal_balance_never_exceeds_contract_eth  -- an insolvency check
#   echidna_withdraw_never_reentered                     -- direct reentrancy proof
# See VaultEchidnaHarness.sol's own comments for why the FIRST invariant
# genuinely passes on BOTH targets (solc 0.8 checked-math reverts the whole
# tx on underflow, same honest finding already documented in
# src/consensus/avs_consensus.py) while the SECOND genuinely fails on BOTH
# (neither harness has a reentrancy mutex, only CEI ordering differs --
# see pipeline-verdict.py's own comment on exactly why only the first one
# gates the verdict). Both outcomes are reported exactly as found, never
# forced either way.
#
# Purely additive/informational, like avs-consensus.py: NOT added to
# pipeline-verdict's REQUIRED list (a fuzz counterexample on the intentionally
# vulnerable default fixture is an expected, not a pipeline-breaking, result).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
RES() { python3 scripts/lib/scanner_result.py "$@"; }

echo "[+] [ZONE 2] Running Echidna property-based fuzzing..."

# Real target resolution, matching run-all-e2e.sh exactly: TARGET_CONTRACT
# (if already exported, e.g. by run-all-e2e.sh) wins as-is; else SECURE=1
# selects SecureVault.sol; else VulnerableVault.sol. Each harness wraps the
# real, unmodified contract of that exact name -- fuzzing the wrong harness
# for the selected target would make every downstream gating decision
# meaningless (it would silently report VulnerableVault's result while
# claiming to have scanned SecureVault, or vice versa).
if [ -n "${TARGET_CONTRACT:-}" ]; then
  : # explicit path given -- respect it as-is
elif [ "${SECURE:-0}" = "1" ]; then
  TARGET_CONTRACT="contracts/solidity/SecureVault.sol"
else
  TARGET_CONTRACT="contracts/solidity/VulnerableVault.sol"
fi
TARGET_NAME="$(basename "$TARGET_CONTRACT" .sol)"

case "$TARGET_NAME" in
  VulnerableVault)
    HARNESS_FILE="test/echidna/VaultEchidnaHarness.sol"
    HARNESS_CONTRACT="VaultEchidnaHarness"
    ;;
  SecureVault)
    HARNESS_FILE="test/echidna/SecureVaultEchidnaHarness.sol"
    HARNESS_CONTRACT="SecureVaultEchidnaHarness"
    ;;
  *)
    # No harness exists for this target (e.g. RandomTestVault.sol) -- honest
    # not_run, never a silent fall-back to fuzzing a different contract's
    # harness and reporting it as if it were this target's real result.
    RES echidna echidna not_run --target "$TARGET_CONTRACT" \
      --detail "no Echidna harness exists for $TARGET_CONTRACT (only VulnerableVault.sol and SecureVault.sol have one)"
    exit 0
    ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  RES echidna echidna not_run --target "$TARGET_CONTRACT" --detail "docker not available"
  exit 0
fi
if ! docker image inspect ghcr.io/crytic/echidna/echidna:latest >/dev/null 2>&1; then
  RES echidna echidna not_run --target "$TARGET_CONTRACT" --detail "ghcr.io/crytic/echidna/echidna:latest image not pulled"
  exit 0
fi

OUT=$(mktemp)
# --crytic-args "--solc-remaps ..." resolves node_modules-style imports (e.g.
# OpenZeppelin) the same real way Slither/Hardhat already do elsewhere in
# this pipeline -- harmless no-op for a harness with no such import.
# REAL BUG FOUND AND FIXED (Phase 4a, found live running the full pipeline
# after migrating SecureVault.sol to OpenZeppelin's Ownable): without this,
# echidna failed outright inside its own container with "Ownable.sol...
# not found", since /code is this repo mounted into the container but
# crytic-compile still needs an explicit remap to look in node_modules.
docker run --rm -v "$PWD:/code" -w /code ghcr.io/crytic/echidna/echidna:latest \
  bash -c "solc-select install 0.8.24 >/dev/null 2>&1 && solc-select use 0.8.24 >/dev/null 2>&1 && \
           echidna $HARNESS_FILE --contract $HARNESS_CONTRACT \
           --crytic-args '--solc-remaps @openzeppelin/=node_modules/@openzeppelin/' \
           --format text --test-limit 20000 --seq-len 20" > "$OUT" 2>&1

# --format json's stdout snapshot does not reliably reflect the FINAL
# per-property names/status (verified directly: it can still show the
# generic placeholder name "name" and status "shrinking" after the process
# has exited) -- --format text's final summary block (one real
# "echidna_<name>: passing|failed!" line per property, with its "Call
# sequence:" directly beneath on failure) is what was verified by hand to be
# reliably correct, so that is what gets parsed here.
cp "$OUT" reports/raw/echidna-text-output.txt 2>/dev/null || true

python3 - "$OUT" "$TARGET_CONTRACT" "$HARNESS_CONTRACT" <<'PYEOF'
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, "scripts/lib")
from scanner_result import ROOT, write_result

out_path, target_contract, harness_contract = sys.argv[1], sys.argv[2], sys.argv[3]
raw = Path(out_path).read_text(encoding="utf-8", errors="replace")
props = []
for m in re.finditer(
    r"^(echidna_\S+):\s+(passing|failed!.*)$((?:\n(?:  .*|    .*))*)",
    raw, re.M,
):
    name, verdict_line, extra = m.group(1), m.group(2), m.group(3)
    passed = verdict_line.startswith("passing")
    props.append({
        "name": name,
        "passed": passed,
        "detail": (verdict_line + extra).strip(),
    })

report_file = ROOT / "reports" / "echidna-report.json"
report_file.parent.mkdir(parents=True, exist_ok=True)
report_file.write_text(json.dumps({"target": target_contract, "harness_contract": harness_contract,
                                   "properties": props, "raw_text": raw}, indent=2) + "\n", encoding="utf-8")

if not props:
    write_result("echidna", "echidna", "error", target=target_contract,
                 detail=f"no property results found in output: {raw[-300:]}")
    sys.exit(0)

for p in props:
    print(f"    -> {p['name']}: {'passing' if p['passed'] else 'FAILED (real counterexample found)'}")

passing = [p for p in props if p["passed"]]
failing = [p for p in props if not p["passed"]]
detail = f"{len(passing)}/{len(props)} propert(y/ies) passing, harness={harness_contract}"
if failing:
    detail += f"; {len(failing)} genuinely falsified with a real counterexample (see reports/echidna-report.json)"
write_result("echidna", "echidna", "ok", target=target_contract,
             counts={"properties_total": len(props), "properties_passing": len(passing),
                     "properties_failing": len(failing)},
             raw_report=report_file, detail=detail,
             extra={"harness_contract": harness_contract})
PYEOF
rm -f "$OUT"
