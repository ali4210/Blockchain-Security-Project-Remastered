#!/usr/bin/env python3
"""Phase 4c: real ML triage/prioritization scanner step -- NOT an independent
vulnerability classifier, NOT a GNN (see src/ml/feature_extraction.py's
module docstring for exactly why). Scores
TARGET_CONTRACT with the model trained by scripts/train-triage-classifier.py
(scikit-learn, 143 real SmartBugs-curated contracts, real Slither findings +
real solc-AST structural features) and layers the result on top of this
run's own Slither output.

Purely additive/informational, like avs-consensus.py / run-ofac-screening.py:
NOT added to pipeline-verdict's REQUIRED list, and runs AFTER
run-sast-symbolic.py so this run's real reports/raw/slither-<tag>.json
already exists for TARGET_CONTRACT.

Honest status via scanner_result:
  not_run  model/sidecar missing or mismatched, training data stale, or
           this run's own Slither didn't produce an ok result to layer on
  error    scoring raised unexpectedly
  ok       a real score was produced against a present, verified model
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import RAW, ROOT, load_all, write_result  # noqa: E402
from src.ml.feature_extraction import get_ast_for_version  # noqa: E402
from src.ml.triage_classifier import TriageClassifier, TriageModelUnavailable  # noqa: E402

SOLC_VERSION = os.getenv("SOLC_VERSION", "0.8.24")
DEFAULT_TARGET = "contracts/solidity/VulnerableVault.sol"


def main():
    print("[+] [ZONE 2] ML triage/prioritization scoring (Phase 4c)...")
    target_path = Path(os.getenv("TARGET_CONTRACT", DEFAULT_TARGET))
    target_path = target_path if target_path.is_absolute() else ROOT / target_path
    if not target_path.is_file():
        return write_result("triage-classifier", "triage-classifier", "error",
                            detail=f"target not found: {target_path}")

    scanners = load_all()
    slither_result = scanners.get("slither", {})
    if slither_result.get("status") != "ok":
        return write_result("triage-classifier", "triage-classifier", "not_run",
                            detail="this run's own Slither result is not ok -- refusing to layer "
                                   "a triage score on top of a Slither run that didn't really "
                                   f"succeed (status={slither_result.get('status', 'missing')})")

    tag = target_path.stem
    slither_raw_path = RAW / f"slither-{tag}.json"
    slither_json = None
    if slither_raw_path.is_file():
        try:
            slither_json = json.loads(slither_raw_path.read_text(encoding="utf-8"))
        except ValueError:
            slither_json = None

    mythril_status = scanners.get("mythril", {}).get("status", "missing")

    try:
        clf = TriageClassifier()
    except TriageModelUnavailable as exc:
        return write_result("triage-classifier", "triage-classifier", "not_run", detail=str(exc)[:300])

    try:
        ast = get_ast_for_version(target_path, SOLC_VERSION, ROOT)
        prediction = clf.predict(slither_json, ast, target_path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:  # noqa: BLE001
        return write_result("triage-classifier", "triage-classifier", "error", detail=str(exc)[:300])

    report = {
        "target": str(target_path.relative_to(ROOT)),
        "predicted_category": prediction.predicted_category,
        "class_probabilities": prediction.class_probabilities,
        "caveat": prediction.caveat,
        "cv_accuracy": prediction.cv_accuracy,
        "cv_macro_f1": prediction.cv_macro_f1,
        "cv_accuracy_95pct_ci": prediction.cv_accuracy_ci,
        "n_training_samples": prediction.n_training_samples,
        "mythril_this_run": mythril_status,
        "mythril_note": ("Mythril is NOT part of this model's training or scoring -- see "
                         "src/ml/feature_extraction.py. This field only records whether Mythril "
                         "itself ran ok this cycle, for human context."),
    }
    report_file = ROOT / "reports" / "triage-classifier-report.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    top3 = sorted(prediction.class_probabilities.items(), key=lambda kv: -kv[1])[:3]
    print(f"    -> {report['target']}: predicted={prediction.predicted_category} "
          f"top3={top3} (n={prediction.n_training_samples}, "
          f"CV accuracy={prediction.cv_accuracy:.3f})")
    print(f"    -> {prediction.caveat}")

    detail = (f"predicted_category={prediction.predicted_category} against real n="
              f"{prediction.n_training_samples} LOOCV model "
              f"(accuracy={prediction.cv_accuracy:.3f}, macro-F1={prediction.cv_macro_f1:.3f}) -- "
              f"triage hint only, not an independent classifier")
    return write_result("triage-classifier", "triage-classifier", "ok",
                        target=report["target"], raw_report=report_file, detail=detail,
                        extra={"predicted_category": prediction.predicted_category,
                               "cv_accuracy": prediction.cv_accuracy,
                               "cv_macro_f1": prediction.cv_macro_f1})


if __name__ == "__main__":
    main()
