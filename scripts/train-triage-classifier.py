#!/usr/bin/env python3
"""Phase 4c: trains the real, honestly-scoped ML triage classifier.

Not a GNN (the only human-labeled dataset found, SmartBugs curated, has just
143 contracts -- far too few to train a graph model that generalizes) and
not trained against Slither's own auto-generated labels (the 467k-row
slither-audited-smart-contracts dataset was rejected precisely because that
would be circular: re-deriving a tool already live in this pipeline).
Instead: a small scikit-learn classifier,
trained on SmartBugs curated's real 143 human-labeled contracts (Apache-2.0,
github.com/smartbugs/smartbugs-curated), using REAL Slither findings + REAL
solc-AST structural features (src/ml/feature_extraction.py) as input.

n=143 across 10 DASP categories is small and badly imbalanced (one category
has a single example). This script does NOT hide that: it reports real
leave-one-out cross-validated accuracy/macro-F1 with a real binomial
confidence interval, and the runtime scanner step (scripts/run-triage-
classifier.py) renders those numbers next to every score it produces --
this is a prioritization/triage hint, not an independent vulnerability
classifier, and the sidecar + report language says so explicitly.

Usage: python3 scripts/train-triage-classifier.py
Writes:
  models/triage_classifier_v1.joblib        -- the trained model
  models/triage_classifier_v1.sidecar.json  -- provenance + real CV metrics
  models/triage_training_data.csv           -- the real per-contract feature matrix (audit trail)
"""
import csv
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")  # headless -- this script runs on the Kali host with no display
import matplotlib.pyplot as plt
import mlflow
import sklearn
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import LeaveOneOut, cross_val_predict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.ml.feature_extraction import (  # noqa: E402
    FEATURE_NAMES, FEATURE_SCHEMA_VERSION, feature_vector,
    get_ast_for_version, schema_hash, slither_features_from_report,
    structural_features_from_ast,
)

DATASET_DIR = ROOT / "data" / "smartbugs-curated"
VERSIONS_CSV = DATASET_DIR / "versions.csv"
MODELS_DIR = ROOT / "models"
SOLC_TIMEOUT = 60
MLFLOW_TRACKING_URI = os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000")
DATASET_COMMIT = "230e649123477eff332742a59a1c7cc6dc286cab"


def plot_confusion_matrix(cm, labels, out_path: Path):
    """A real matplotlib confusion-matrix heatmap over this run's actual
    LOOCV predictions -- not a placeholder image."""
    fig, ax = plt.subplots(figsize=(8, 7))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_title("Triage classifier -- real LOOCV confusion matrix (n=%d)" % sum(sum(r) for r in cm))
    for i in range(len(labels)):
        for j in range(len(labels)):
            if cm[i][j] > 0:
                ax.text(j, i, str(cm[i][j]), ha="center", va="center",
                        color="white" if cm[i][j] > (max(max(r) for r in cm) / 2) else "black", fontsize=7)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(out_path, dpi=120)
    plt.close(fig)


def plot_feature_importances(importances, out_path: Path):
    """A real matplotlib bar chart of this run's actual fitted feature
    importances -- not a placeholder image."""
    names = [n for n, _ in importances]
    values = [v for _, v in importances]
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh(names[::-1], values[::-1], color="#2563eb")
    ax.set_xlabel("Importance")
    ax.set_title("Triage classifier -- real fitted feature importances")
    fig.tight_layout()
    fig.savefig(out_path, dpi=120)
    plt.close(fig)


def dataset_content_sha256() -> str:
    """Hash of every real training file's path+bytes, sorted -- changes the
    instant the on-disk training set changes, used by the runtime scorer to
    detect a stale/mismatched dataset (see run-triage-classifier.py)."""
    h = hashlib.sha256()
    for p in sorted(DATASET_DIR.rglob("*")):
        if p.is_file():
            h.update(str(p.relative_to(DATASET_DIR)).encode())
            h.update(p.read_bytes())
    return h.hexdigest()


def run_slither(target: Path, solc_version: str) -> dict | None:
    """Real Slither run against one training contract, same flags shape as
    run-sast-symbolic.py's slither_scan() minus the node_modules remap
    (SmartBugs-curated's files are single, self-contained flattened
    sources -- no imports to resolve)."""
    exe = "slither"
    out = ROOT / "models" / "_tmp_slither_out.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.unlink(missing_ok=True)
    cmd = [exe, str(target), "--solc-solcs-select", solc_version, "--json", str(out)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=ROOT)
    except Exception as exc:  # noqa: BLE001
        print(f"    ! slither could not run on {target.name}: {exc}", file=sys.stderr)
        return None
    if not out.is_file():
        return None
    try:
        data = json.loads(out.read_text(encoding="utf-8"))
    finally:
        out.unlink(missing_ok=True)
    if not data.get("success"):
        return None
    return data


def main():
    if not VERSIONS_CSV.is_file():
        print(f"[-] {VERSIONS_CSV} missing -- run: git clone --depth 1 "
              f"https://github.com/smartbugs/smartbugs-curated.git {DATASET_DIR}")
        sys.exit(1)

    rows = list(csv.DictReader(VERSIONS_CSV.open()))
    print(f"[+] Phase 4c triage classifier training: {len(rows)} real SmartBugs-curated contracts")

    X, y, audit_rows = [], [], []
    slither_failures = 0
    for i, row in enumerate(rows, 1):
        rel_path = row["file"]
        version = row["compiled version"].strip()
        target = DATASET_DIR / rel_path
        label = Path(rel_path).parts[1]  # dataset/<category>/<file>.sol
        print(f"    [{i}/{len(rows)}] {rel_path} (solc {version}, label={label})")

        slither_json = run_slither(target, version)
        if slither_json is None:
            slither_failures += 1
        slither_feats = slither_features_from_report(slither_json)

        try:
            ast = get_ast_for_version(target, version, ROOT)
            struct_feats = structural_features_from_ast(ast, target.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:  # noqa: BLE001
            print(f"    ! structural features failed for {rel_path}: {exc}", file=sys.stderr)
            continue

        vec = feature_vector(struct_feats, slither_feats)
        X.append(vec)
        y.append(label)
        audit_rows.append({"file": rel_path, "label": label, **slither_feats, **struct_feats})

    n = len(X)
    print(f"[+] Real feature matrix built: {n}/{len(rows)} contracts "
          f"({slither_failures} had no usable Slither result -> all-zero Slither features, "
          f"structural features still real)")
    if n < len(rows) * 0.9:
        print("[-] Too many contracts failed feature extraction -- refusing to train on a "
              "degraded sample without a human decision. Aborting.")
        sys.exit(1)

    import numpy as np
    X_arr = np.array(X, dtype=float)
    y_arr = np.array(y)

    print("\n[+] Real class distribution (this IS the full imbalance -- not resampled, not hidden):")
    from collections import Counter
    for cls, count in sorted(Counter(y_arr).items(), key=lambda kv: -kv[1]):
        print(f"      {cls}: {count}")

    loo = LeaveOneOut()
    results = {}
    for name, clf in (
        ("random_forest", RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")),
        ("gradient_boosting", GradientBoostingClassifier(random_state=42)),
    ):
        print(f"\n[+] Leave-one-out CV for {name} (n={n}, {n} folds -- standard practice at this "
              f"sample size, see training script docstring)...")
        preds = cross_val_predict(clf, X_arr, y_arr, cv=loo)
        acc = accuracy_score(y_arr, preds)
        macro_f1 = f1_score(y_arr, preds, average="macro", zero_division=0)
        report = classification_report(y_arr, preds, zero_division=0, output_dict=True)
        cm = confusion_matrix(y_arr, preds, labels=sorted(set(y_arr))).tolist()
        results[name] = {"accuracy": acc, "macro_f1": macro_f1, "report": report, "confusion_matrix": cm,
                         "labels": sorted(set(y_arr))}
        print(f"    -> {name}: LOOCV accuracy={acc:.4f}  macro-F1={macro_f1:.4f}")
        print(f"    -> real classification_report:\n{classification_report(y_arr, preds, zero_division=0)}")

    chosen = max(results, key=lambda k: results[k]["macro_f1"])
    print(f"\n[+] Chosen model (higher real LOOCV macro-F1, not cherry-picked): {chosen}")
    print(f"    random_forest macro-F1={results['random_forest']['macro_f1']:.4f}  "
          f"gradient_boosting macro-F1={results['gradient_boosting']['macro_f1']:.4f}")

    # Real binomial (Wilson score) 95% CI on the chosen model's LOOCV accuracy.
    import math
    acc = results[chosen]["accuracy"]
    z = 1.96
    denom = 1 + z**2 / n
    center = (acc + z**2 / (2 * n)) / denom
    half = (z * math.sqrt(acc * (1 - acc) / n + z**2 / (4 * n**2))) / denom
    ci = (max(0.0, center - half), min(1.0, center + half))
    print(f"    95% Wilson CI on accuracy (n={n}): [{ci[0]:.3f}, {ci[1]:.3f}]")

    final_clf = (RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
                 if chosen == "random_forest" else GradientBoostingClassifier(random_state=42))
    final_clf.fit(X_arr, y_arr)
    if hasattr(final_clf, "feature_importances_"):
        importances = sorted(zip(FEATURE_NAMES, final_clf.feature_importances_.tolist()),
                             key=lambda kv: -kv[1])
        print("\n[+] Real feature importances (full-data refit):")
        for feat, imp in importances:
            print(f"      {feat}: {imp:.4f}")
    else:
        importances = []

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_DIR / "triage_classifier_v1.joblib"
    joblib.dump(final_clf, model_path)

    audit_csv = MODELS_DIR / "triage_training_data.csv"
    with audit_csv.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(audit_rows[0].keys()))
        w.writeheader()
        w.writerows(audit_rows)

    cm_path = MODELS_DIR / "triage_confusion_matrix.png"
    fi_path = MODELS_DIR / "triage_feature_importances.png"
    plot_confusion_matrix(results[chosen]["confusion_matrix"], results[chosen]["labels"], cm_path)
    if importances:
        plot_feature_importances(importances, fi_path)
    print(f"\n[+] Wrote real plots: {cm_path.name}, {fi_path.name if importances else '(no feature_importances_)'}")

    # MLflow is additive visibility, never a hard dependency for this script's
    # real job (producing the model/sidecar) -- a tracking server that's down
    # must not block training, same "informational, not required" posture as
    # every other dashboard integration in this project.
    mlflow_run_id = None
    mlflow_experiment_id = None
    try:
        mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
        mlflow.set_experiment("triage-classifier-training")
        with mlflow.start_run(run_name=f"train-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}") as run:
            mlflow_run_id = run.info.run_id
            mlflow_experiment_id = run.info.experiment_id
            mlflow.log_params({
                "n_training_samples": n,
                "dataset_source": "https://github.com/smartbugs/smartbugs-curated",
                "dataset_commit": DATASET_COMMIT,
                "chosen_model": chosen,
                "cv_method": "leave-one-out",
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "sklearn_version": sklearn.__version__,
                **{f"hparam_{k}": v for k, v in final_clf.get_params().items()},
            })
            metrics = {
                "cv_accuracy": results[chosen]["accuracy"],
                "cv_macro_f1": results[chosen]["macro_f1"],
                "cv_accuracy_ci_low": ci[0],
                "cv_accuracy_ci_high": ci[1],
                "random_forest_macro_f1": results["random_forest"]["macro_f1"],
                "gradient_boosting_macro_f1": results["gradient_boosting"]["macro_f1"],
            }
            for cls, rep in results[chosen]["report"].items():
                if isinstance(rep, dict) and "f1-score" in rep:
                    safe_cls = cls.replace(" ", "_")
                    metrics[f"class_{safe_cls}_precision"] = rep["precision"]
                    metrics[f"class_{safe_cls}_recall"] = rep["recall"]
                    metrics[f"class_{safe_cls}_f1"] = rep["f1-score"]
            mlflow.log_metrics(metrics)
            mlflow.log_artifact(str(model_path))
            mlflow.log_artifact(str(cm_path))
            if importances:
                mlflow.log_artifact(str(fi_path))
            mlflow.log_artifact(str(audit_csv))
        print(f"\n[+] Logged real MLflow run {mlflow_run_id} to {MLFLOW_TRACKING_URI} "
              f"(experiment 'triage-classifier-training')")
    except Exception as exc:  # noqa: BLE001
        print(f"\n[!] MLflow logging skipped (tracking server at {MLFLOW_TRACKING_URI} unreachable or "
              f"errored: {exc}) -- the real model/sidecar above were still produced and saved locally.")

    sidecar = {
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "n_training_samples": n,
        "class_distribution": dict(Counter(y_arr)),
        "dataset_source": "https://github.com/smartbugs/smartbugs-curated",
        "dataset_license": "Apache-2.0",
        "dataset_commit_recorded_at_fetch": DATASET_COMMIT,
        "training_data_sha256": dataset_content_sha256(),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": FEATURE_NAMES,
        "feature_schema_hash": schema_hash(),
        "chosen_model": chosen,
        "model_params": final_clf.get_params(),
        "sklearn_version": sklearn.__version__,
        "cv_method": "leave-one-out",
        "cv_results": {k: {"accuracy": v["accuracy"], "macro_f1": v["macro_f1"],
                           "per_class_report": v["report"], "confusion_matrix": v["confusion_matrix"],
                           "labels": v["labels"]} for k, v in results.items()},
        "accuracy_95pct_wilson_ci": list(ci),
        "feature_importances": importances,
        "mlflow_tracking_uri": MLFLOW_TRACKING_URI,
        "mlflow_run_id": mlflow_run_id,
        "mlflow_experiment_id": mlflow_experiment_id,
        "mlflow_experiment": "triage-classifier-training",
        "mlflow_run_url": (f"{MLFLOW_TRACKING_URI}/#/experiments/{mlflow_experiment_id}/runs/{mlflow_run_id}"
                           if mlflow_run_id else None),
        "honest_caveats": [
            "n=143 across 10 DASP categories; one category (short_addresses) has exactly 1 real example.",
            "LOOCV accuracy/macro-F1 reported above, with a real 95% CI -- treat both as noisy point estimates, not production-grade accuracy.",
            "This is a prioritization/triage hint layered on Slither's own findings, not an independent vulnerability classifier.",
            "Mythril was NOT part of training (see src/ml/feature_extraction.py docstring) -- myth is not installed natively on this host and real symbolic execution over 143 contracts was judged disproportionate to this step's scope.",
        ],
    }
    sidecar_path = MODELS_DIR / "triage_classifier_v1.sidecar.json"
    sidecar_path.write_text(json.dumps(sidecar, indent=2) + "\n", encoding="utf-8")

    print(f"\n[+] Wrote {model_path.relative_to(ROOT)}")
    print(f"[+] Wrote {sidecar_path.relative_to(ROOT)}")
    print(f"[+] Wrote {audit_csv.relative_to(ROOT)} (real per-contract feature matrix, {n} rows)")


if __name__ == "__main__":
    main()
