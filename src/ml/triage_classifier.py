"""Runtime scorer for the Phase 4c triage classifier (see
scripts/train-triage-classifier.py for how models/triage_classifier_v1.*
was produced, and src/ml/feature_extraction.py for the honest scope of
what feeds it).

HONEST BEHAVIOUR (same contract as kyc_verifier.py / address_screener.py):
  * Missing model file, missing sidecar, a feature-schema mismatch, or a
    training-data hash mismatch -> TriageModelUnavailable. Callers must
    translate that into a not_run scanner result. A score is NEVER guessed
    when the model/sidecar can't be trusted.
  * A real score is always returned alongside the sidecar's real n=143 LOOCV
    accuracy/macro-F1 and 95% CI -- see TriagePrediction.caveat. Nothing
    renders this model's output as a bare number.
  * This is a prioritization/triage hint layered on Slither's own findings,
    trained on 143 real human-labeled contracts -- never call it an
    "ML vulnerability detector" or "independent classifier" anywhere this
    is surfaced (report/HTML/DefectDojo).
"""
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib

from src.ml.feature_extraction import (
    FEATURE_SCHEMA_VERSION, feature_vector, schema_hash,
    slither_features_from_report, structural_features_from_ast,
)

MODELS_DIR = Path(__file__).resolve().parents[2] / "models"
MODEL_PATH = MODELS_DIR / "triage_classifier_v1.joblib"
SIDECAR_PATH = MODELS_DIR / "triage_classifier_v1.sidecar.json"
DATASET_DIR = Path(__file__).resolve().parents[2] / "data" / "smartbugs-curated"


class TriageModelUnavailable(RuntimeError):
    """The trained triage model/sidecar is missing, mismatched, or stale.
    Callers must report not_run, never fabricate a score."""


def _dataset_content_sha256() -> Optional[str]:
    if not DATASET_DIR.is_dir():
        return None
    h = hashlib.sha256()
    for p in sorted(DATASET_DIR.rglob("*")):
        if p.is_file():
            h.update(str(p.relative_to(DATASET_DIR)).encode())
            h.update(p.read_bytes())
    return h.hexdigest()


@dataclass
class TriagePrediction:
    predicted_category: str
    class_probabilities: Dict[str, float]
    caveat: str
    cv_accuracy: float
    cv_macro_f1: float
    cv_accuracy_ci: List[float]
    n_training_samples: int


class TriageClassifier:
    """Loads and validates the trained model + sidecar once; raises
    TriageModelUnavailable immediately if anything doesn't line up, rather
    than failing later on a silent mismatch."""

    def __init__(self, model_path: Path = MODEL_PATH, sidecar_path: Path = SIDECAR_PATH,
                 verify_training_data: bool = True):
        if not model_path.is_file():
            raise TriageModelUnavailable(f"model file missing: {model_path}")
        if not sidecar_path.is_file():
            raise TriageModelUnavailable(f"sidecar missing: {sidecar_path}")
        try:
            self.sidecar: Dict[str, Any] = json.loads(sidecar_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise TriageModelUnavailable(f"sidecar unreadable: {exc}") from exc

        sidecar_schema_hash = self.sidecar.get("feature_schema_hash")
        if sidecar_schema_hash != schema_hash():
            raise TriageModelUnavailable(
                f"feature schema mismatch: model was trained against schema hash "
                f"{sidecar_schema_hash!r}, current feature_extraction.py is {schema_hash()!r} "
                f"-- refusing to score with misaligned columns, retrain the model")
        if self.sidecar.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
            raise TriageModelUnavailable(
                f"feature schema version mismatch: model={self.sidecar.get('feature_schema_version')} "
                f"current={FEATURE_SCHEMA_VERSION}")

        if verify_training_data:
            recorded_hash = self.sidecar.get("training_data_sha256")
            current_hash = _dataset_content_sha256()
            if current_hash is None:
                raise TriageModelUnavailable(
                    f"training dataset missing on disk ({DATASET_DIR}) -- cannot verify model provenance")
            if recorded_hash != current_hash:
                raise TriageModelUnavailable(
                    "training dataset on disk does not match the hash recorded at training time "
                    "-- model may be stale relative to the data it claims to be trained on, refusing to score")

        try:
            self.model = joblib.load(model_path)
        except Exception as exc:  # noqa: BLE001
            raise TriageModelUnavailable(f"model file could not be loaded: {exc}") from exc

        cv = self.sidecar.get("cv_results", {}).get(self.sidecar.get("chosen_model"), {})
        self._cv_accuracy = cv.get("accuracy", 0.0)
        self._cv_macro_f1 = cv.get("macro_f1", 0.0)
        self._cv_ci = self.sidecar.get("accuracy_95pct_wilson_ci", [0.0, 1.0])
        self._n = self.sidecar.get("n_training_samples", 0)

    def caveat_text(self) -> str:
        return (f"Triage/prioritization hint only, layered on Slither's own findings -- NOT an "
                f"independent vulnerability detector. Trained on n={self._n} real, human-labeled "
                f"SmartBugs-curated contracts (10 imbalanced DASP categories, one with a single "
                f"example). Real leave-one-out CV: accuracy={self._cv_accuracy:.3f} "
                f"(95% CI [{self._cv_ci[0]:.3f}, {self._cv_ci[1]:.3f}]), macro-F1={self._cv_macro_f1:.3f}.")

    def predict(self, slither_json: Optional[dict], ast: dict, source_text: str) -> TriagePrediction:
        slither_feats = slither_features_from_report(slither_json)
        struct_feats = structural_features_from_ast(ast, source_text)
        vec = feature_vector(struct_feats, slither_feats)
        probs = self.model.predict_proba([vec])[0]
        classes = list(self.model.classes_)
        prob_map = {str(c): round(float(p), 4) for c, p in zip(classes, probs)}
        predicted = str(classes[int(probs.argmax())])
        return TriagePrediction(
            predicted_category=predicted,
            class_probabilities=prob_map,
            caveat=self.caveat_text(),
            cv_accuracy=self._cv_accuracy,
            cv_macro_f1=self._cv_macro_f1,
            cv_accuracy_ci=list(self._cv_ci),
            n_training_samples=self._n,
        )
