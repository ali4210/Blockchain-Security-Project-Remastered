"""Unit tests for the Phase 4c ML triage classifier's honest-skip behaviour.

HONEST BEHAVIOUR UNDER TEST (src/ml/triage_classifier.py): a missing model
file, a missing sidecar, a feature-schema mismatch, or a training-data hash
mismatch must all raise TriageModelUnavailable -- never a silently guessed
score. These tests build a tiny, fully controlled model/sidecar/dataset
fixture in tmp_path so they never depend on the real trained artifact under
models/ (which scripts/train-triage-classifier.py regenerates).
"""
import hashlib
import json
import sys
from pathlib import Path

import joblib
import pytest
from sklearn.ensemble import RandomForestClassifier

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import src.ml.feature_extraction as fe  # noqa: E402
import src.ml.triage_classifier as tc  # noqa: E402
from src.ml.triage_classifier import TriageClassifier, TriageModelUnavailable  # noqa: E402


def _dataset_hash(dataset_dir: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(dataset_dir.rglob("*")):
        if p.is_file():
            h.update(str(p.relative_to(dataset_dir)).encode())
            h.update(p.read_bytes())
    return h.hexdigest()


@pytest.fixture
def valid_fixture(tmp_path, monkeypatch):
    """A real (if tiny) fitted RandomForestClassifier + a sidecar whose
    schema hash and training-data hash both genuinely match -- the happy
    path every other test perturbs one piece of."""
    dataset_dir = tmp_path / "dataset"
    dataset_dir.mkdir()
    (dataset_dir / "a.sol").write_text("contract A {}")
    (dataset_dir / "b.sol").write_text("contract B {}")

    n_features = len(fe.FEATURE_NAMES)
    X = [[float(i)] * n_features for i in range(4)]
    y = ["reentrancy", "reentrancy", "access_control", "access_control"]
    model = RandomForestClassifier(n_estimators=5, random_state=0).fit(X, y)

    model_path = tmp_path / "model.joblib"
    joblib.dump(model, model_path)

    sidecar_path = tmp_path / "model.sidecar.json"
    sidecar = {
        "feature_schema_version": fe.FEATURE_SCHEMA_VERSION,
        "feature_schema_hash": fe.schema_hash(),
        "training_data_sha256": _dataset_hash(dataset_dir),
        "n_training_samples": 4,
        "chosen_model": "random_forest",
        "cv_results": {"random_forest": {"accuracy": 0.6, "macro_f1": 0.4}},
        "accuracy_95pct_wilson_ci": [0.3, 0.8],
    }
    sidecar_path.write_text(json.dumps(sidecar))

    monkeypatch.setattr(tc, "DATASET_DIR", dataset_dir)
    return model_path, sidecar_path, dataset_dir, sidecar


def test_missing_model_file_raises_unavailable(valid_fixture, tmp_path):
    _, sidecar_path, _, _ = valid_fixture
    with pytest.raises(TriageModelUnavailable, match="model file missing"):
        TriageClassifier(model_path=tmp_path / "does-not-exist.joblib", sidecar_path=sidecar_path)


def test_missing_sidecar_raises_unavailable(valid_fixture, tmp_path):
    model_path, _, _, _ = valid_fixture
    with pytest.raises(TriageModelUnavailable, match="sidecar missing"):
        TriageClassifier(model_path=model_path, sidecar_path=tmp_path / "does-not-exist.json")


def test_model_file_deleted_after_training_triggers_skip(valid_fixture, tmp_path):
    """(a) the honest-skip path when the model artifact is removed/renamed
    out from under a previously-valid setup -- not just 'never existed'."""
    model_path, sidecar_path, _, _ = valid_fixture
    assert model_path.is_file()
    renamed = tmp_path / "model.joblib.bak"
    model_path.rename(renamed)

    with pytest.raises(TriageModelUnavailable, match="model file missing"):
        TriageClassifier(model_path=model_path, sidecar_path=sidecar_path)


def test_stale_training_data_hash_triggers_skip(valid_fixture):
    """(b) a training-data content mismatch (dataset changed since training)
    must refuse to score, not silently use a possibly-wrong model."""
    model_path, sidecar_path, dataset_dir, sidecar = valid_fixture
    sidecar["training_data_sha256"] = "0" * 64  # deliberately wrong
    sidecar_path.write_text(json.dumps(sidecar))

    with pytest.raises(TriageModelUnavailable, match="does not match the hash recorded"):
        TriageClassifier(model_path=model_path, sidecar_path=sidecar_path)


def test_missing_training_dataset_dir_triggers_skip(valid_fixture, tmp_path, monkeypatch):
    model_path, sidecar_path, _, _ = valid_fixture
    monkeypatch.setattr(tc, "DATASET_DIR", tmp_path / "no-such-dataset-dir")
    with pytest.raises(TriageModelUnavailable, match="training dataset missing"):
        TriageClassifier(model_path=model_path, sidecar_path=sidecar_path)


def test_feature_schema_hash_mismatch_triggers_skip(valid_fixture):
    model_path, sidecar_path, _, sidecar = valid_fixture
    sidecar["feature_schema_hash"] = "not-the-real-hash"
    sidecar_path.write_text(json.dumps(sidecar))
    with pytest.raises(TriageModelUnavailable, match="feature schema mismatch"):
        TriageClassifier(model_path=model_path, sidecar_path=sidecar_path)


def test_feature_schema_version_mismatch_triggers_skip(valid_fixture):
    model_path, sidecar_path, _, sidecar = valid_fixture
    sidecar["feature_schema_version"] = fe.FEATURE_SCHEMA_VERSION + 1
    sidecar["feature_schema_hash"] = fe.schema_hash()  # keep this one correct in isolation
    sidecar_path.write_text(json.dumps(sidecar))
    with pytest.raises(TriageModelUnavailable, match="feature schema version mismatch"):
        TriageClassifier(model_path=model_path, sidecar_path=sidecar_path)


def test_valid_setup_loads_and_predicts(valid_fixture):
    """The happy path: everything lines up -> a real prediction, with the
    honest caveat text always present (never a bare number)."""
    model_path, sidecar_path, _, _ = valid_fixture
    clf = TriageClassifier(model_path=model_path, sidecar_path=sidecar_path)

    ast = {"nodeType": "SourceUnit", "nodes": []}
    prediction = clf.predict(slither_json=None, ast=ast, source_text="contract X {}")

    assert prediction.predicted_category in {"reentrancy", "access_control"}
    assert abs(sum(prediction.class_probabilities.values()) - 1.0) < 1e-6
    assert "n=4" in prediction.caveat
    assert "NOT an" in prediction.caveat or "triage" in prediction.caveat.lower()
    assert prediction.n_training_samples == 4
