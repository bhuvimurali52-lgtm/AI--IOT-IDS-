"""Phase 7 offline evaluation tests."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.detection.anomaly_detector import AnomalyDetector
from app.evaluation.datasets import (
    build_labeled_evaluation_records,
    evaluation_matrix_from_records,
)
from app.evaluation.evaluator import (
    confusion_counts,
    evaluate_detector,
    metrics_from_confusion,
    run_offline_evaluation,
)
from app.features.extractor import MODEL_FEATURE_ORDER
from app.main import app
from app.services import runtime as runtime_mod
from app.services.runtime import IDSRuntime


@pytest.fixture()
def model_path() -> Path:
    path = Path("models/anomaly_detector.joblib")
    if not path.exists():
        pytest.skip("models/anomaly_detector.joblib missing")
    return path


def test_evaluation_dataset_labels_and_features() -> None:
    records = build_labeled_evaluation_records(n_normal=20, n_anomalous=15, seed=42)
    assert any(r["ground_truth"] == 0 for r in records)
    assert any(r["ground_truth"] == 1 for r in records)
    assert all("ground_truth" in r for r in records)
    X, y, names = evaluation_matrix_from_records(records)
    assert X.shape[1] == 11
    assert names == list(MODEL_FEATURE_ORDER)
    assert set(np.unique(y).tolist()) == {0, 1}
    # Labels must not be part of X columns.
    assert X.shape[0] == len(records)


def test_metrics_math_and_zero_division() -> None:
    cm = {"tn": 5, "fp": 1, "fn": 2, "tp": 4}
    mets = metrics_from_confusion(cm)
    assert mets["accuracy"] == pytest.approx((4 + 5) / 12)
    assert mets["precision"] == pytest.approx(4 / 5)
    assert mets["recall"] == pytest.approx(4 / 6)
    assert mets["specificity"] == pytest.approx(5 / 6)
    assert mets["false_positive_rate"] == pytest.approx(1 / 6)
    assert mets["false_negative_rate"] == pytest.approx(2 / 6)
    assert mets["anomaly_detection_rate"] == mets["recall"]
    # Zero-division safe
    empty = metrics_from_confusion({"tn": 0, "fp": 0, "fn": 0, "tp": 0})
    assert empty["precision"] == 0.0
    assert empty["recall"] == 0.0
    assert empty["f1"] == 0.0
    assert empty["accuracy"] == 0.0


def test_confusion_consistent_with_predictions(model_path: Path) -> None:
    records = build_labeled_evaluation_records(n_normal=30, n_anomalous=20, seed=7)
    X, y_true, _ = evaluation_matrix_from_records(records)
    detector = AnomalyDetector.load(model_path)
    result = evaluate_detector(detector, X, y_true, include_threshold_analysis=False)
    cm = result["confusion_matrix"]
    assert cm["tn"] + cm["fp"] + cm["fn"] + cm["tp"] == len(y_true)
    assert result["dataset"]["normal"] + result["dataset"]["anomalous"] == len(y_true)
    assert (
        result["predictions"]["normal"] + result["predictions"]["anomalous"]
        == len(y_true)
    )
    # Accuracy consistency
    total = len(y_true)
    expected_acc = (cm["tp"] + cm["tn"]) / total
    assert result["metrics"]["accuracy"] == pytest.approx(expected_acc)


def test_inference_does_not_use_labels(model_path: Path) -> None:
    records = build_labeled_evaluation_records(n_normal=10, n_anomalous=10, seed=1)
    X, y_true, _ = evaluation_matrix_from_records(records)
    detector = AnomalyDetector.load(model_path)

    orig_predict = detector.predict

    def wrapped_predict(arr):
        assert arr.shape[1] == 11
        return orig_predict(arr)

    detector.predict = wrapped_predict  # type: ignore[method-assign]
    _ = evaluate_detector(detector, X, y_true, include_threshold_analysis=False)
    assert X.shape[1] == 11


def test_evaluation_deterministic_and_no_retrain(model_path: Path) -> None:
    mtime_before = model_path.stat().st_mtime
    a = run_offline_evaluation(model_path=model_path, seed=42)
    b = run_offline_evaluation(model_path=model_path, seed=42)
    assert a["metrics"] == b["metrics"]
    assert a["confusion_matrix"] == b["confusion_matrix"]
    assert a["dataset"] == b["dataset"]
    assert a["predictions"] == b["predictions"]
    assert [r["threshold"] for r in a["threshold_analysis"]] == [
        r["threshold"] for r in b["threshold_analysis"]
    ]
    mtime_after = model_path.stat().st_mtime
    assert mtime_before == mtime_after


def test_api_evaluation_endpoint(model_path: Path, tmp_path: Path) -> None:
    settings = get_settings()
    settings.model_path = model_path
    settings.database_path = tmp_path / "eval.db"
    runtime_mod._RUNTIME = IDSRuntime(settings=settings)
    client = TestClient(app)
    resp = client.get("/api/evaluation")
    assert resp.status_code == 200
    body = resp.json()
    assert "dataset" in body
    assert "confusion_matrix" in body
    assert "metrics" in body
    assert body["dataset"]["total"] == body["dataset"]["normal"] + body["dataset"]["anomalous"]
    assert set(body["confusion_matrix"]) >= {"tn", "fp", "fn", "tp"}
    assert body["feature_order"] == list(MODEL_FEATURE_ORDER)
