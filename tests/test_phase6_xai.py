"""Phase 6 XAI explanation tests (no retrain, no live capture)."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.capture.synthetic import generate_synthetic_flow_records
from app.core.config import get_settings
from app.database.models import IDSDatabase
from app.detection.anomaly_detector import AnomalyDetector
from app.detection.predictor import Predictor
from app.explainability.explainer import ExplanationError, explain_anomaly
from app.features.extractor import MODEL_FEATURE_ORDER, flow_records_to_matrix
from app.main import app
from app.services import runtime as runtime_mod


@pytest.fixture()
def fitted_detector(tmp_path: Path) -> AnomalyDetector:
    flows = generate_synthetic_flow_records(n_normal=80, n_anomalous=0)
    X, names = flow_records_to_matrix(flows)
    detector = AnomalyDetector(contamination=0.05, n_estimators=50, random_state=42)
    detector.fit(X, feature_names=names)
    path = tmp_path / "xai_model.joblib"
    detector.save(path)
    return AnomalyDetector.load(path)


def test_explanation_structure_and_all_features(fitted_detector: AnomalyDetector) -> None:
    unusual = generate_synthetic_flow_records(n_normal=0, n_anomalous=1)[0]
    X, _ = flow_records_to_matrix([unusual])
    result = explain_anomaly(fitted_detector, X[0])
    assert result["method"] == "local_baseline_occlusion"
    assert "contributions" in result
    contribs = result["contributions"]
    assert len(contribs) == 11
    names = [c["feature"] for c in contribs]
    assert set(names) == set(MODEL_FEATURE_ORDER)
    assert len(names) == 11
    required = {
        "feature",
        "value",
        "contribution",
        "absolute_contribution",
        "direction",
        "rank",
    }
    ranks = []
    for c in contribs:
        assert required <= set(c)
        assert c["direction"] in {"toward_anomaly", "toward_normal", "neutral"}
        assert np.isfinite(c["contribution"])
        assert np.isfinite(c["absolute_contribution"])
        assert c["absolute_contribution"] == abs(c["contribution"])
        ranks.append(c["rank"])
    assert sorted(ranks) == list(range(1, 12))


def test_explanation_deterministic(fitted_detector: AnomalyDetector) -> None:
    unusual = generate_synthetic_flow_records(n_normal=0, n_anomalous=1)[0]
    X, _ = flow_records_to_matrix([unusual])
    a = explain_anomaly(fitted_detector, X[0])
    b = explain_anomaly(fitted_detector, X[0])
    assert a["anomaly_score"] == b["anomaly_score"]
    assert [c["contribution"] for c in a["contributions"]] == [
        c["contribution"] for c in b["contributions"]
    ]


def test_explanation_normal_and_unusual(fitted_detector: AnomalyDetector) -> None:
    normal = generate_synthetic_flow_records(n_normal=1, n_anomalous=0)[0]
    unusual = generate_synthetic_flow_records(n_normal=0, n_anomalous=1)[0]
    Xn, _ = flow_records_to_matrix([normal])
    Xu, _ = flow_records_to_matrix([unusual])
    en = explain_anomaly(fitted_detector, Xn[0])
    eu = explain_anomaly(fitted_detector, Xu[0])
    assert len(en["contributions"]) == 11
    assert len(eu["contributions"]) == 11
    assert np.isfinite(en["anomaly_score"])
    assert np.isfinite(eu["anomaly_score"])


def test_explanation_does_not_retrain_or_change_prediction(
    fitted_detector: AnomalyDetector, tmp_path: Path
) -> None:
    unusual = generate_synthetic_flow_records(n_normal=0, n_anomalous=1)[0]
    X, _ = flow_records_to_matrix([unusual])
    before = fitted_detector.anomaly_scores(X).copy()
    pred_before = fitted_detector.predict(X).copy()
    # Touch a fake model path mtime check via save copy
    model_path = tmp_path / "copy.joblib"
    fitted_detector.save(model_path)
    mtime_before = model_path.stat().st_mtime

    explain_anomaly(fitted_detector, X[0])

    after = fitted_detector.anomaly_scores(X)
    pred_after = fitted_detector.predict(X)
    np.testing.assert_allclose(before, after)
    np.testing.assert_array_equal(pred_before, pred_after)
    assert model_path.stat().st_mtime == mtime_before


def test_explanation_rejects_nan(fitted_detector: AnomalyDetector) -> None:
    bad = {name: 1.0 for name in MODEL_FEATURE_ORDER}
    bad["duration"] = float("nan")
    with pytest.raises(ExplanationError):
        explain_anomaly(fitted_detector, bad)


def test_api_explanation_endpoint(tmp_path: Path, fitted_detector: AnomalyDetector) -> None:
    settings = get_settings()
    settings.database_path = tmp_path / "xai.db"
    settings.model_path = tmp_path / "det.joblib"
    fitted_detector.save(settings.model_path)
    runtime_mod._RUNTIME = None

    db = IDSDatabase(settings.database_path)
    predictor = Predictor(
        detector=fitted_detector, settings=settings, database=db
    )
    unusual = generate_synthetic_flow_records(n_normal=0, n_anomalous=1)[0]
    unusual["data_source"] = "synthetic"
    unusual["mode"] = "SYNTHETIC"
    predictor.predict_flow(unusual)
    flow_id = db.list_flows(limit=1)[0]["id"]

    client = TestClient(app)
    # Point runtime to same settings/db/model
    runtime_mod._RUNTIME = None
    settings2 = get_settings()
    settings2.database_path = settings.database_path
    settings2.model_path = settings.model_path

    # Re-bind runtime with correct paths
    from app.services.runtime import IDSRuntime

    runtime_mod._RUNTIME = IDSRuntime(settings=settings)

    resp = client.get(f"/api/explanation/{flow_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["flow_id"] == flow_id
    assert len(body["explanation"]["contributions"]) == 11
    assert body["explanation"]["method"] == "local_baseline_occlusion"

    missing = client.get("/api/explanation/999999")
    assert missing.status_code == 404
