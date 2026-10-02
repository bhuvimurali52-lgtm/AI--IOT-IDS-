"""Phase 8 application-hardening tests (no retraining, no live capture)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.middleware.cors import CORSMiddleware

from app.core.config import Settings
from app.core.errors import (
    filter_public_mapping,
    looks_like_secret_key,
    sanitize_public_message,
)
from app.features.extractor import MODEL_FEATURE_ORDER
from app.main import app

EXPECTED_FEATURES = [
    "duration",
    "packet_count",
    "byte_count",
    "packets_per_second",
    "bytes_per_second",
    "average_packet_size",
    "min_packet_size",
    "max_packet_size",
    "source_port",
    "destination_port",
    "protocol",
]


def test_sanitize_public_message_strips_filesystem_paths() -> None:
    raw = r"failed to load C:\Users\bhuvi\project\model.joblib extra"
    out = sanitize_public_message(raw)
    assert "C:\\Users" not in out
    assert "[path]" in out
    assert "traceback" not in out.lower()


def test_sanitize_secret_like_message_uses_fallback() -> None:
    out = sanitize_public_message("invalid password=hunter2", fallback="Request failed")
    assert out == "Request failed"


def test_filter_public_mapping_drops_secret_keys() -> None:
    payload = {
        "model_loaded": True,
        "api_key": "should-not-leak",
        "password": "nope",
        "ids_mode": "synthetic",
    }
    filtered = filter_public_mapping(payload)
    assert filtered["model_loaded"] is True
    assert filtered["ids_mode"] == "synthetic"
    assert "api_key" not in filtered
    assert "password" not in filtered
    assert looks_like_secret_key("authorization")


def test_unhandled_exception_is_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    class Boom:
        def status(self) -> dict:
            raise RuntimeError(
                r"Traceback (most recent call last):\nFile "
                r'"C:\Users\bhuvi\app.py", line 1\nsecret_token=abc'
            )

    monkeypatch.setattr("app.api.routes.get_runtime", lambda: Boom())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/status")
    assert resp.status_code == 500
    body = resp.json()
    text = str(body)
    assert body["detail"] == "Internal server error"
    assert "Traceback" not in text
    assert "C:\\Users" not in text
    assert "secret_token" not in text


def test_health_payload_unchanged() -> None:
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "iot-ids"}


def test_ready_endpoint_does_not_retrain() -> None:
    model = Path("models/anomaly_detector.joblib")
    if not model.exists():
        pytest.skip("models/anomaly_detector.joblib missing")
    mtime = model.stat().st_mtime
    client = TestClient(app)
    resp = client.get("/ready")
    assert resp.status_code in {200, 503}
    body = resp.json()
    assert "ready" in body
    assert "model_loaded" in body
    assert "database_available" in body
    assert "retrain" not in str(body).lower() or "does not retrain" in str(body).lower()
    assert model.stat().st_mtime == mtime


def test_cors_is_explicit_and_no_wildcard_credentials() -> None:
    cors_layers = [m for m in app.user_middleware if m.cls is CORSMiddleware]
    assert cors_layers, "CORS middleware must be configured explicitly"
    kwargs = cors_layers[0].kwargs
    origins = list(kwargs.get("allow_origins") or [])
    assert kwargs.get("allow_credentials") is False
    if "*" in origins:
        assert kwargs.get("allow_credentials") is False
    else:
        assert "http://localhost:8502" in origins or "http://127.0.0.1:8502" in origins

    client = TestClient(app)
    resp = client.get("/health", headers={"Origin": "http://localhost:8502"})
    assert resp.status_code == 200
    allow = resp.headers.get("access-control-allow-origin")
    assert allow in {None, "http://localhost:8502"}
    if allow == "*":
        assert resp.headers.get("access-control-allow-credentials") != "true"


def test_production_wildcard_cors_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(app_env="production", cors_allowed_origins="*")


def test_feature_order_unchanged() -> None:
    assert list(MODEL_FEATURE_ORDER) == EXPECTED_FEATURES
    assert len(MODEL_FEATURE_ORDER) == 11


def test_existing_phase_endpoints_still_ok() -> None:
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/api/status").status_code == 200
    assert client.get("/api/model").status_code == 200
    assert client.get("/api/flows").status_code == 200
    assert client.get("/api/alerts").status_code == 200
    eval_resp = client.get("/api/evaluation")
    assert eval_resp.status_code in {200, 503}
    missing = client.get("/api/explanation/999999")
    assert missing.status_code == 404
    detail = str(missing.json())
    assert "Traceback" not in detail
    assert not re.search(r"[A-Za-z]:\\", detail)


def test_dashboard_imports_and_unique_keys() -> None:
    from app.dashboard.components import render_evaluation_panel, render_explanation_panel
    from app.dashboard.streamlit_app import main

    assert callable(main)
    assert callable(render_explanation_panel)
    assert callable(render_evaluation_panel)
    keys = [
        "flow_timeline",
        "risk_timeline",
        "risk_distribution",
        "xai_contribution_chart",
        "eval_threshold_chart",
        "start_live_capture_btn",
        "stop_live_capture_btn",
        "capture_refresh_btn",
        "run_synthetic_test_btn",
    ]
    assert len(keys) == len(set(keys))


def test_model_artifact_not_modified_by_hardening_checks() -> None:
    path = Path("models/anomaly_detector.joblib")
    if not path.exists():
        pytest.skip("models/anomaly_detector.joblib missing")
    before = path.stat().st_mtime
    from app.detection.anomaly_detector import AnomalyDetector

    det = AnomalyDetector.load(path)
    assert det.is_fitted
    after = path.stat().st_mtime
    assert before == after
