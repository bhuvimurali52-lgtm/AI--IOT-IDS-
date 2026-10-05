"""Phase 5 dashboard helper tests (no live network capture required)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.dashboard.services.metrics import (
    anomaly_rate,
    filter_records,
    normalize_mode,
    parse_features,
    parse_timestamp,
    severity_distribution,
    summarize_metrics,
)


def test_anomaly_rate_zero_and_normal() -> None:
    assert anomaly_rate(0, 0) == 0.0
    assert anomaly_rate(1, 4) == 25.0
    assert anomaly_rate(2, 8) == 25.0


def test_parse_timestamp_invalid() -> None:
    assert parse_timestamp(None) is None
    assert parse_timestamp("not-a-time") is None
    assert parse_timestamp("2026-09-15T10:00:00Z") is not None


def test_parse_features_from_json() -> None:
    row = {"features_json": '{"packet_count": 12, "byte_count": 340}'}
    feats = parse_features(row)
    assert feats["packet_count"] == 12
    assert feats["byte_count"] == 340


def test_filter_mode_excludes_synthetic_from_live() -> None:
    now = datetime.now(timezone.utc)
    rows = [
        {
            "timestamp": now.isoformat(),
            "mode": "SYNTHETIC",
            "severity": "High",
            "risk_score": 70,
            "is_anomaly": 1,
        },
        {
            "timestamp": now.isoformat(),
            "mode": "LIVE",
            "severity": "Low",
            "risk_score": 10,
            "is_anomaly": 0,
        },
    ]
    live = filter_records(rows, mode="LIVE", severity="ALL", time_range_label="Last 1 hour", now=now)
    assert len(live) == 1
    assert live[0]["mode"] == "LIVE"


def test_filter_time_and_severity() -> None:
    now = datetime.now(timezone.utc)
    rows = [
        {
            "timestamp": (now - timedelta(minutes=2)).isoformat(),
            "mode": "SYNTHETIC",
            "severity": "Critical",
            "risk_score": 95,
        },
        {
            "timestamp": (now - timedelta(hours=5)).isoformat(),
            "mode": "SYNTHETIC",
            "severity": "Critical",
            "risk_score": 95,
        },
        {
            "timestamp": (now - timedelta(minutes=1)).isoformat(),
            "mode": "SYNTHETIC",
            "severity": "Low",
            "risk_score": 10,
        },
    ]
    filtered = filter_records(
        rows,
        mode="SYNTHETIC",
        severity="CRITICAL",
        time_range_label="Last 5 minutes",
        now=now,
    )
    assert len(filtered) == 1
    assert filtered[0]["severity"].upper() == "CRITICAL"


def test_filter_all_time_keeps_historical_records() -> None:
    now = datetime.now(timezone.utc)
    rows = [
        {
            "timestamp": (now - timedelta(days=20)).isoformat(),
            "mode": "SYNTHETIC",
            "severity": "High",
            "risk_score": 74,
            "is_anomaly": 1,
        }
    ]
    hidden = filter_records(
        rows, mode="ALL", severity="ALL", time_range_label="Last 24 hours", now=now
    )
    kept = filter_records(
        rows, mode="ALL", severity="ALL", time_range_label="All time", now=now
    )
    assert hidden == []
    assert len(kept) == 1
    assert kept[0]["risk_score"] == 74


def test_severity_distribution_and_summary() -> None:
    rows = [
        {"severity": "Low", "risk_score": 10, "is_anomaly": 0},
        {"severity": "High", "risk_score": 70, "is_anomaly": 1},
        {"severity": "Critical", "risk_score": 90, "is_anomaly": 1},
    ]
    dist = severity_distribution(rows)
    assert dist["LOW"] == 1
    assert dist["HIGH"] == 1
    assert dist["CRITICAL"] == 1
    summary = summarize_metrics(rows)
    assert summary["total_flows"] == 3
    assert summary["anomalous_flows"] == 2
    assert summary["anomaly_rate"] == pytest.approx(66.67)


def test_normalize_mode() -> None:
    assert normalize_mode("synthetic") == "SYNTHETIC"
    assert normalize_mode("LIVE") == "LIVE"


def test_api_model_includes_training_hyperparams() -> None:
    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app)
    resp = client.get("/api/model")
    assert resp.status_code == 200
    body = resp.json()
    assert "feature_order" in body
    assert body.get("n_features") == 11 or len(body.get("feature_order") or []) == 11
    assert "contamination" in body
    assert "n_estimators" in body
    assert "random_state" in body
    assert body.get("model_type") == "Isolation Forest"
