"""Phase 3 capture / flow / detection / API tests (no admin, no network)."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.alerts.engine import generate_alert, should_alert
from app.capture.packet_capture import CapturedPacket, PacketCapture
from app.capture.synthetic import (
    generate_synthetic_flow_records,
    generate_synthetic_packets,
)
from app.core.config import get_settings
from app.database.models import IDSDatabase
from app.detection.anomaly_detector import AnomalyDetector
from app.detection.predictor import Predictor
from app.detection.risk import compute_risk_score, risk_severity
from app.features.extractor import FLOW_FEATURE_NAMES, flow_records_to_matrix
from app.features.flow_aggregator import FlowAggregator, aggregate_packets
from app.main import app


@pytest.fixture()
def tmp_db(tmp_path: Path) -> IDSDatabase:
    return IDSDatabase(tmp_path / "test_ids.db")


def test_packet_capture_init_synthetic() -> None:
    cap = PacketCapture(mode="synthetic", duration=1.0, packet_count=5)
    assert cap.mode == "synthetic"
    assert not cap.is_running
    result = cap.start()
    assert result.mode == "synthetic"
    assert result.packets == []
    assert result.privilege_note


def test_packet_capture_invalid_mode() -> None:
    with pytest.raises(ValueError):
        PacketCapture(mode="attack")


def test_flow_aggregation_and_missing_ip() -> None:
    packets = [
        CapturedPacket(
            timestamp=1.0,
            length=100,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1111,
            dst_port=80,
            protocol="TCP",
            tcp_flags="S",
        ),
        CapturedPacket(
            timestamp=1.2,
            length=200,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1111,
            dst_port=80,
            protocol="TCP",
            tcp_flags="A",
        ),
        CapturedPacket(timestamp=1.3, length=50),  # missing IP -> skipped
    ]
    agg = FlowAggregator(data_source="synthetic")
    agg.add_packets(packets)
    flows = agg.get_flows()
    assert len(flows) == 1
    assert agg.skipped_packets == 1
    assert flows[0].packet_count == 2
    assert flows[0].byte_count == 300
    assert flows[0].tcp_flag_syn == 1
    assert flows[0].tcp_flag_ack == 1


def test_aggregate_packets_helper() -> None:
    packets = generate_synthetic_packets(n_normal=10, n_anomalous=2)
    flows = aggregate_packets(packets, data_source="synthetic")
    assert len(flows) >= 1
    assert "packet_count" in flows[0]


def test_isolation_forest_fit_predict_save_load(tmp_path: Path) -> None:
    flows = generate_synthetic_flow_records(n_normal=60, n_anomalous=0)
    X, names = flow_records_to_matrix(flows)
    assert names == FLOW_FEATURE_NAMES
    detector = AnomalyDetector(contamination=0.1, n_estimators=50, random_state=42)
    detector.fit(X, feature_names=names)
    labels = detector.predict_labels(X[:5])
    assert all(lbl in {"NORMAL", "ANOMALOUS"} for lbl in labels)
    scores = detector.anomaly_scores(X[:5])
    assert scores.shape == (5,)

    path = tmp_path / "model.joblib"
    detector.save(path)
    loaded = AnomalyDetector.load(path)
    np.testing.assert_allclose(
        detector.anomaly_scores(X[:3]), loaded.anomaly_scores(X[:3])
    )


def test_predictor_schema_and_persistence(tmp_db: IDSDatabase, tmp_path: Path) -> None:
    normal = generate_synthetic_flow_records(n_normal=80, n_anomalous=0)
    X, names = flow_records_to_matrix(normal)
    detector = AnomalyDetector(contamination=0.05, random_state=0)
    detector.fit(X, feature_names=names)
    model_path = tmp_path / "det.joblib"
    detector.save(model_path)

    settings = get_settings()
    # Avoid mutating global settings permanently; override via object fields.
    settings.model_path = model_path
    settings.alert_risk_threshold = 1

    predictor = Predictor(detector=detector, settings=settings, database=tmp_db)
    unusual = generate_synthetic_flow_records(n_normal=0, n_anomalous=3)[0]
    result = predictor.predict_flow(unusual)

    assert set(result) >= {
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "is_anomaly",
        "anomaly_score",
        "risk_score",
    }
    assert isinstance(result["is_anomaly"], bool)
    assert 0 <= result["risk_score"] <= 100
    assert tmp_db.stats()["total_flows"] >= 1


def test_risk_score_bounds_and_severity() -> None:
    for score in [-2.0, -0.1, 0.0, 0.5, 2.0]:
        risk = compute_risk_score(score, {"packets_per_second": 10})
        assert 0 <= risk <= 100
    assert risk_severity(10) == "Low"
    assert risk_severity(40) == "Medium"
    assert risk_severity(70) == "High"
    assert risk_severity(90) == "Critical"


def test_alert_generation() -> None:
    assert should_alert(60, 60)
    assert not should_alert(10, 60)
    alert = generate_alert(
        flow={"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "protocol": "TCP"},
        anomaly_score=0.8,
        risk_score=85,
        severity="Critical",
        data_source="synthetic",
    )
    assert alert.is_synthetic is True
    assert "SYNTHETIC" in alert.message
    assert alert.risk_score == 85


def test_database_persistence(tmp_db: IDSDatabase) -> None:
    tmp_db.insert_flow(
        {
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "protocol": "TCP",
            "is_anomaly": True,
            "anomaly_score": 0.9,
            "risk_score": 88,
            "data_source": "synthetic",
            "features": {"duration": 1.0},
        }
    )
    tmp_db.insert_alert(
        {
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "protocol": "TCP",
            "risk_score": 88,
            "anomaly_score": 0.9,
            "severity": "Critical",
            "message": "test",
            "data_source": "synthetic",
            "is_synthetic": True,
        }
    )
    stats = tmp_db.stats()
    assert stats["total_flows"] == 1
    assert stats["anomalous_flows"] == 1
    assert stats["alert_count"] == 1
    assert len(tmp_db.list_flows()) == 1
    assert len(tmp_db.list_alerts()) == 1


def test_safe_test_mode_fixtures() -> None:
    packets = generate_synthetic_packets(n_normal=5, n_anomalous=2)
    flows = generate_synthetic_flow_records(n_normal=5, n_anomalous=2)
    assert len(packets) == 7
    assert all(f["data_source"] == "synthetic" for f in flows)
    assert any(f["traffic_profile"] == "anomalous" for f in flows)


def test_api_endpoints_health_and_status() -> None:
    client = TestClient(app)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["service"] == "iot-ids"
    status = client.get("/api/status")
    assert status.status_code == 200
    body = status.json()
    assert "ids_mode" in body
    assert "model_loaded" in body


def test_api_lists_and_detection_require_model(tmp_path: Path, monkeypatch) -> None:
    # Point runtime DB/model to temp paths for isolation.
    from app.services import runtime as runtime_mod

    settings = get_settings()
    settings.database_path = tmp_path / "api.db"
    settings.model_path = tmp_path / "missing.joblib"
    runtime_mod._RUNTIME = None

    client = TestClient(app)
    assert client.get("/api/alerts").status_code == 200
    assert client.get("/api/flows").status_code == 200
    stop = client.post("/api/capture/stop")
    assert stop.status_code == 200
    # Without a model, detection test should fail with 500.
    resp = client.post("/api/detection/test")
    assert resp.status_code == 500
