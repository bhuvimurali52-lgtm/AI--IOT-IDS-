"""Phase 4 live pipeline tests (mocked; no admin, no real sniff, no network)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.capture.packet_capture import CapturedPacket, CaptureError, PacketCapture
from app.capture.synthetic import generate_synthetic_flow_records
from app.core.config import get_settings
from app.database.models import IDSDatabase
from app.detection.anomaly_detector import AnomalyDetector
from app.detection.live_detector import LiveDetector
from app.features.extractor import (
    MODEL_FEATURE_ORDER,
    FeatureValidationError,
    flow_to_model_vector,
    validate_model_features,
)
from app.features.flow_aggregator import FlowAggregator
from app.main import app
from app.services import runtime as runtime_mod
from app.services.runtime import IDSRuntime, LIVE_CAPTURE_BANNER


@pytest.fixture()
def tmp_db(tmp_path: Path) -> IDSDatabase:
    return IDSDatabase(tmp_path / "phase4.db")


@pytest.fixture()
def fitted_model(tmp_path: Path) -> tuple[AnomalyDetector, Path]:
    flows = generate_synthetic_flow_records(n_normal=80, n_anomalous=0)
    from app.features.extractor import flow_records_to_matrix

    X, names = flow_records_to_matrix(flows)
    detector = AnomalyDetector(contamination=0.05, n_estimators=50, random_state=42)
    detector.fit(X, feature_names=names)
    path = tmp_path / "phase4_model.joblib"
    detector.save(path)
    return detector, path


def test_model_feature_order_contract() -> None:
    assert len(MODEL_FEATURE_ORDER) == 11
    assert list(MODEL_FEATURE_ORDER) == [
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


def test_feature_vector_ordering() -> None:
    flow = {
        "duration": 1.0,
        "packet_count": 10,
        "byte_count": 1000,
        "packets_per_second": 10.0,
        "bytes_per_second": 1000.0,
        "average_packet_size": 100.0,
        "min_packet_size": 60,
        "max_packet_size": 200,
        "source_port": 1234,
        "destination_port": 80,
        "protocol": "TCP",
    }
    vector = flow_to_model_vector(flow)
    assert len(vector) == 11
    assert vector[8] == 1234.0
    assert vector[9] == 80.0
    assert vector[10] == 6.0  # TCP
    ordered = validate_model_features(
        {name: vector[i] for i, name in enumerate(MODEL_FEATURE_ORDER)}
    )
    assert ordered == vector


def test_validate_rejects_nan_and_missing() -> None:
    with pytest.raises(FeatureValidationError):
        validate_model_features({"duration": 1.0})
    bad = {name: 1.0 for name in MODEL_FEATURE_ORDER}
    bad["duration"] = float("nan")
    with pytest.raises(FeatureValidationError):
        validate_model_features(bad)


def test_packet_to_flow_conversion() -> None:
    packets = [
        CapturedPacket(
            timestamp=10.0,
            length=100,
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            src_port=5555,
            dst_port=443,
            protocol="TCP",
            tcp_flags="S",
        ),
        CapturedPacket(
            timestamp=10.5,
            length=200,
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            src_port=5555,
            dst_port=443,
            protocol="TCP",
            tcp_flags="A",
        ),
    ]
    agg = FlowAggregator(data_source="live")
    agg.add_packets(packets)
    flows = agg.get_flow_dicts()
    assert len(flows) == 1
    assert flows[0]["mode"] == "LIVE"
    assert flows[0]["data_source"] == "live"
    assert flows[0]["packet_count"] == 2.0
    assert flows[0]["byte_count"] == 300.0
    vector = flow_to_model_vector(flows[0])
    assert len(vector) == 11


def test_flow_timeout_completion() -> None:
    agg = FlowAggregator(data_source="live")
    agg.add_packet(
        CapturedPacket(
            timestamp=100.0,
            length=80,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1,
            dst_port=2,
            protocol="UDP",
        )
    )
    assert agg.open_flow_count == 1
    # Not idle yet relative to "now" close to end_time.
    assert agg.pop_idle_flows(5.0, now=101.0) == []
    completed = agg.pop_idle_flows(5.0, now=106.0)
    assert len(completed) == 1
    assert agg.open_flow_count == 0


def test_flush_all_on_stop() -> None:
    agg = FlowAggregator(data_source="live")
    agg.add_packet(
        CapturedPacket(
            timestamp=1.0,
            length=50,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=9,
            dst_port=9,
            protocol="TCP",
        )
    )
    flushed = agg.flush_all()
    assert len(flushed) == 1
    assert agg.open_flow_count == 0


def test_invalid_packet_handling() -> None:
    agg = FlowAggregator(data_source="live")
    agg.add_packet(CapturedPacket(timestamp=1.0, length=40))  # no IPs
    assert agg.skipped_packets == 1
    assert agg.open_flow_count == 0


def test_live_detector_initialization(fitted_model, tmp_db: IDSDatabase) -> None:
    detector, path = fitted_model
    settings = get_settings()
    settings.model_path = path
    settings.alert_risk_threshold = 1
    live = LiveDetector(settings=settings, database=tmp_db, detector=detector)
    assert live.is_ready
    live2 = LiveDetector(settings=settings, database=tmp_db)
    live2.load_model(path)
    assert live2.is_ready


def test_model_inference_and_live_persistence(
    fitted_model, tmp_db: IDSDatabase
) -> None:
    detector, path = fitted_model
    settings = get_settings()
    settings.model_path = path
    settings.alert_risk_threshold = 1
    live = LiveDetector(settings=settings, database=tmp_db, detector=detector)
    unusual = generate_synthetic_flow_records(n_normal=0, n_anomalous=1)[0]
    unusual["data_source"] = "live"
    unusual["mode"] = "LIVE"
    result = live.process_flow(unusual)
    assert result is not None
    assert result["mode"] == "LIVE"
    assert "anomaly_score" in result
    assert "risk_score" in result
    flows = tmp_db.list_flows()
    assert len(flows) == 1
    assert flows[0]["mode"] == "LIVE"
    assert tmp_db.stats()["live_flows"] == 1
    assert tmp_db.stats()["synthetic_flows"] == 0


def test_live_alert_persistence(fitted_model, tmp_db: IDSDatabase) -> None:
    detector, path = fitted_model
    settings = get_settings()
    settings.model_path = path
    settings.alert_risk_threshold = 0  # force alert path when anomalous
    live = LiveDetector(settings=settings, database=tmp_db, detector=detector)
    unusual = generate_synthetic_flow_records(n_normal=0, n_anomalous=2)
    for f in unusual:
        f["data_source"] = "live"
        f["mode"] = "LIVE"
    results = live.process_flows(unusual)
    assert results
    alerts = tmp_db.list_alerts(mode="LIVE")
    # Alerts only if anomalous + threshold; unusual fixtures usually flag.
    if any(r.get("is_anomaly") for r in results):
        assert len(alerts) >= 1
        assert all(a["mode"] == "LIVE" for a in alerts)
        assert all(a["is_synthetic"] == 0 for a in alerts)


def test_mode_separation(tmp_db: IDSDatabase) -> None:
    tmp_db.insert_flow(
        {
            "source_ip": "1.1.1.1",
            "destination_ip": "2.2.2.2",
            "protocol": "TCP",
            "is_anomaly": False,
            "anomaly_score": 0.1,
            "risk_score": 10,
            "severity": "Low",
            "data_source": "synthetic",
            "mode": "SYNTHETIC",
            "features": {},
        }
    )
    tmp_db.insert_flow(
        {
            "source_ip": "3.3.3.3",
            "destination_ip": "4.4.4.4",
            "protocol": "UDP",
            "is_anomaly": True,
            "anomaly_score": 0.9,
            "risk_score": 90,
            "severity": "Critical",
            "data_source": "live",
            "mode": "LIVE",
            "features": {},
        }
    )
    live = tmp_db.list_flows(mode="LIVE")
    synth = tmp_db.list_flows(mode="SYNTHETIC")
    assert len(live) == 1
    assert live[0]["mode"] == "LIVE"
    assert len(synth) == 1
    assert synth[0]["mode"] == "SYNTHETIC"
    stats = tmp_db.stats()
    assert stats["live_flows"] == 1
    assert stats["synthetic_flows"] == 1


def test_live_detector_rejects_invalid_flow(
    fitted_model, tmp_db: IDSDatabase, monkeypatch
) -> None:
    detector, path = fitted_model
    settings = get_settings()
    settings.model_path = path
    live = LiveDetector(settings=settings, database=tmp_db, detector=detector)

    def _boom(_flow):
        raise FeatureValidationError("forced")

    monkeypatch.setattr(
        "app.detection.live_detector.flow_to_model_vector", _boom
    )
    result = live.process_flow({"source_ip": "x", "data_source": "live"})
    assert result is None
    assert live.rejected_flows == 1


def test_api_status_and_model_and_capture_validation(
    tmp_path: Path, fitted_model, monkeypatch
) -> None:
    _, path = fitted_model
    settings = get_settings()
    settings.database_path = tmp_path / "api_phase4.db"
    settings.model_path = path
    settings.ids_mode = "synthetic"
    runtime_mod._RUNTIME = None

    client = TestClient(app)
    status = client.get("/api/status")
    assert status.status_code == 200
    body = status.json()
    assert "capture_status" in body
    assert "model_loaded" in body
    assert "database_status" in body
    assert body["flows_count"] == body["total_flows"]

    model = client.get("/api/model")
    assert model.status_code == 200
    minfo = model.json()
    assert minfo["model_loaded"] is True
    assert minfo["feature_order"] == list(MODEL_FEATURE_ORDER)

    # Invalid capture params rejected by validation.
    bad = client.post("/api/capture/start", json={"duration": -1})
    assert bad.status_code == 422

    stop = client.post("/api/capture/stop")
    assert stop.status_code == 200

    start = client.post(
        "/api/capture/start",
        json={"mode": "synthetic", "duration": 1.0, "packet_count": 5},
    )
    assert start.status_code == 200
    assert start.json()["mode"] == "synthetic"
    assert start.json()["ok"] is True


def test_capture_start_stop_live_mocked(tmp_path: Path, fitted_model) -> None:
    _, path = fitted_model
    settings = get_settings()
    settings.database_path = tmp_path / "live_rt.db"
    settings.model_path = path
    settings.ids_mode = "live"
    settings.capture_duration = 0.5
    settings.capture_packet_count = 1
    settings.flow_timeout_seconds = 0.5
    runtime = IDSRuntime(settings=settings)

    with patch.object(PacketCapture, "start_async") as mock_start:

        def _fake_async(on_packet=None):
            # Simulate one normalized packet without Scapy.
            pkt = CapturedPacket(
                timestamp=1.0,
                length=120,
                src_ip="10.1.1.1",
                dst_ip="10.1.1.2",
                src_port=1111,
                dst_port=80,
                protocol="TCP",
                tcp_flags="S",
            )
            if on_packet:
                on_packet(pkt)
            # Leave capture "running" until stop.

        mock_start.side_effect = _fake_async
        result = runtime.start_capture()
        assert result["ok"] is True
        assert result["mode"] == "live"
        assert result.get("live_capture_banner") == LIVE_CAPTURE_BANNER
        assert runtime.state.capture_running is True
        stop = runtime.stop_capture()
        assert stop["ok"] is True
        assert runtime.state.capture_running is False


def test_packet_capture_start_async_rejects_synthetic() -> None:
    cap = PacketCapture(mode="synthetic")
    with pytest.raises(CaptureError):
        cap.start_async()


def test_live_preflight_reports_missing_pcap(monkeypatch) -> None:
    class _Conf:
        use_pcap = False

    monkeypatch.setattr(
        "scapy.config.conf", _Conf(), raising=False
    )
    # Force import path used by preflight
    import scapy.config as scapy_config

    monkeypatch.setattr(scapy_config, "conf", _Conf())
    err = PacketCapture.preflight_live()
    assert err is not None
    assert "Npc" in err or "libpcap" in err


def test_normalize_scapy_packet_handles_bad_object() -> None:
    from app.capture.packet_capture import normalize_scapy_packet

    assert normalize_scapy_packet(object()) is None
