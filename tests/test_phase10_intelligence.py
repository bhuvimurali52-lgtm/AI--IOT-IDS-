"""Phase 10 security-intelligence integration tests (no live firewall, no retrain)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.dashboard.services.intelligence import (
    anomaly_recommendations,
    build_overview,
    build_timeline,
    firewall_recommendations,
    flow_feature_view,
    rank_flows_for_investigation,
    record_ids,
    run_safe_demonstration,
    select_anomalous_flow,
)
from app.explainability.explainer import METHOD_NAME
from app.features.extractor import MODEL_FEATURE_ORDER
from app.firewall.collector import _NETSH_ALLPROFILES
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


class _FakeClient:
    def __init__(
        self,
        *,
        flows: list[dict[str, Any]] | None = None,
        synthetic: dict[str, Any] | None = None,
        explanation: dict[str, Any] | Exception | None = None,
        firewall: dict[str, Any] | Exception | None = None,
        fail_synthetic: bool = False,
    ) -> None:
        self._flows = flows if flows is not None else []
        self._synthetic = synthetic or {
            "ok": True,
            "flows_scored": 10,
            "anomalies_flagged": 5,
            "warning": "SYNTHETIC",
        }
        self._explanation = explanation
        self._firewall = firewall if firewall is not None else {
            "status": "ok",
            "overall_severity": "INFORMATIONAL",
            "read_only": True,
            "assessed_at": "2026-01-01T00:00:00+00:00",
            "findings": [],
        }
        self.fail_synthetic = fail_synthetic
        self.calls: list[str] = []

    def run_synthetic_test(self) -> dict[str, Any]:
        self.calls.append("synthetic")
        if self.fail_synthetic:
            raise RuntimeError("synthetic backend unavailable")
        return dict(self._synthetic)

    def flows(self, *, limit: int = 200, mode: str | None = None) -> list[dict[str, Any]]:
        self.calls.append("flows")
        return list(self._flows)

    def explanation(self, flow_id: int) -> dict[str, Any]:
        self.calls.append(f"explanation:{flow_id}")
        if isinstance(self._explanation, Exception):
            raise self._explanation
        if self._explanation is None:
            raise KeyError("Flow not found")
        return dict(self._explanation)

    def firewall(self) -> dict[str, Any]:
        self.calls.append("firewall")
        if isinstance(self._firewall, Exception):
            raise self._firewall
        return dict(self._firewall)


def _sample_flow(**overrides: Any) -> dict[str, Any]:
    row = {
        "id": 7,
        "timestamp": "2026-01-01T12:00:00+00:00",
        "source_ip": "10.0.0.9",
        "destination_ip": "10.0.0.20",
        "protocol": "TCP",
        "is_anomaly": 1,
        "anomaly_score": 0.4,
        "risk_score": 72,
        "severity": "High",
        "mode": "SYNTHETIC",
        "features": {
            "duration": 1.2,
            "packet_count": 40,
            "byte_count": 8000,
            "packets_per_second": 33.0,
            "bytes_per_second": 6666.0,
            "average_packet_size": 200.0,
            "source_port": 41000,
            "destination_port": 80,
        },
    }
    row.update(overrides)
    return row


def test_unified_overview_loads() -> None:
    overview = build_overview(
        status={"ids_mode": "synthetic", "model_loaded": True},
        flows=[_sample_flow(), _sample_flow(id=8, is_anomaly=0, risk_score=10, severity="Low")],
        alerts=[{"severity": "High", "risk_score": 72}],
        firewall={
            "overall_severity": "INFORMATIONAL",
            "status": "findings",
            "assessed_at": "2026-01-01T12:05:00+00:00",
        },
        api_online=True,
    )
    assert overview["system_mode"] == "SYNTHETIC"
    assert overview["model_status"] == "LOADED"
    assert overview["total_flows"] == 2
    assert overview["normal_flows"] == 1
    assert overview["anomalous_flows"] == 1
    assert overview["total_alerts"] == 1
    assert overview["high_risk_alerts"] == 1
    assert overview["highest_risk"] == 72
    assert "INFORMATIONAL" in overview["firewall_posture"]
    assert overview["overall_security_severity"] == "HIGH"
    assert overview["last_assessment_time"]
    assert overview["read_only_firewall"] is True


def test_empty_database_is_handled() -> None:
    overview = build_overview(status={}, flows=[], alerts=[], firewall=None, api_online=False)
    assert overview["total_flows"] == 0
    assert overview["total_alerts"] == 0
    assert overview["firewall_posture"] == "Not assessed"
    assert build_timeline([], []) == []
    assert select_anomalous_flow([]) is None


def test_security_investigation_feature_view() -> None:
    view = flow_feature_view(_sample_flow())
    assert view["packet_count"] == 40
    assert view["byte_count"] == 8000
    assert view["packets_per_second"] == 33.0
    recs = anomaly_recommendations(_sample_flow())
    assert "Investigate the originating device." in recs
    assert any("not executed" in item.lower() for item in recs)
    assert any("does not stop an attack" in item.lower() for item in recs)


def test_existing_xai_method_unchanged() -> None:
    assert METHOD_NAME == "local_baseline_occlusion"
    assert list(MODEL_FEATURE_ORDER) == EXPECTED_FEATURES


def test_safe_demo_works() -> None:
    client = _FakeClient(
        flows=[_sample_flow()],
        explanation={
            "flow_id": 7,
            "explanation": {
                "method": "local_baseline_occlusion",
                "contributions": [
                    {
                        "feature": "packet_count",
                        "contribution": 0.2,
                        "direction": "toward_anomalous",
                        "rank": 1,
                    }
                ],
            },
        },
        firewall={"status": "ok", "overall_severity": "NONE", "read_only": True},
    )
    result = run_safe_demonstration(client)
    assert result["ok"] is True
    assert result["selected_flow"]["id"] == 7
    assert result["explanation"]["flow_id"] == 7
    assert result["firewall"]["read_only"] is True
    assert "synthetic" in client.calls
    assert "firewall" in client.calls
    assert any(c.startswith("explanation:") for c in client.calls)
    assert "SYNTHETIC" in str(result.get("warning") or "").upper() or "synthetic" in str(result.get("warning") or "").lower()


def test_firewall_integration_recommendations() -> None:
    recs = firewall_recommendations(
        {
            "status": "findings",
            "findings": [
                {
                    "id": "FW-OUTBOUND-ALLOW-001",
                    "title": "Outbound default policy permits traffic",
                    "remediation": "Review outbound defaults.",
                }
            ],
        }
    )
    assert any("organizational requirements" in item for item in recs)
    assert any("egress filtering" in item for item in recs)
    assert any("no firewall changes are performed" in item for item in recs)


def test_missing_flow_is_handled() -> None:
    client = _FakeClient(flows=[], explanation=KeyError("missing"))
    result = run_safe_demonstration(client)
    assert result["selected_flow"] is None
    assert any("No anomalous" in e for e in result["errors"])


def test_api_errors_are_handled_safely() -> None:
    client = _FakeClient(
        flows=[_sample_flow()],
        fail_synthetic=True,
    )
    result = run_safe_demonstration(client)
    assert result["ok"] is False
    assert "Synthetic demonstration failed." in result["errors"]
    blob = str(result)
    assert "Traceback" not in blob
    assert "C:\\Users" not in blob

    client2 = _FakeClient(
        flows=[_sample_flow()],
        explanation=RuntimeError(r"C:\Windows\System32\model.joblib boom"),
        firewall=RuntimeError("netsh stdout dump"),
    )
    result2 = run_safe_demonstration(client2)
    assert result2["ok"] is True
    assert result2["explanation"] is None
    assert result2["firewall"]["read_only"] is True
    assert "C:\\Windows" not in str(result2["errors"])


def test_synthetic_mode_remains_functional() -> None:
    overview = build_overview(
        status={"ids_mode": "synthetic", "model_loaded": True, "last_capture_error": "Npcap missing"},
        flows=[_sample_flow(is_anomaly=0, risk_score=5, severity="Low")],
        alerts=[],
        api_online=True,
    )
    assert overview["system_mode"] == "SYNTHETIC"
    timeline = build_timeline(
        [_sample_flow(is_anomaly=0, risk_score=5, timestamp="2026-01-01T00:00:00Z")],
        [],
    )
    assert timeline[0]["event"] == "Normal flow"


def test_live_mode_overview_does_not_require_firewall_fetch() -> None:
    overview = build_overview(
        status={"ids_mode": "live", "model_loaded": True, "capture_mode": "LIVE"},
        flows=[],
        alerts=[],
        firewall=None,
        api_online=True,
    )
    assert overview["system_mode"] == "LIVE"
    assert overview["firewall_posture"] == "Not assessed"


def test_timeline_does_not_fabricate_events() -> None:
    events = build_timeline(
        [{"id": 1, "is_anomaly": 1}],  # no timestamp
        [{"severity": "High"}],  # no timestamp
        explanation={"flow_id": 1},  # no timestamp
        firewall={"status": "ok"},  # no assessed_at
    )
    assert events == []


def test_no_firewall_modification_in_phase10_sources() -> None:
    assert _NETSH_ALLPROFILES == ("netsh", "advfirewall", "show", "allprofiles")
    intel = Path("app/dashboard/services/intelligence.py").read_text(encoding="utf-8")
    ui = Path("app/dashboard/components/intelligence.py").read_text(encoding="utf-8")
    combined = intel + "\n" + ui
    for banned in (
        "advfirewall set",
        "advfirewall add",
        "advfirewall delete",
        "advfirewall reset",
        "netsh advfirewall enable",
        "netsh advfirewall disable",
    ):
        assert banned not in combined.lower()
    assert "Run Security Demonstration" in ui
    assert "RUN SECURITY DEMO" in ui
    assert "Security Intelligence Overview" in ui
    assert "Security Investigation" in ui


def test_investigation_ranks_newest_high_risk_first() -> None:
    older = _sample_flow(id=1, risk_score=90, timestamp="2026-01-01T00:00:00+00:00")
    newer = _sample_flow(id=9, risk_score=90, timestamp="2026-10-03T12:00:00+00:00")
    normal = _sample_flow(id=8, is_anomaly=0, risk_score=10, timestamp="2026-10-03T13:00:00+00:00")
    ranked = rank_flows_for_investigation([older, normal, newer])
    assert [row["id"] for row in ranked] == [9, 1, 8]
    chosen = select_anomalous_flow([older, normal, newer])
    assert chosen is not None
    assert chosen["id"] == 9
    assert record_ids([older, newer, {"id": "nope"}]) == {1, 9}


def test_dashboard_phase10_imports_and_keys() -> None:
    from app.dashboard.components import (
        render_run_security_demo,
        render_safe_demonstration,
        render_security_investigation,
        render_security_overview,
        render_security_timeline,
    )
    from app.dashboard.streamlit_app import main

    assert callable(main)
    assert callable(render_security_overview)
    assert callable(render_security_investigation)
    assert callable(render_run_security_demo)
    assert callable(render_safe_demonstration)
    assert callable(render_security_timeline)
    keys = [
        "safe_demo_btn",
        "run_security_demo_btn",
        "inv_flow_select",
        "inv_xai_btn",
        "security_event_timeline",
        "inv_xai_chart",
        "demo_xai_chart",
        "xai_contribution_chart",
    ]
    assert len(keys) == len(set(keys))
    src = Path("app/dashboard/streamlit_app.py").read_text(encoding="utf-8")
    assert "render_security_overview" in src
    assert "render_safe_demonstration" in src
    assert "render_run_security_demo" in src
    body = src[src.find("def _render_body") : src.find("if refresh_seconds")]
    assert "run_safe_demonstration" not in body
    assert "render_run_security_demo" not in body
    assert "client.firewall()" not in body


def test_existing_endpoints_remain_functional() -> None:
    client = TestClient(app)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    status = client.get("/api/status")
    assert status.status_code == 200
    model = client.get("/api/model")
    assert model.status_code == 200
    order = model.json().get("feature_order") or model.json().get("model_feature_order")
    assert list(order) == EXPECTED_FEATURES
    missing = client.get("/api/explanation/99999999")
    assert missing.status_code in {404, 400, 503}


def test_model_artifact_not_modified_by_phase10() -> None:
    path = Path("models/anomaly_detector.joblib")
    if not path.exists():
        pytest.skip("models/anomaly_detector.joblib missing")
    before = path.stat().st_mtime
    from app.detection.anomaly_detector import AnomalyDetector

    det = AnomalyDetector.load(path)
    assert det.is_fitted
    assert path.stat().st_mtime == before
