"""Phase 9 read-only firewall posture tests.

Never inspects or modifies the host Windows Firewall. Collector I/O is mocked.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.features.extractor import MODEL_FEATURE_ORDER
from app.firewall.analyzer import analyze_snapshot
from app.firewall.checker import (
    FirewallChecker,
    assessment_to_public_dict,
)
from app.firewall.collector import (
    _NETSH_ALLPROFILES,
    FirewallCollector,
    parse_netsh_allprofiles,
)
from app.firewall.models import FirewallProfileStatus, FirewallSnapshot
from app.main import app


SAMPLE_NETSH = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
"""

RAW_NETSH_DUMP = (
    "Domain Profile Settings:\n"
    "State ON\n"
    "Firewall Policy BlockInbound,AllowOutbound\n"
    r"C:\Windows\System32\netsh.exe"
)

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


@pytest.fixture(autouse=True)
def _block_real_firewall_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    def _blocked(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("tests must not invoke real firewall commands")

    monkeypatch.setattr("app.firewall.collector.subprocess.run", _blocked)


def _profile(
    name: str,
    *,
    enabled: bool | None = True,
    inbound: str | None = "block",
    outbound: str | None = "allow",
) -> FirewallProfileStatus:
    return FirewallProfileStatus(
        name=name,
        enabled=enabled,
        inbound_default=inbound,
        outbound_default=outbound,
    )


def _snapshot(
    *,
    status: str = "ok",
    available: bool = True,
    profiles: list[FirewallProfileStatus] | None = None,
    errors: list[str] | None = None,
    platform: str = "Windows",
) -> FirewallSnapshot:
    return FirewallSnapshot(
        platform=platform,
        assessed_at="2026-01-01T00:00:00+00:00",
        collection_status=status,
        firewall_available=available,
        profiles=profiles or [],
        collection_errors=errors or [],
    )


def _healthy_snapshot() -> FirewallSnapshot:
    return _snapshot(
        profiles=[
            _profile("Domain"),
            _profile("Private"),
            _profile("Public"),
        ]
    )


class _StubCollector:
    def __init__(self, payload: Any) -> None:
        self.payload = payload
        self.calls = 0

    def collect(self) -> Any:
        self.calls += 1
        return self.payload


def _install_collector(monkeypatch: pytest.MonkeyPatch, payload: Any) -> _StubCollector:
    stub = _StubCollector(payload)

    class _Factory:
        def __init__(self) -> None:
            self._stub = stub

        def collect(self) -> Any:
            return self._stub.collect()

    monkeypatch.setattr("app.firewall.checker.FirewallCollector", _Factory)
    return stub


def _assess(snapshot: FirewallSnapshot) -> Any:
    return FirewallChecker(collector=_StubCollector(snapshot)).assess()


def test_healthy_enabled_profiles() -> None:
    assessment = analyze_snapshot(_healthy_snapshot())
    assert assessment.firewall_available is True
    assert assessment.status in {"ok", "findings"}
    high = [f for f in assessment.findings if f.severity in {"HIGH", "CRITICAL"}]
    assert high == []
    assert assessment.overall_severity in {"NONE", "INFORMATIONAL"}
    assert assessment.read_only is True


def test_all_profiles_disabled_is_critical() -> None:
    snapshot = _snapshot(
        profiles=[
            _profile("Domain", enabled=False),
            _profile("Private", enabled=False),
            _profile("Public", enabled=False),
        ]
    )
    assessment = analyze_snapshot(snapshot)
    assert assessment.overall_severity == "CRITICAL"
    assert any(f.id == "FW-DISABLED-001" for f in assessment.findings)


def test_public_profile_disabled_is_high() -> None:
    snapshot = _snapshot(
        profiles=[
            _profile("Domain"),
            _profile("Private"),
            _profile("Public", enabled=False),
        ]
    )
    assessment = analyze_snapshot(snapshot)
    assert assessment.overall_severity == "HIGH"
    assert any(f.id == "FW-PUBLIC-OFF-001" for f in assessment.findings)


def test_private_profile_disabled_is_high() -> None:
    snapshot = _snapshot(
        profiles=[
            _profile("Domain"),
            _profile("Private", enabled=False),
            _profile("Public"),
        ]
    )
    assessment = analyze_snapshot(snapshot)
    assert assessment.overall_severity == "HIGH"
    assert any(f.id == "FW-PRIVATE-OFF-001" for f in assessment.findings)


def test_domain_profile_disabled_is_high() -> None:
    snapshot = _snapshot(
        profiles=[
            _profile("Domain", enabled=False),
            _profile("Private"),
            _profile("Public"),
        ]
    )
    assessment = analyze_snapshot(snapshot)
    assert assessment.overall_severity == "HIGH"
    assert any(f.id == "FW-DOMAIN-OFF-001" for f in assessment.findings)


def test_inbound_default_allow_is_high() -> None:
    snapshot = _snapshot(
        profiles=[
            _profile("Domain"),
            _profile("Private"),
            _profile("Public", inbound="allow"),
        ]
    )
    assessment = analyze_snapshot(snapshot)
    assert assessment.overall_severity == "HIGH"
    assert any(f.id == "FW-INBOUND-ALLOW-001" for f in assessment.findings)


def test_outbound_default_allow_is_informational() -> None:
    snapshot = _snapshot(
        profiles=[
            _profile("Domain", outbound="allow"),
            _profile("Private", outbound="allow"),
            _profile("Public", outbound="allow"),
        ]
    )
    assessment = analyze_snapshot(snapshot)
    outbound = [f for f in assessment.findings if f.id == "FW-OUTBOUND-ALLOW-001"]
    assert len(outbound) == 1
    assert outbound[0].severity == "INFORMATIONAL"


def test_unsupported_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.firewall.collector.platform.system", lambda: "Linux")
    snapshot = FirewallCollector().collect()
    assert snapshot.collection_status == "unsupported_platform"
    assert snapshot.firewall_available is False
    assessment = analyze_snapshot(snapshot)
    assert assessment.status == "incomplete"
    assert assessment.overall_severity == "MEDIUM"


def test_netsh_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.firewall.collector.platform.system", lambda: "Windows")
    monkeypatch.setattr("app.firewall.collector.shutil.which", lambda _name: None)
    snapshot = FirewallCollector().collect()
    assert snapshot.collection_status == "command_unavailable"
    assert snapshot.firewall_available is False


def test_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.firewall.collector.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "app.firewall.collector.shutil.which", lambda _name: "netsh"
    )

    def _timeout(*_a: Any, **_k: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="netsh", timeout=15)

    monkeypatch.setattr("app.firewall.collector.subprocess.run", _timeout)
    snapshot = FirewallCollector().collect()
    assert snapshot.collection_status == "timeout"


def test_permission_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.firewall.collector.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "app.firewall.collector.shutil.which", lambda _name: "netsh"
    )

    def _denied(*_a: Any, **_k: Any) -> None:
        raise PermissionError("access denied")

    monkeypatch.setattr("app.firewall.collector.subprocess.run", _denied)
    snapshot = FirewallCollector().collect()
    assert snapshot.collection_status == "permission_denied"


def test_malformed_collector_result() -> None:
    assessment = FirewallChecker(collector=_StubCollector({"unexpected": True})).assess()
    assert assessment.status == "incomplete"
    assert any("Malformed" in err for err in assessment.collection_errors) or any(
        f.id == "FW-COLLECT-001" for f in assessment.findings
    )


def test_deterministic_repeated_analysis() -> None:
    snapshot = _snapshot(
        profiles=[
            _profile("Domain", enabled=False),
            _profile("Private"),
            _profile("Public", inbound="allow"),
        ]
    )
    first = analyze_snapshot(snapshot)
    second = analyze_snapshot(snapshot)
    assert [f.id for f in first.findings] == [f.id for f in second.findings]
    assert [f.severity for f in first.findings] == [f.severity for f in second.findings]
    assert first.overall_severity == second.overall_severity
    assert first.status == second.status


def test_duplicate_finding_prevention() -> None:
    snapshot = _snapshot(
        profiles=[
            _profile("Domain"),
            _profile("Private"),
            _profile("Public", enabled=False),
            _profile("Public", enabled=False),
        ]
    )
    assessment = analyze_snapshot(snapshot)
    public_off = [f for f in assessment.findings if f.id == "FW-PUBLIC-OFF-001"]
    assert len(public_off) == 1
    ids = [f.id for f in assessment.findings]
    assert len(ids) == len(set(ids))


def test_public_assessment_does_not_expose_raw_subprocess_output() -> None:
    snapshot = _snapshot(
        status="parse_failed",
        available=False,
        errors=[RAW_NETSH_DUMP, "stdout: Domain Profile Settings:"],
    )
    payload = assessment_to_public_dict(_assess(snapshot))
    blob = str(payload).lower()
    assert "domain profile settings" not in blob
    assert "blockinbound" not in blob
    assert "stdout" not in blob


def test_public_assessment_does_not_expose_filesystem_paths() -> None:
    snapshot = _snapshot(
        status="collection_failed",
        available=False,
        errors=[r"failed C:\Windows\System32\netsh.exe /home/user/ids.db"],
    )
    payload = assessment_to_public_dict(_assess(snapshot))
    blob = str(payload)
    assert r"C:\Windows" not in blob
    assert "/home/user" not in blob
    assert "System32\\netsh.exe" not in blob


def test_read_only_remains_true() -> None:
    payload = assessment_to_public_dict(_assess(_healthy_snapshot()))
    assert payload["read_only"] is True
    assert FirewallChecker(collector=_StubCollector(_healthy_snapshot())).assess().read_only is True


def test_api_firewall_returns_200_for_successful_assessment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_collector(monkeypatch, _healthy_snapshot())
    client = TestClient(app)
    resp = client.get("/api/firewall")
    assert resp.status_code == 200
    body = resp.json()
    assert body["read_only"] is True
    assert body["status"] in {"ok", "findings"}
    assert "rule_count" not in body


def test_api_firewall_returns_503_for_incomplete_collection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_collector(
        monkeypatch,
        _snapshot(status="timeout", available=False, errors=["Firewall inspection timed out."]),
    )
    client = TestClient(app)
    resp = client.get("/api/firewall")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "incomplete"
    assert body["read_only"] is True


def test_existing_api_behavior_remains_unaffected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_collector(monkeypatch, _healthy_snapshot())
    client = TestClient(app)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok", "service": "iot-ids"}
    status = client.get("/api/status")
    assert status.status_code == 200
    assert "ids_mode" in status.json()
    model = client.get("/api/model")
    assert model.status_code == 200
    info = model.json()
    assert list(info.get("feature_order") or info.get("model_feature_order")) == list(
        MODEL_FEATURE_ORDER
    )
    assert list(MODEL_FEATURE_ORDER) == EXPECTED_FEATURES
    fw = client.get("/api/firewall")
    assert fw.status_code in {200, 503}


def test_parse_netsh_sample_without_subprocess() -> None:
    profiles = parse_netsh_allprofiles(SAMPLE_NETSH)
    assert {p.name for p in profiles} == {"Domain", "Private", "Public"}
    assert all(p.enabled is True for p in profiles)
    assert all(p.inbound_default == "block" for p in profiles)
    assert all(p.outbound_default == "allow" for p in profiles)


def test_collector_uses_fixed_read_only_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.firewall.collector.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "app.firewall.collector.shutil.which", lambda _name: "netsh"
    )
    captured: dict[str, Any] = {}

    def _fake_run(**kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            args=kwargs.get("args") or [],
            returncode=0,
            stdout=SAMPLE_NETSH,
            stderr="",
        )

    monkeypatch.setattr("app.firewall.collector.subprocess.run", _fake_run)
    snapshot = FirewallCollector().collect()
    assert snapshot.collection_status == "ok"
    assert captured.get("args") == list(_NETSH_ALLPROFILES)
    assert captured.get("shell") in {None, False}
    assert _NETSH_ALLPROFILES == ("netsh", "advfirewall", "show", "allprofiles")
    for verb in ("set", "add", "delete", "reset", "enable", "disable"):
        assert verb not in _NETSH_ALLPROFILES


def test_snapshot_does_not_include_rule_count() -> None:
    data = _healthy_snapshot().to_dict()
    assert "rule_count" not in data


def test_firewall_source_has_no_modifying_commands() -> None:
    root = Path("app/firewall")
    combined = "\n".join(p.read_text(encoding="utf-8") for p in root.glob("*.py"))
    assert "â€" not in combined
    assert "shell=True" not in combined
    assert "advfirewall show allprofiles" in combined
    for banned in (
        "advfirewall set",
        "advfirewall add",
        "advfirewall delete",
        "advfirewall reset",
        "firewall add",
        "netsh advfirewall set",
        "netsh advfirewall add",
        "netsh advfirewall delete",
        "netsh advfirewall reset",
        "netsh advfirewall enable",
        "netsh advfirewall disable",
    ):
        assert banned not in combined.lower()


def test_dashboard_audit_is_click_only_and_caption_is_correct() -> None:
    panel = Path("app/dashboard/components/firewall.py").read_text(encoding="utf-8")
    app_src = Path("app/dashboard/streamlit_app.py").read_text(encoding="utf-8")
    assert "â€" not in panel
    assert "Read-only security posture assessment" in panel
    assert "no firewall changes are performed." in panel
    assert 'st.button(\n        "Run firewall posture audit"' in panel or (
        '"Run firewall posture audit"' in panel
    )
    assert panel.index("Run firewall posture audit") < panel.index("client.firewall()")
    assert "if run:" in panel
    body = app_src[app_src.find("def _render_body") : app_src.find("if refresh_seconds")]
    assert "render_firewall_panel" not in body
    assert "render_firewall_panel" in app_src
