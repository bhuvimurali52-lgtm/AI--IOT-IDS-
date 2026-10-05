"""SOC command-center Streamlit dashboard (presentation layer).

Consumes the FastAPI service. Does not retrain models or invent traffic.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

import streamlit as st

from app.core.config import get_settings
from app.dashboard.charts import (
    flow_timeline_figure,
    risk_distribution_figure,
    risk_timeline_figure,
)
from app.dashboard.nav import (
    AUTO_REFRESH_PAGES,
    NAV_EVALUATION,
    NAV_FIREWALL,
    NAV_INVESTIGATION,
    NAV_OVERVIEW,
    NAV_PAGES,
    NAV_SYSTEM,
    NAV_THREAT,
    NAV_XAI,
)
from app.dashboard.components import (
    render_alerts_table,
    render_capture_controls,
    render_evaluation_panel,
    render_explanation_panel,
    render_firewall_findings_brief,
    render_firewall_panel,
    render_flows_table,
    render_metric_cards,
    render_model_panel,
    render_run_security_demo,
    render_safe_demonstration,
    render_security_investigation,
    render_security_overview,
    render_security_timeline,
    render_synthetic_controls,
)
from app.dashboard.services.api_client import DashboardAPIClient
from app.dashboard.services.intelligence import record_ids
from app.dashboard.services.metrics import TIME_RANGE_MINUTES, filter_records, summarize_metrics
from app.dashboard.theme import badge_class, inject_command_center_theme

logger = logging.getLogger(__name__)


def _safe_load(
    client: DashboardAPIClient,
) -> tuple[bool, dict[str, Any], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], str | None]:
    """Fetch dashboard data from the API with graceful degradation."""
    api_online, _ = client.health()
    if not api_online:
        return False, {}, {}, [], [], "FastAPI is offline or unreachable."

    error: str | None = None
    status: dict[str, Any] = {}
    model: dict[str, Any] = {}
    flows: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    try:
        status = client.status()
    except Exception as exc:  # noqa: BLE001
        logger.warning("status fetch failed: %s", exc)
        error = "Unable to load /api/status."
    try:
        model = client.model()
    except Exception as exc:  # noqa: BLE001
        logger.warning("model fetch failed: %s", exc)
        if error is None:
            error = "Unable to load /api/model."
    try:
        flows = client.flows(limit=500)
    except Exception as exc:  # noqa: BLE001
        logger.warning("flows fetch failed: %s", exc)
        if error is None:
            error = "Unable to load /api/flows."
    try:
        alerts = client.alerts(limit=500)
    except Exception as exc:  # noqa: BLE001
        logger.warning("alerts fetch failed: %s", exc)
        if error is None:
            error = "Unable to load /api/alerts."
    return True, status, model, flows, alerts, error


def _apply_filters(
    flows_src: list[dict[str, Any]],
    alerts_src: list[dict[str, Any]],
    filters: dict[str, Any],
    *,
    low_max: int,
    medium_max: int,
    high_max: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    mode_filter = filters["mode"]
    flows = filter_records(
        flows_src,
        mode=mode_filter,
        severity=filters["severity"],
        time_range_label=filters["time_range"],
        low_max=low_max,
        medium_max=medium_max,
        high_max=high_max,
    )
    alerts = filter_records(
        alerts_src,
        mode=mode_filter,
        severity=filters["severity"],
        time_range_label=filters["time_range"],
        low_max=low_max,
        medium_max=medium_max,
        high_max=high_max,
    )
    return flows, alerts


def _sidebar_filters() -> dict[str, Any]:
    """Sidebar nav + display filters. Does not change IDS_MODE."""
    st.sidebar.markdown("### 🛡 AI-IOT SECURITY COMMAND CENTER")
    st.sidebar.caption("Navigation controls the displayed section only.")
    page = st.sidebar.radio("Navigation", list(NAV_PAGES), index=0, key="soc_nav")
    st.sidebar.markdown("---")
    st.sidebar.subheader("Display filters")
    st.sidebar.caption(
        "These filters change what is shown. They do not change IDS capture mode."
    )
    data_filter_label = st.sidebar.selectbox(
        "Data filter",
        ["All", "Synthetic", "Live"],
        index=0,
        key="data_filter",
        help="ALL / SYNTHETIC / LIVE records in the dashboard. Not IDS_MODE.",
    )
    data_map = {"All": "ALL", "Synthetic": "SYNTHETIC", "Live": "LIVE"}
    severity = st.sidebar.selectbox(
        "Severity",
        ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        index=0,
        key="severity_filter",
    )
    time_range_options = list(TIME_RANGE_MINUTES.keys())
    time_range = st.sidebar.selectbox(
        "Time range",
        time_range_options,
        index=time_range_options.index("All time"),
        key="soc_time_range",
    )
    st.sidebar.markdown("---")
    st.sidebar.subheader("Auto-refresh")
    refresh_label = st.sidebar.selectbox(
        "Refresh interval",
        ["OFF", "5 seconds", "10 seconds", "30 seconds"],
        index=2,
        key="refresh_interval",
    )
    refresh_map = {
        "OFF": 0,
        "5 seconds": 5,
        "10 seconds": 10,
        "30 seconds": 30,
    }
    return {
        "page": page,
        "mode": data_map[data_filter_label],
        "severity": severity,
        "time_range": time_range,
        "refresh_seconds": refresh_map[refresh_label],
    }


def _render_command_header(status: dict[str, Any], *, api_online: bool) -> None:
    inject_command_center_theme()
    status = status or {}
    model_ok = bool(status.get("model_loaded")) and api_online
    db_raw = str(status.get("database_status") or "").lower()
    db_ok = api_online and (
        db_raw in {"ok", "connected", ""}
        or (status.get("database_status") is None and bool(status))
    )
    capture_running = bool(status.get("capture_running"))
    mode = str(status.get("ids_mode") or "synthetic").upper()
    if mode not in {"LIVE", "SYNTHETIC"}:
        mode = "SYNTHETIC"
    st.markdown(
        """
        <p class="soc-title">🛡 AI-IOT SECURITY COMMAND CENTER</p>
        <p class="soc-sub">Intelligent anomaly detection • Explainable risk analysis • Firewall security posture</p>
        <p class="soc-disclaimer">
          Anomaly detection based on learned flow behavior; not named-attack classification
          and not a production IDS or enterprise SIEM replacement.
        </p>
        """,
        unsafe_allow_html=True,
    )
    badges = (
        f'<span class="{badge_class(model_ok)}" role="status">MODEL: {"LOADED" if model_ok else "NOT LOADED"}</span>'
        f'<span class="{badge_class(api_online)}" role="status">API: {"ONLINE" if api_online else "OFFLINE"}</span>'
        f'<span class="{badge_class(db_ok)}" role="status">DATABASE: {"CONNECTED" if db_ok else "DISCONNECTED"}</span>'
        f'<span class="{badge_class(not capture_running, warn=capture_running)}" role="status">'
        f'CAPTURE: {"RUNNING" if capture_running else "STOPPED"}</span>'
        f'<span class="soc-badge soc-info" role="status">MODE: {mode}</span>'
    )
    st.markdown(f'<div class="soc-badge-row">{badges}</div>', unsafe_allow_html=True)


def main() -> None:
    st.set_page_config(
        page_title="AI-IoT Security Command Center",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_command_center_theme()
    settings = get_settings()
    client = DashboardAPIClient(settings=settings)
    filters = _sidebar_filters()
    page = str(filters.get("page") or NAV_OVERVIEW)

    api_online, status, model, flows_raw, alerts_raw, error = _safe_load(client)
    capture_mode = str(status.get("ids_mode") or "synthetic").upper()
    if capture_mode not in {"LIVE", "SYNTHETIC"}:
        capture_mode = "SYNTHETIC"
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"**Capture mode (runtime):** `{capture_mode if api_online else 'UNKNOWN'}`")
    st.sidebar.caption(
        "Set by IDS_MODE / the API. The Data filter above does not change capture mode."
    )
    st.sidebar.caption(f"API: `{settings.resolved_dashboard_api_url()}`")

    _render_command_header(status, api_online=api_online)
    if not api_online:
        st.error(
            "FastAPI offline. Start the API before using the dashboard:\n\n"
            f"`uvicorn app.main:app --host 127.0.0.1 --port {settings.api_port}`"
        )

    if error:
        st.warning(error)

    low_max = int(status.get("risk_low_max", settings.risk_low_max))
    medium_max = int(status.get("risk_medium_max", settings.risk_medium_max))
    high_max = int(status.get("risk_high_max", settings.risk_high_max))
    fw_cached = (
        st.session_state.get("fw_assessment")
        if isinstance(st.session_state.get("fw_assessment"), dict)
        else None
    )

    # Manual / expensive actions stay outside the auto-refresh fragment.
    if page == NAV_OVERVIEW:
        render_run_security_demo(
            client,
            api_online=api_online,
            known_flow_ids=sorted(record_ids(flows_raw)),
        )
    if page == NAV_FIREWALL:
        render_firewall_panel(client, api_online=api_online)
        if isinstance(fw_cached, dict):
            render_firewall_findings_brief(fw_cached)
        return
    if page == NAV_INVESTIGATION:
        render_security_investigation(client, flows_raw, api_online=api_online)
        return
    if page == NAV_EVALUATION:
        render_evaluation_panel(client, api_online=api_online)
        return
    if page == NAV_SYSTEM:
        st.subheader("System")
        st.write(f"**Application version:** `{settings.app_version}`")
        st.write(f"**API URL:** `{settings.resolved_dashboard_api_url()}`")
        st.write(f"**IDS mode:** `{capture_mode}`")
        render_model_panel(model or status)
        st.subheader("LIVE CAPTURE STATUS")
        left, right = st.columns(2)
        with left:
            render_capture_controls(client, status, api_online=api_online)
        with right:
            render_synthetic_controls(client, api_online=api_online)
        render_safe_demonstration(client, api_online=api_online)
        return

    def _render_body() -> None:
        _api_online, _status, _model, flows_raw2, alerts_raw2, _error = _safe_load(client)
        flows_src = flows_raw2 if _api_online else flows_raw
        alerts_src = alerts_raw2 if _api_online else alerts_raw
        status_src = _status or status
        flows, alerts = _apply_filters(
            flows_src,
            alerts_src,
            filters,
            low_max=low_max,
            medium_max=medium_max,
            high_max=high_max,
        )
        expl = (
            st.session_state.get("inv_explanation")
            if isinstance(st.session_state.get("inv_explanation"), dict)
            else None
        )
        fw = (
            st.session_state.get("fw_assessment")
            if isinstance(st.session_state.get("fw_assessment"), dict)
            else None
        )

        if page == NAV_XAI:
            render_explanation_panel(client, flows)
            return

        data_ok = bool(_api_online)
        if _error and ("/api/flows" in str(_error) or "/api/status" in str(_error)):
            data_ok = False
            st.error(_error)

        if page == NAV_THREAT:
            st.subheader("Threat Detection")
            if not data_ok:
                st.error(
                    "FastAPI is unavailable. Threat metrics are hidden so zeros "
                    "are not shown as if the database were empty."
                )
                return
            metrics = summarize_metrics(flows)
            render_metric_cards(metrics, alert_count=len(alerts), api_online=data_ok)
            c1, c2 = st.columns(2)
            with c1:
                st.plotly_chart(
                    risk_timeline_figure(flows),
                    use_container_width=True,
                    key="risk_timeline",
                )
            with c2:
                st.plotly_chart(
                    flow_timeline_figure(flows),
                    use_container_width=True,
                    key="flow_timeline",
                )
            st.plotly_chart(
                risk_distribution_figure(
                    flows, low_max=low_max, medium_max=medium_max, high_max=high_max
                ),
                use_container_width=True,
                key="risk_distribution",
            )
            render_alerts_table(alerts)
            render_flows_table(flows)
            return

        render_security_overview(
            status_src,
            flows,
            alerts,
            api_online=data_ok if page == NAV_OVERVIEW else api_online,
            firewall=fw,
        )
        st.markdown("**THREAT ACTIVITY**")
        st.plotly_chart(
            risk_timeline_figure(flows),
            use_container_width=True,
            key="risk_timeline",
        )
        left, right = st.columns(2)
        with left:
            st.plotly_chart(
                risk_distribution_figure(
                    flows, low_max=low_max, medium_max=medium_max, high_max=high_max
                ),
                use_container_width=True,
                key="risk_distribution",
            )
        with right:
            render_security_timeline(
                flows,
                alerts,
                explanation=expl,
                firewall=fw,
            )
        render_alerts_table(alerts)

    refresh_seconds = int(filters["refresh_seconds"])
    use_fragment = page in AUTO_REFRESH_PAGES and refresh_seconds > 0
    if use_fragment:
        try:

            @st.fragment(run_every=timedelta(seconds=refresh_seconds))
            def _auto_body() -> None:
                st.caption(f"Auto-refresh every {refresh_seconds}s")
                _render_body()

            _auto_body()
        except Exception:  # noqa: BLE001
            logger.exception("Auto-refresh fragment unavailable; rendering once")
            _render_body()
    else:
        _render_body()


if __name__ == "__main__":
    main()
