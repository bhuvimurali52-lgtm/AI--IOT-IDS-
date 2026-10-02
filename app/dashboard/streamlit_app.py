"""Phase 5 SOC-style Streamlit dashboard.

Consumes the FastAPI service for status, model metadata, flows, alerts,
and capture/synthetic controls. Does not retrain models or invent traffic.
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
from app.dashboard.components import (
    render_alerts_table,
    render_capture_controls,
    render_evaluation_panel,
    render_explanation_panel,
    render_firewall_panel,
    render_flows_table,
    render_header,
    render_health_panel,
    render_metric_cards,
    render_model_panel,
    render_sidebar_filters,
    render_synthetic_controls,
    render_system_state,
)
from app.dashboard.services.api_client import DashboardAPIClient
from app.dashboard.services.metrics import filter_records, summarize_metrics

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


def main() -> None:
    st.set_page_config(
        page_title="IoT IDS SOC Dashboard",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    settings = get_settings()
    client = DashboardAPIClient(settings=settings)

    render_header()
    filters = render_sidebar_filters()
    st.sidebar.caption(f"API: `{settings.resolved_dashboard_api_url()}`")
    st.sidebar.caption(
        "Start FastAPI with the same API_PORT as DASHBOARD_API_URL. "
        "If /api/model returns 404, a stale Phase 3 process is likely on that port — "
        "stop it and restart uvicorn with the current Phase 5 code."
    )

    refresh_seconds = int(filters["refresh_seconds"])

    # Load once for header/status/controls so Capture Controls is not inside
    # the auto-refresh fragment (which can duplicate that section).
    api_online, status, model, flows_raw, alerts_raw, error = _safe_load(client)
    if not api_online:
        st.error(
            "FastAPI offline. Start the API before using the dashboard:\n\n"
            f"`uvicorn app.main:app --host 127.0.0.1 --port {settings.api_port}`"
        )
        render_system_state({}, api_online=False)
        render_health_panel({}, api_online=False)
        render_metric_cards(
            {
                "total_flows": 0,
                "normal_flows": 0,
                "anomalous_flows": 0,
                "max_risk_score": 0,
                "anomaly_rate": 0.0,
            },
            0,
        )
        left, right = st.columns(2)
        with left:
            render_capture_controls(client, {}, api_online=False)
        with right:
            render_synthetic_controls(client, api_online=False)
        render_firewall_panel(client, api_online=False)
        st.info("No network flows detected yet.")
        st.info("No alerts detected.")
        return

    if error:
        st.warning(error)

    low_max = int(status.get("risk_low_max", settings.risk_low_max))
    medium_max = int(status.get("risk_medium_max", settings.risk_medium_max))
    high_max = int(status.get("risk_high_max", settings.risk_high_max))

    render_system_state(status, api_online=True)
    render_health_panel(status, api_online=True)

    left, right = st.columns(2)
    with left:
        render_capture_controls(client, status, api_online=True)
    with right:
        render_synthetic_controls(client, api_online=True)
    render_firewall_panel(client, api_online=True)

    def _render_body() -> None:
        _api_online, _status, _model, flows_raw2, alerts_raw2, _error = _safe_load(client)
        flows_src = flows_raw2 if _api_online else flows_raw
        alerts_src = alerts_raw2 if _api_online else alerts_raw
        model_src = _model or model
        status_src = _status or status

        mode_filter = filters["mode"]
        api_mode = mode_filter if mode_filter in {"LIVE", "SYNTHETIC"} else None
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
        if api_mode == "LIVE":
            flows = [f for f in flows if str(f.get("mode")).upper() == "LIVE"]
            alerts = [a for a in alerts if str(a.get("mode")).upper() == "LIVE"]

        metrics = summarize_metrics(flows)
        render_metric_cards(metrics, alert_count=len(alerts))

        if str(status_src.get("ids_mode", "")).lower() == "synthetic" or any(
            str(f.get("mode")).upper() == "SYNTHETIC" for f in flows[:20]
        ):
            st.warning(
                "SYNTHETIC records may be present. They are local fixtures, "
                "not real captured packets."
            )

        st.subheader("Analytics")
        c1, c2 = st.columns(2)
        with c1:
            st.plotly_chart(
                flow_timeline_figure(flows),
                use_container_width=True,
                key="flow_timeline",
            )
        with c2:
            st.plotly_chart(
                risk_timeline_figure(flows),
                use_container_width=True,
                key="risk_timeline",
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
        render_explanation_panel(client, flows)
        render_evaluation_panel(client, api_online=True)
        render_model_panel(model_src or status_src)

    if refresh_seconds > 0:
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
