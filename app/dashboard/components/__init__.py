"""Streamlit UI components for the SOC dashboard."""

from __future__ import annotations

import logging
from typing import Any, Mapping, Sequence

import pandas as pd
import streamlit as st

from app.dashboard.components.evaluation import render_evaluation_panel
from app.dashboard.components.firewall import render_firewall_panel
from app.dashboard.components.intelligence import (
    render_firewall_findings_brief,
    render_run_security_demo,
    render_safe_demonstration,
    render_security_investigation,
    render_security_overview,
    render_security_timeline,
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
from app.dashboard.services.metrics import TIME_RANGE_MINUTES
from app.dashboard.theme import badge_class, inject_command_center_theme

logger = logging.getLogger(__name__)

__all__ = [
    "NAV_EVALUATION",
    "NAV_FIREWALL",
    "NAV_INVESTIGATION",
    "NAV_OVERVIEW",
    "NAV_PAGES",
    "NAV_SYSTEM",
    "NAV_THREAT",
    "NAV_XAI",
    "AUTO_REFRESH_PAGES",
    "render_alerts_table",
    "render_capture_controls",
    "render_evaluation_panel",
    "render_explanation_panel",
    "render_firewall_findings_brief",
    "render_firewall_panel",
    "render_flows_table",
    "render_header",
    "render_health_panel",
    "render_metric_cards",
    "render_model_panel",
    "render_run_security_demo",
    "render_safe_demonstration",
    "render_security_investigation",
    "render_security_overview",
    "render_security_timeline",
    "render_sidebar_filters",
    "render_synthetic_controls",
    "render_system_state",
]


def render_header(
    status: Mapping[str, Any] | None = None,
    *,
    api_online: bool = False,
) -> None:
    inject_command_center_theme()
    status = status or {}
    model_ok = bool(status.get("model_loaded")) and api_online
    db_raw = str(status.get("database_status") or "").lower()
    db_ok = api_online and (
        db_raw in {"ok", "connected", ""} or (status.get("database_status") is None and bool(status))
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


def render_system_state(status: Mapping[str, Any], *, api_online: bool) -> None:
    model = "LOADED" if status.get("model_loaded") else "NOT LOADED"
    capture = "RUNNING" if status.get("capture_running") else "STOPPED"
    mode = str(status.get("capture_mode") or status.get("ids_mode") or "SYNTHETIC").upper()
    db_raw = str(status.get("database_status") or "").lower()
    database = "CONNECTED" if api_online and db_raw in {"ok", "connected"} else (
        "DISCONNECTED" if not api_online else "CONNECTED" if db_raw else "DISCONNECTED"
    )
    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(f"**MODEL:** `{model}`")
    c2.markdown(f"**CAPTURE:** `{capture}`")
    c3.markdown(f"**MODE:** `{mode}`")
    c4.markdown(f"**DATABASE:** `{database}`")


def render_health_panel(status: Mapping[str, Any], *, api_online: bool) -> None:
    st.subheader("System Health")
    h1, h2, h3, h4 = st.columns(4)
    h1.metric("FastAPI", "ONLINE" if api_online else "OFFLINE")
    db_ok = api_online and str(status.get("database_status") or "").lower() in {
        "ok",
        "connected",
        "",
    }
    # When API is online and returns status, treat DB as connected unless marked otherwise.
    if api_online and status.get("database_status") is None and status:
        db_ok = True
    h2.metric("Database", "CONNECTED" if db_ok else "DISCONNECTED")
    h3.metric("Model", "LOADED" if status.get("model_loaded") else "NOT LOADED")
    h4.metric(
        "Capture",
        "RUNNING" if status.get("capture_running") else "STOPPED",
    )


def render_metric_cards(
    metrics: Mapping[str, Any],
    alert_count: int,
    *,
    api_online: bool = True,
) -> None:
    st.subheader("Operational Metrics")
    if not api_online:
        st.error(
            "FastAPI is unavailable. Metric cards are hidden so zeros are not shown "
            "as if the database were empty."
        )
        return
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Total Flows", int(metrics.get("total_flows", 0)))
    m2.metric("Normal Flows", int(metrics.get("normal_flows", 0)))
    m3.metric("Anomalous Flows", int(metrics.get("anomalous_flows", 0)))
    m4.metric("Active Alerts", int(alert_count))
    m5.metric("Highest Risk", int(metrics.get("max_risk_score", 0)))
    m6.metric("ANOMALY RATE", f"{float(metrics.get('anomaly_rate', 0.0)):.2f}%")


def render_sidebar_filters() -> dict[str, Any]:
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


def _is_npcap_limitation_message(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(
        token in lowered
        for token in ("npcap", "libpcap", "npc provider", "winpcap")
    )


def render_capture_controls(
    client: Any,
    status: Mapping[str, Any],
    *,
    api_online: bool,
) -> None:
    st.subheader("Capture Controls")
    ids_mode = str(status.get("ids_mode") or "synthetic").lower()
    live_mode = ids_mode == "live"
    iface = status.get("capture_interface") or "default"
    st.write(
        f"**Interface:** `{iface}`  |  "
        f"**Capture status:** `{'RUNNING' if status.get('capture_running') else 'STOPPED'}`  |  "
        f"**Configured mode:** `{ids_mode.upper()}`"
    )

    if live_mode:
        st.info(
            "Live capture monitors traffic visible to the selected local network "
            "interface. Use only on systems/networks you are authorized to monitor."
        )
        err = status.get("last_capture_error")
        if err:
            st.error(str(err))
            if _is_npcap_limitation_message(str(err)):
                st.warning("Live capture unavailable — verify Npcap and permissions.")
    else:
        st.info(
            "SYNTHETIC mode does not require live packet capture or Npcap. "
            "Use Synthetic Test for SAFE TEST fixtures."
        )

    b1, b2, b3 = st.columns(3)
    with b1:
        if st.button(
            "START LIVE CAPTURE",
            key="start_live_capture_btn",
            use_container_width=True,
            disabled=not api_online,
        ):
            try:
                result = client.start_capture(
                    {
                        "mode": "live",
                        "duration": 30.0,
                        "packet_count": 200,
                    }
                )
                if result.get("ok"):
                    st.success("LIVE capture started.")
                    if result.get("live_capture_banner"):
                        st.error(str(result["live_capture_banner"]))
                else:
                    err = result.get("error") or "Capture failed to start"
                    st.error(err)
                    if _is_npcap_limitation_message(str(err)):
                        st.warning(
                            "Live capture unavailable — verify Npcap and permissions."
                        )
                if result.get("authorization_notice"):
                    st.info(result["authorization_notice"])
            except Exception as exc:  # noqa: BLE001
                logger.exception("Live capture start failed")
                st.error("Unable to start live capture.")
                st.caption(str(exc))
                st.warning(
                    "Live capture unavailable — verify Npcap and permissions."
                )
    with b2:
        if st.button(
            "STOP LIVE CAPTURE",
            key="stop_live_capture_btn",
            use_container_width=True,
            disabled=not api_online,
        ):
            try:
                result = client.stop_capture()
                if result.get("ok"):
                    st.info("Capture stop requested.")
                else:
                    st.error(result.get("error") or "Stop failed")
            except Exception as exc:  # noqa: BLE001
                logger.exception("Live capture stop failed")
                st.error("Unable to stop capture.")
                st.caption(str(exc))
    with b3:
        if st.button("REFRESH NOW", key="capture_refresh_btn", use_container_width=True):
            st.rerun()


def render_synthetic_controls(client: Any, *, api_online: bool) -> None:
    st.subheader("SAFE SYNTHETIC TEST")
    st.caption(
        "Generates local synthetic fixtures only. No real network traffic."
    )
    if st.button(
        "RUN SYNTHETIC TEST",
        key="run_synthetic_test_btn",
        use_container_width=True,
        disabled=not api_online,
    ):
        try:
            result = client.run_synthetic_test()
            preds = result.get("predictions") or []
            anomalies = sum(1 for p in preds if p.get("is_anomaly"))
            alerts = sum(1 for p in preds if p.get("alert"))
            st.warning(result.get("warning") or "Synthetic test complete (SYNTHETIC).")
            c1, c2, c3 = st.columns(3)
            c1.metric("Flows generated", int(result.get("flows_scored") or len(preds)))
            c2.metric("Anomalies detected", int(result.get("anomalies_flagged") or anomalies))
            c3.metric("Alerts generated", alerts)
            st.success("All generated records are marked SYNTHETIC.")
        except Exception as exc:  # noqa: BLE001
            logger.exception("Synthetic test failed")
            st.error("Synthetic test failed.")
            st.caption(str(exc))


def render_model_panel(model: Mapping[str, Any]) -> None:
    st.subheader("Model Information")
    if not model:
        st.warning("Model metadata unavailable.")
        return
    c1, c2, c3 = st.columns(3)
    c1.write(f"**Model:** {model.get('model_type', 'Isolation Forest')}")
    c1.write(f"**Training samples:** {model.get('n_training_samples', '—')}")
    c2.write(f"**Features:** {model.get('n_features', '—')}")
    c2.write(f"**n_estimators:** {model.get('n_estimators', '—')}")
    c3.write(f"**contamination:** {model.get('contamination', '—')}")
    c3.write(f"**random_state:** {model.get('random_state', '—')}")
    order = model.get("feature_order") or model.get("model_feature_order") or []
    st.markdown("**Feature order:**")
    st.code("\n".join(str(x) for x in order) if order else "(unavailable)")
    if model.get("limitation"):
        st.caption(str(model["limitation"]))


def _is_demo_record(row: Mapping[str, Any]) -> bool:
    started = str(st.session_state.get("demo_started_at") or "")
    if started:
        ts = str(row.get("timestamp") or "")
        mode = str(row.get("mode") or "").upper()
        if ts and ts >= started and mode in {"", "SYNTHETIC"}:
            return True
    raw_ids = st.session_state.get("demo_new_flow_ids") or []
    ids: set[int] = set()
    for value in raw_ids:
        try:
            ids.add(int(value))
        except (TypeError, ValueError):
            continue
    try:
        rid = int(row.get("id")) if row.get("id") is not None else None
    except (TypeError, ValueError):
        rid = None
    return rid in ids if rid is not None else False


def render_alerts_table(alerts: Sequence[Mapping[str, Any]]) -> None:
    st.subheader("Recent Alerts")
    if not alerts:
        st.info("No alerts detected.")
        return
    rows = []
    for a in alerts:
        sev = str(a.get("severity") or "").upper()
        is_new = _is_demo_record(a)
        rows.append(
            {
                "ID": a.get("id"),
                "New": "DEMO" if is_new else "",
                "Time": a.get("timestamp"),
                "Source": a.get("source_ip"),
                "Destination": a.get("destination_ip"),
                "Protocol": a.get("protocol"),
                "Anomaly Score": a.get("anomaly_score"),
                "Risk": a.get("risk_score"),
                "Severity": a.get("severity"),
                "Mode": a.get("mode"),
                "_sev": sev,
                "_new": "DEMO" if is_new else "",
            }
        )
    rows.sort(key=lambda r: (r["_new"] == "DEMO", str(r.get("Time") or "")), reverse=True)
    frame = pd.DataFrame(rows)

    def _style_severity(series: pd.Series) -> list[str]:
        styles = []
        for val in series:
            u = str(val).upper()
            if u == "CRITICAL":
                styles.append("background-color: #fecaca; font-weight: 700;")
            elif u == "HIGH":
                styles.append("background-color: #ffedd5; font-weight: 600;")
            else:
                styles.append("")
        return styles

    def _style_new(series: pd.Series) -> list[str]:
        return [
            "background-color: #fde68a; font-weight: 700;" if str(val) == "DEMO" else ""
            for val in series
        ]

    display = frame.drop(columns=["_sev", "_new"])
    try:
        styled = display.style.apply(_style_severity, subset=["Severity"]).apply(
            _style_new, subset=["New"]
        )
        st.dataframe(styled, use_container_width=True, hide_index=True)
    except Exception:  # noqa: BLE001
        st.dataframe(display, use_container_width=True, hide_index=True)


def render_flows_table(flows: Sequence[Mapping[str, Any]]) -> None:
    st.subheader("Recent Flows")
    if not flows:
        st.info("No network flows detected yet.")
        return
    rows = []
    for f in flows:
        is_anom = f.get("is_anomaly") in (1, True, "1", "true", "True")
        is_new = _is_demo_record(f)
        sev = str(f.get("severity") or "").upper()
        rows.append(
            {
                "ID": f.get("id"),
                "New": "DEMO" if is_new else "",
                "Timestamp": f.get("timestamp"),
                "Source IP": f.get("source_ip"),
                "Destination IP": f.get("destination_ip"),
                "Protocol": f.get("protocol"),
                "Packets": f.get("packet_count"),
                "Bytes": f.get("byte_count"),
                "Anomaly": "YES" if is_anom else "NO",
                "Anomaly Score": f.get("anomaly_score"),
                "Risk": f.get("risk_score"),
                "Severity": f.get("severity"),
                "Mode": f.get("mode"),
                "_anom": is_anom,
                "_sev": sev,
                "_new": is_new,
            }
        )
    rows.sort(
        key=lambda r: (
            bool(r["_new"]),
            bool(r["_anom"]),
            int(r.get("Risk") or 0),
            str(r.get("Timestamp") or ""),
        ),
        reverse=True,
    )
    frame = pd.DataFrame(rows)

    def _style_anomaly(series: pd.Series) -> list[str]:
        styles = []
        for val in series:
            if str(val).upper() == "YES":
                styles.append("background-color: #ffedd5; font-weight: 700;")
            else:
                styles.append("")
        return styles

    def _style_severity(series: pd.Series) -> list[str]:
        styles = []
        for val in series:
            u = str(val).upper()
            if u == "CRITICAL":
                styles.append("background-color: #fecaca; font-weight: 700;")
            elif u == "HIGH":
                styles.append("background-color: #ffedd5; font-weight: 600;")
            else:
                styles.append("")
        return styles

    def _style_new(series: pd.Series) -> list[str]:
        return [
            "background-color: #fde68a; font-weight: 700;" if str(val) == "DEMO" else ""
            for val in series
        ]

    display = frame.drop(columns=["_anom", "_sev", "_new"])
    try:
        styled = (
            display.style.apply(_style_anomaly, subset=["Anomaly"])
            .apply(_style_severity, subset=["Severity"])
            .apply(_style_new, subset=["New"])
        )
        st.dataframe(styled, use_container_width=True, hide_index=True)
    except Exception:  # noqa: BLE001
        st.dataframe(display, use_container_width=True, hide_index=True)


def render_explanation_panel(client: Any, flows: Sequence[Mapping[str, Any]]) -> None:
    """AI Explanation section for a selected flow."""
    from app.dashboard.charts import explanation_contribution_figure

    st.subheader("🧠 WHY WAS THIS FLOW FLAGGED?")
    st.caption(
        "Positive contribution indicates that the feature increased deviation "
        "from the learned normal baseline. This is a local baseline-occlusion "
        "explanation, not a causal or exact Shapley attribution. "
        "Anomalous selections load the existing /api/explanation immediately."
    )
    if not flows:
        st.info("No network flows detected yet.")
        return

    from app.dashboard.services.intelligence import rank_flows_for_investigation

    ranked = rank_flows_for_investigation(flows)
    demo_ids = {int(x) for x in (st.session_state.get("demo_new_flow_ids") or []) if str(x).isdigit() or isinstance(x, int)}
    labeled = []
    for f in ranked:
        fid = f.get("id")
        if fid is None:
            continue
        is_anom = f.get("is_anomaly") in (1, True, "1", "true", "True")
        tag = "ANOMALOUS" if is_anom else "NORMAL"
        try:
            fid_int = int(fid)
        except (TypeError, ValueError):
            continue
        marker = " | DEMO NEW" if fid_int in demo_ids else ""
        mode = f.get("mode", "")
        labeled.append(
            (
                f"#{fid} | {tag}{marker} | {f.get('source_ip')} → {f.get('destination_ip')} | "
                f"{mode} | risk={f.get('risk_score')}",
                fid_int,
                is_anom,
            )
        )
    if not labeled:
        st.info("No explainable flows with IDs are available yet.")
        return

    anomalous_opts = [item for item in labeled if item[2]]
    options = anomalous_opts or labeled
    labels = [item[0] for item in options]
    preferred = st.session_state.get("xai_flow_id")
    index = 0
    if preferred is not None:
        for i, item in enumerate(options):
            if item[1] == int(preferred):
                index = i
                break
    if st.session_state.pop("xai_select_pending", False) and labels:
        st.session_state["xai_flow_select"] = labels[index]
    selected_label = st.selectbox(
        "Select flow to explain",
        labels,
        index=index,
        key="xai_flow_select",
    )
    selected_id = next(item[1] for item in options if item[0] == selected_label)
    selected_anom = next(item[2] for item in options if item[0] == selected_label)

    if st.button("Explain selected flow", key="xai_explain_btn"):
        st.session_state["xai_flow_id"] = selected_id

    flow_id = selected_id if selected_anom else st.session_state.get("xai_flow_id", selected_id)
    if selected_anom:
        st.session_state["xai_flow_id"] = selected_id
    try:
        payload = client.explanation(int(flow_id))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Explanation fetch failed")
        st.error("Unable to load explanation for the selected flow.")
        st.caption(str(exc))
        return

    expl = payload.get("explanation") or {}
    m1, m2, m3, m4 = st.columns(4)
    m1.metric(
        "Anomaly score",
        f"{float(payload.get('stored_anomaly_score') or expl.get('anomaly_score') or 0):.4f}",
    )
    m2.metric("Risk score", payload.get("risk_score", "—"))
    m3.metric("Severity", payload.get("severity", "—"))
    m4.metric("Mode", payload.get("mode", "—"))

    contribs = expl.get("contributions") or []
    if not contribs:
        st.warning("No contributions returned.")
        return

    table_rows = [
        {
            "Rank": c.get("rank"),
            "Feature": c.get("feature"),
            "Value": c.get("value"),
            "Contribution": c.get("contribution"),
            "|Contribution|": c.get("absolute_contribution"),
            "Direction": c.get("direction"),
        }
        for c in sorted(contribs, key=lambda x: int(x.get("rank", 999)))
    ]
    st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)
    st.plotly_chart(
        explanation_contribution_figure(contribs, top_n=11),
        use_container_width=True,
        key="xai_contribution_chart",
    )
    if expl.get("disclaimer"):
        st.caption(str(expl["disclaimer"]))
