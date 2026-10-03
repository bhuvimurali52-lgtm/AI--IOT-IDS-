"""Phase 10 SOC intelligence panels (consume existing APIs only)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

import pandas as pd
import streamlit as st

from app.dashboard.charts import explanation_contribution_figure
from app.dashboard.services.intelligence import (
    anomaly_recommendations,
    build_overview,
    build_timeline,
    firewall_recommendations,
    flow_feature_view,
    run_safe_demonstration,
)

logger = logging.getLogger(__name__)

_XAI_NOTE = (
    "Positive contribution means the feature moved the local score toward "
    "anomalous behavior. This is a local baseline-occlusion approximation "
    "\u2014 not a causal explanation and not an exact Shapley/SHAP value."
)


def render_security_overview(
    status: Mapping[str, Any],
    flows: Sequence[Mapping[str, Any]],
    alerts: Sequence[Mapping[str, Any]],
    *,
    api_online: bool,
    firewall: Mapping[str, Any] | None = None,
) -> None:
    st.subheader("Security Intelligence Overview")
    st.caption(
        "An AI-powered IoT security monitoring prototype that detects anomalous "
        "network behavior using an Isolation Forest model, assigns risk, generates "
        "alerts, provides local explainability, and performs read-only Windows "
        "Firewall security posture assessment through a SOC-style dashboard."
    )
    overview = build_overview(
        status=status,
        flows=flows,
        alerts=alerts,
        firewall=firewall,
        api_online=api_online,
    )
    r1 = st.columns(4)
    r1[0].metric("System mode", overview["system_mode"])
    r1[1].metric("Model status", overview["model_status"])
    r1[2].metric("Total flows", overview["total_flows"])
    r1[3].metric("Normal flows", overview["normal_flows"])
    r2 = st.columns(4)
    r2[0].metric("Anomalous flows", overview["anomalous_flows"])
    r2[1].metric("Total alerts", overview["total_alerts"])
    r2[2].metric("High-risk alerts", overview["high_risk_alerts"])
    r2[3].metric("Highest current risk", overview["highest_risk"])
    r3 = st.columns(3)
    r3[0].metric("Current firewall posture", overview["firewall_posture"])
    r3[1].metric("Overall security severity", overview["overall_security_severity"])
    r3[2].metric(
        "Last assessment time",
        overview["last_assessment_time"] or "\u2014",
    )
    if overview["system_mode"] == "SYNTHETIC":
        st.info("SYNTHETIC mode does not require live packet capture or Npcap.")
    st.caption(
        "Firewall figures reflect the last read-only assessment in this session, "
        "if one was run. No fabricated incidents are shown."
    )


def render_security_investigation(
    client: Any,
    flows: Sequence[Mapping[str, Any]],
    *,
    api_online: bool,
) -> None:
    st.subheader("Security Investigation")
    st.caption(
        "Inspect an existing persisted flow. XAI uses the existing "
        "local_baseline_occlusion method without retraining."
    )
    explainable = [f for f in flows if f.get("id") is not None]
    if not explainable:
        st.info("No persisted flows are available to investigate.")
        return

    labels = []
    for f in explainable:
        tag = "ANOMALOUS" if f.get("is_anomaly") in (1, True, "1", "true", "True") else "NORMAL"
        labels.append(
            f"#{f.get('id')} | {tag} | {f.get('source_ip')} \u2192 "
            f"{f.get('destination_ip')} | {f.get('mode')} | risk={f.get('risk_score')}"
        )
    selected = st.selectbox(
        "Select flow or alert record",
        labels,
        index=0,
        key="inv_flow_select",
    )
    flow = explainable[labels.index(selected)]
    feats = flow_feature_view(flow)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Flow ID", flow.get("id"))
    c1.write(f"**Timestamp:** {flow.get('timestamp') or '\u2014'}")
    c2.write(f"**Source:** {flow.get('source_ip')}:{feats.get('source_port')}")
    c2.write(f"**Destination:** {flow.get('destination_ip')}:{feats.get('destination_port')}")
    c3.write(f"**Protocol:** {flow.get('protocol') or feats.get('protocol')}")
    c3.write(f"**Duration:** {feats.get('duration')}")
    c4.write(f"**Detection:** {'ANOMALOUS' if flow.get('is_anomaly') in (1, True, '1', 'true', 'True') else 'NORMAL'}")
    c4.write(f"**Severity:** {flow.get('severity')}")

    c5, c6, c7, c8 = st.columns(4)
    c5.metric("Packet count", feats.get("packet_count") if feats.get("packet_count") is not None else "\u2014")
    c6.metric("Byte count", feats.get("byte_count") if feats.get("byte_count") is not None else "\u2014")
    c7.metric("Packets/s", feats.get("packets_per_second") if feats.get("packets_per_second") is not None else "\u2014")
    c8.metric("Bytes/s", feats.get("bytes_per_second") if feats.get("bytes_per_second") is not None else "\u2014")
    st.write(f"**Average packet size:** {feats.get('average_packet_size')}")
    st.write(
        f"**Anomaly score:** {flow.get('anomaly_score')}  |  "
        f"**Risk score:** {flow.get('risk_score')}"
    )

    if st.button(
        "Load XAI explanation",
        key="inv_xai_btn",
        disabled=not api_online,
        use_container_width=True,
    ):
        try:
            payload = client.explanation(int(flow["id"]))
            payload = dict(payload)
            payload["timestamp"] = datetime.now(timezone.utc).isoformat()
            st.session_state["inv_explanation"] = payload
            st.session_state["xai_flow_id"] = int(flow["id"])
        except Exception as exc:  # noqa: BLE001
            logger.exception("Investigation explanation failed")
            st.error("Unable to load explanation for the selected flow.")
            st.caption(str(exc)[:300])
            st.session_state["inv_explanation"] = None

    expl_payload = st.session_state.get("inv_explanation")
    if not expl_payload:
        st.info("Load an explanation for the selected flow when ready.")
    elif expl_payload.get("flow_id") != flow.get("id") and int(
        expl_payload.get("flow_id") or -1
    ) != int(flow.get("id")):
        st.info("Loaded explanation is for a different flow. Load again to refresh.")
    else:
        _render_xai_block(expl_payload, key_prefix="inv")

    recs = anomaly_recommendations(flow)
    if recs:
        st.markdown("**Analyst recommendations (not executed)**")
        for item in recs:
            st.write(f"- {item}")


def _render_xai_block(payload: Mapping[str, Any], *, key_prefix: str = "inv") -> None:
    st.markdown("**AI Explanation**")
    st.caption(_XAI_NOTE)
    expl = payload.get("explanation") or {}
    contribs = expl.get("contributions") or []
    m1, m2, m3, m4 = st.columns(4)
    m1.metric(
        "Anomaly score",
        f"{float(payload.get('stored_anomaly_score') or expl.get('anomaly_score') or 0):.4f}",
    )
    m2.metric("Risk score", payload.get("risk_score", "\u2014"))
    m3.metric("Severity", payload.get("severity", "\u2014"))
    m4.metric("Method", expl.get("method") or "local_baseline_occlusion")
    if not contribs:
        st.warning("No contributions returned.")
        return
    rows = [
        {
            "Feature": c.get("feature"),
            "Contribution": c.get("contribution"),
            "Direction": c.get("direction"),
            "Rank": c.get("rank"),
        }
        for c in sorted(contribs, key=lambda x: int(x.get("rank", 999)))
    ]
    st.dataframe(
        pd.DataFrame(rows),
        use_container_width=True,
        hide_index=True,
        key=f"{key_prefix}_xai_table",
    )
    st.plotly_chart(
        explanation_contribution_figure(contribs, top_n=11),
        use_container_width=True,
        key=f"{key_prefix}_xai_chart",
    )
    if expl.get("disclaimer"):
        st.caption(str(expl["disclaimer"]))


def render_safe_demonstration(client: Any, *, api_online: bool) -> None:
    st.subheader("Safe Demonstration")
    st.caption(
        "Runs the existing synthetic fixture path: generate normal and anomalous "
        "records, extract the 11 features, score with the saved Isolation Forest, "
        "assign risk, persist alerts, explain one anomalous flow, and fetch "
        "read-only firewall posture. No live attacks, packet injection, or "
        "firewall changes."
    )
    if st.button(
        "Run Security Demonstration",
        key="safe_demo_btn",
        disabled=not api_online,
        use_container_width=True,
    ):
        try:
            result = run_safe_demonstration(client)
            st.session_state["demo_result"] = result
            if result.get("firewall"):
                st.session_state["fw_assessment"] = result["firewall"]
            expl = result.get("explanation")
            if expl and expl.get("flow_id") is not None:
                expl = dict(expl)
                expl["timestamp"] = datetime.now(timezone.utc).isoformat()
                st.session_state["inv_explanation"] = expl
                st.session_state["xai_flow_id"] = int(expl["flow_id"])
        except Exception as exc:  # noqa: BLE001
            logger.exception("Safe demonstration failed")
            st.error("Safe demonstration failed.")
            st.caption(str(exc)[:300])
            return

    result = st.session_state.get("demo_result")
    if not result:
        st.info("Run the demonstration to populate synthetic results in this session.")
        return
    st.warning(result.get("warning") or "Synthetic demonstration complete.")
    syn = result.get("synthetic") or {}
    k1, k2, k3 = st.columns(3)
    k1.metric("Flows scored", int(syn.get("flows_scored") or 0))
    k2.metric("Anomalies flagged", int(syn.get("anomalies_flagged") or 0))
    k3.metric("Demo status", "OK" if result.get("ok") else "INCOMPLETE")
    for err in result.get("errors") or []:
        st.warning(str(err))
    chosen = result.get("selected_flow")
    if chosen:
        st.write(
            f"Selected anomalous flow **#{chosen.get('id')}** "
            f"risk={chosen.get('risk_score')} severity={chosen.get('severity')}"
        )
    expl = result.get("explanation")
    if expl:
        _render_xai_block(expl, key_prefix="demo")
    fw = result.get("firewall") or {}
    if fw and not fw.get("error"):
        st.write(
            f"Firewall posture: **{fw.get('overall_severity')}** "
            f"(status={fw.get('status')}, read_only={fw.get('read_only', True)})"
        )
        st.caption(
            "Read-only security posture assessment \u2014 no firewall changes are performed."
        )


def render_security_timeline(
    flows: Sequence[Mapping[str, Any]],
    alerts: Sequence[Mapping[str, Any]],
    *,
    explanation: Mapping[str, Any] | None = None,
    firewall: Mapping[str, Any] | None = None,
) -> None:
    st.subheader("Security Event Timeline")
    st.caption("Events are drawn only from stored flows, alerts, and session assessments.")
    events = build_timeline(
        flows,
        alerts,
        explanation=explanation,
        firewall=firewall,
        limit=20,
    )
    if not events:
        st.info("No timestamped security events are available yet.")
        return
    st.dataframe(
        pd.DataFrame(events),
        use_container_width=True,
        hide_index=True,
        key="security_event_timeline",
    )


def render_firewall_findings_brief(firewall: Mapping[str, Any] | None) -> None:
    if not firewall or firewall.get("error"):
        return
    recs = firewall_recommendations(firewall)
    if not recs:
        return
    st.markdown("**Firewall analyst recommendations (not executed)**")
    for item in recs:
        st.write(f"- {item}")
