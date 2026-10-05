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
    rank_flows_for_investigation,
    record_ids,
    run_safe_demonstration,
    select_anomalous_flow,
)

logger = logging.getLogger(__name__)

_XAI_NOTE = (
    "Positive contribution indicates that the feature increased deviation "
    "from the learned normal baseline. This is a local baseline-occlusion "
    "explanation, not a causal or exact Shapley attribution."
)


def render_security_overview(
    status: Mapping[str, Any],
    flows: Sequence[Mapping[str, Any]],
    alerts: Sequence[Mapping[str, Any]],
    *,
    api_online: bool,
    firewall: Mapping[str, Any] | None = None,
    low_max: int = 29,
    medium_max: int = 59,
    high_max: int = 79,
) -> None:
    from app.dashboard.theme import kpi_cards_html
    from app.detection.risk import risk_severity

    st.subheader("Security Intelligence Overview")
    st.caption(
        "Presentation path: Overview → Threat Detection → Investigation → "
        "AI Explainability. Demo traffic is SYNTHETIC / CONTROLLED."
    )
    if not api_online:
        st.error(
            "FastAPI is unavailable. KPI cards are hidden so zeros are not shown "
            "as if the database were empty."
        )
        return
    overview = build_overview(
        status=status,
        flows=flows,
        alerts=alerts,
        firewall=firewall,
        api_online=api_online,
    )
    st.markdown(
        kpi_cards_html(
            [
                (overview["total_flows"], "TOTAL FLOWS", "ok"),
                (overview["anomalous_flows"], "ANOMALOUS FLOWS", "anom"),
                (overview["total_alerts"], "SECURITY ALERTS", "alert"),
                (overview["highest_risk"], "HIGHEST RISK", "anom"),
            ]
        ),
        unsafe_allow_html=True,
    )
    level = risk_severity(
        int(overview["highest_risk"]),
        low_max=low_max,
        medium_max=medium_max,
        high_max=high_max,
    ).upper()
    st.markdown("**CURRENT THREAT LEVEL**")
    st.markdown(
        f'<div class="soc-level" role="status">'
        f"<strong>{overview['highest_risk']}</strong> &nbsp;|&nbsp; {level} "
        f"&nbsp;|&nbsp; {overview['total_alerts']} alerts"
        f"</div>",
        unsafe_allow_html=True,
    )
    st.caption(
        f"Capture mode (runtime): **{overview['system_mode']}** · "
        f"Model: {overview['model_status']} · Firewall: {overview['firewall_posture']}"
    )
    if overview["system_mode"] == "SYNTHETIC":
        st.info("Synthetic mode active. Live packet capture is not required.")


def render_security_investigation(
    client: Any,
    flows: Sequence[Mapping[str, Any]],
    *,
    api_online: bool,
) -> None:
    st.subheader("Security Investigation")
    st.caption(
        "Inspect an existing persisted flow. Newest highest-risk anomalous "
        "records are listed first. XAI uses the existing "
        "local_baseline_occlusion method without retraining."
    )
    if not api_online:
        st.error("FastAPI is unavailable. Investigation cannot load live explanations.")
    explainable = rank_flows_for_investigation(flows)
    if not explainable:
        st.info("No persisted flows are available to investigate.")
        return

    demo_ids = {int(x) for x in (st.session_state.get("demo_new_flow_ids") or [])}
    labels = []
    for f in explainable:
        tag = "ANOMALOUS" if f.get("is_anomaly") in (1, True, "1", "true", "True") else "NORMAL"
        try:
            fid_int = int(f.get("id"))
        except (TypeError, ValueError):
            fid_int = None
        marker = " | DEMO NEW" if fid_int in demo_ids else ""
        labels.append(
            f"#{f.get('id')} | {tag}{marker} | {f.get('source_ip')} \u2192 "
            f"{f.get('destination_ip')} | {f.get('mode')} | risk={f.get('risk_score')}"
        )
    preferred_id = st.session_state.get("xai_flow_id")
    index = 0
    if preferred_id is not None:
        for i, f in enumerate(explainable):
            try:
                if int(f.get("id") or 0) == int(preferred_id):
                    index = i
                    break
            except (TypeError, ValueError):
                continue
    if st.session_state.pop("demo_select_pending", False) and labels:
        st.session_state["inv_flow_select"] = labels[index]
    selected = st.selectbox(
        "Select flow or alert record",
        labels,
        index=index,
        key="inv_flow_select",
    )
    flow = explainable[labels.index(selected)]
    feats = flow_feature_view(flow)
    is_anom = flow.get("is_anomaly") in (1, True, "1", "true", "True")

    st.markdown(f"### FLOW #{flow.get('id')}")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Anomaly status", "ANOMALOUS" if is_anom else "NORMAL")
    m2.metric("Risk score", flow.get("risk_score"))
    m3.metric("Severity", flow.get("severity") or "\u2014")
    m4.write(f"**Timestamp:** {flow.get('timestamp') or '\u2014'}")
    m5.write(f"**Mode:** {flow.get('mode') or '\u2014'}")

    st.markdown("**Traffic investigation — 11-feature contract**")
    from app.features.extractor import MODEL_FEATURE_ORDER

    feat_cols = st.columns(4)
    for i, name in enumerate(MODEL_FEATURE_ORDER):
        value = feats.get(name)
        if name == "protocol" and flow.get("protocol") not in (None, ""):
            value = flow.get("protocol")
        feat_cols[i % 4].metric(name, value if value is not None else "\u2014")

    st.markdown("**TRAFFIC INVESTIGATION**")
    t1, t2, t3, t4 = st.columns(4)
    t1.write(f"**Source:** {flow.get('source_ip')}:{feats.get('source_port')}")
    t2.write(f"**Destination:** {flow.get('destination_ip')}:{feats.get('destination_port')}")
    t3.write(f"**Protocol:** {flow.get('protocol') or feats.get('protocol')}")
    t4.write(f"**Anomaly score:** {flow.get('anomaly_score')}")

    if st.button(
        "Load XAI explanation",
        key="inv_xai_btn",
        disabled=not api_online,
        use_container_width=True,
    ):
        _load_investigation_explanation(client, flow)

    expl_payload = st.session_state.get("inv_explanation")
    same_flow = False
    if expl_payload:
        try:
            same_flow = int(expl_payload.get("flow_id") or -1) == int(flow.get("id"))
        except (TypeError, ValueError):
            same_flow = False
    if is_anom and api_online and not same_flow:
        _load_investigation_explanation(client, flow)
        expl_payload = st.session_state.get("inv_explanation")
        try:
            same_flow = int((expl_payload or {}).get("flow_id") or -1) == int(flow.get("id"))
        except (TypeError, ValueError):
            same_flow = False

    if not expl_payload:
        st.info("Load an explanation for the selected flow when ready.")
    elif not same_flow:
        st.info("Loaded explanation is for a different flow. Load again to refresh.")
    else:
        _render_xai_block(expl_payload, key_prefix="inv")

    recs = anomaly_recommendations(flow)
    if recs:
        st.markdown("**Analyst recommendations (not executed)**")
        for item in recs:
            st.write(f"- {item}")


def _load_investigation_explanation(client: Any, flow: Mapping[str, Any]) -> None:
    try:
        payload = dict(client.explanation(int(flow["id"])))
        payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        st.session_state["inv_explanation"] = payload
        st.session_state["xai_flow_id"] = int(flow["id"])
    except Exception as exc:  # noqa: BLE001
        logger.exception("Investigation explanation failed")
        st.error("Unable to load explanation for the selected flow.")
        st.caption(str(exc)[:300])
        st.session_state["inv_explanation"] = None


def render_run_security_demo(
    client: Any,
    *,
    api_online: bool,
    known_flow_ids: Sequence[int] | None = None,
) -> None:
    """Overview presentation action. Must stay outside auto-refresh fragments."""
    st.markdown("### RUN SECURITY DEMO")
    st.caption("Generate controlled synthetic traffic through the real IDS detection pipeline.")
    st.warning(
        "SYNTHETIC / CONTROLLED only. This does not inject packets and is not a "
        "real-world attack."
    )
    if not api_online:
        st.error("FastAPI is unavailable. RUN SECURITY DEMO cannot call the detection pipeline.")
    clicked = st.button(
        "RUN SECURITY DEMO",
        key="run_security_demo_btn",
        disabled=not api_online,
        use_container_width=True,
    )
    if clicked:
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            result = run_safe_demonstration(client)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Security demo failed")
            st.error("Security demo failed. FastAPI did not complete the synthetic detection test.")
            st.caption(str(exc)[:300])
            return
        st.session_state["demo_result"] = result
        st.session_state["demo_started_at"] = started_at
        after_ids = record_ids(result.get("flows") or [])
        before_ids = {int(x) for x in (known_flow_ids or [])}
        st.session_state["demo_new_flow_ids"] = sorted(after_ids - before_ids)
        chosen = result.get("selected_flow") or select_anomalous_flow(result.get("flows") or [])
        if chosen and chosen.get("id") is not None:
            st.session_state["xai_flow_id"] = int(chosen["id"])
            st.session_state["demo_select_pending"] = True
            st.session_state["xai_select_pending"] = True
            expl = result.get("explanation")
            if expl and expl.get("flow_id") is not None:
                expl = dict(expl)
                expl["timestamp"] = datetime.now(timezone.utc).isoformat()
                st.session_state["inv_explanation"] = expl
        if result.get("firewall"):
            st.session_state["fw_assessment"] = result["firewall"]
        if result.get("ok"):
            st.session_state["demo_flash"] = True
            st.rerun()
        st.error("Security demo did not complete through the synthetic detection pipeline.")
        for err in result.get("errors") or []:
            st.warning(str(err))
        return

    if st.session_state.get("demo_flash") and (
        st.session_state.get("demo_result") or {}
    ).get("ok"):
        st.success(
            "Security demo completed — synthetic traffic processed and alerts generated."
        )
        st.caption(
            "Records are SYNTHETIC / CONTROLLED. Continue to Threat Detection, "
            "Investigation, then AI Explainability."
        )
        syn = (st.session_state.get("demo_result") or {}).get("synthetic") or {}
        c1, c2, c3 = st.columns(3)
        c1.metric("Flows scored", int(syn.get("flows_scored") or 0))
        c2.metric("Anomalies flagged", int(syn.get("anomalies_flagged") or 0))
        c3.metric("New flow IDs", len(st.session_state.get("demo_new_flow_ids") or []))


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
