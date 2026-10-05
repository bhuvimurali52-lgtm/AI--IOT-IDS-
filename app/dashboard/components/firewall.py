"""Read-only firewall security posture panel."""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd
import streamlit as st

logger = logging.getLogger(__name__)


def render_firewall_panel(client: Any, *, api_online: bool) -> None:
    st.subheader("🔥 WINDOWS FIREWALL SECURITY POSTURE")
    st.caption(
        "Read-only security posture assessment \u2014 no firewall changes are performed."
    )
    st.info(
        "This is a local Windows configuration/posture checker. It is not a "
        "replacement for enterprise firewall management, SIEM, EDR, or a "
        "certified vulnerability assessment."
    )
    st.markdown("### 🔒 READ-ONLY AUDIT")
    st.caption("RUN FIREWALL AUDIT")

    run = st.button(
        "Run firewall posture audit",
        key="fw_audit_btn",
        disabled=not api_online,
        use_container_width=True,
    )
    if run:
        try:
            st.session_state["fw_assessment"] = client.firewall()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Firewall assessment fetch failed")
            st.error("Unable to run firewall posture assessment.")
            st.caption(str(exc)[:300])
            return

    result = st.session_state.get("fw_assessment")
    if not result:
        st.info("Run the audit to display firewall posture findings.")
        return

    st.markdown("**OVERALL POSTURE**")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Firewall available", str(result.get("firewall_available")))
    m2.metric("Overall severity", result.get("overall_severity", "\u2014"))
    m3.metric("Finding count", int(result.get("finding_count") or 0))
    m4.metric("Status", result.get("status", "\u2014"))

    profiles = result.get("profiles") or []
    if profiles:
        st.markdown("**Profile status**")
        rows = [
            {
                "Profile": p.get("name"),
                "Enabled": p.get("enabled"),
                "Inbound default": p.get("inbound_default"),
                "Outbound default": p.get("outbound_default"),
            }
            for p in profiles
        ]
        st.dataframe(
            pd.DataFrame(rows),
            use_container_width=True,
            hide_index=True,
            key="fw_profiles_table",
        )

    findings = result.get("findings") or []
    if profiles:
        named = {str(p.get("name") or "").strip().title(): p for p in profiles}
        c_dom, c_pri, c_pub = st.columns(3)
        for col, name in ((c_dom, "Domain"), (c_pri, "Private"), (c_pub, "Public")):
            p = named.get(name) or {}
            with col:
                st.markdown(f"**{name} Profile**")
                st.write(f"Enabled: `{p.get('enabled', '—')}`")
                st.write(f"Inbound default: `{p.get('inbound_default', '—')}`")
                st.write(f"Outbound default: `{p.get('outbound_default', '—')}`")

    st.markdown("**FINDINGS / SEVERITY**")
    if findings:
        st.markdown("**Security posture findings**")
        table = [
            {
                "ID": f.get("id"),
                "Severity": f.get("severity"),
                "Category": f.get("category"),
                "Title": f.get("title"),
                "Observed": f.get("observed_value"),
                "Recommended": f.get("expected_or_recommended_value"),
                "Remediation": f.get("remediation"),
            }
            for f in findings
        ]
        st.dataframe(
            pd.DataFrame(table),
            use_container_width=True,
            hide_index=True,
            key="fw_findings_table",
        )
        for f in findings:
            with st.expander(f"{f.get('id')} \u2014 {f.get('title')}"):
                st.caption("AI-assisted security explanation")
                st.write(f.get("explanation") or f.get("description"))
    else:
        st.success("No security posture findings from the collected snapshot.")

    if result.get("collection_errors"):
        st.warning("Collection was incomplete.")
        for err in result["collection_errors"]:
            st.caption(str(err))
    if result.get("disclaimer"):
        st.caption(str(result["disclaimer"]))
