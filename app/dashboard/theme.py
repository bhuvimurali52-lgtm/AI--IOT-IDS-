"""Streamlit visual theme for the SOC command-center UI (presentation only)."""

from __future__ import annotations

from typing import Any, Sequence

import streamlit as st

SOC_CSS = """
<style>
  .stApp { background: #0b1220; color: #e2e8f0; }
  [data-testid="stSidebar"] {
    background: #0f172a;
    border-right: 1px solid #1e293b;
  }
  [data-testid="stSidebar"] * { color: #e2e8f0; }
  h1, h2, h3 { color: #f8fafc !important; letter-spacing: 0.02em; }
  .soc-title {
    font-size: 1.7rem; font-weight: 700; margin: 0;
    color: #f8fafc; letter-spacing: 0.04em;
  }
  .soc-sub {
    margin: 0.35rem 0 0 0; color: #93c5fd; font-size: 0.95rem;
  }
  .soc-disclaimer {
    margin: 0.45rem 0 0.75rem 0; color: #94a3b8; font-size: 0.82rem; line-height: 1.4;
  }
  .soc-badge-row { display: flex; flex-wrap: wrap; gap: 0.45rem; margin: 0.4rem 0 0.9rem 0; }
  .soc-badge {
    border: 1px solid #334155; border-radius: 999px; padding: 0.22rem 0.7rem;
    font-size: 0.75rem; font-weight: 650; letter-spacing: 0.04em;
    background: #111827;
  }
  .soc-ok { color: #86efac; border-color: #166534; }
  .soc-warn { color: #fde68a; border-color: #a16207; }
  .soc-bad { color: #fecaca; border-color: #991b1b; }
  .soc-info { color: #bfdbfe; border-color: #1d4ed8; }
  .soc-kpi-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.75rem; }
  .soc-kpi {
    background: #111827; border: 1px solid #1e293b; border-radius: 12px;
    padding: 0.9rem 1rem;
  }
  .soc-kpi .v { font-size: 1.85rem; font-weight: 700; color: #f8fafc; line-height: 1.1; }
  .soc-kpi .l { margin-top: 0.35rem; font-size: 0.72rem; letter-spacing: 0.08em; color: #94a3b8; }
  .soc-kpi.alert .v { color: #fca5a5; }
  .soc-kpi.anom .v { color: #fdba74; }
  .soc-kpi.ok .v { color: #86efac; }
  .soc-level {
    background: #111827; border: 1px solid #1e293b; border-radius: 12px;
    padding: 1rem 1.1rem; margin: 0.6rem 0 1rem 0;
  }
  @media (max-width: 900px) {
    .soc-kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }
</style>
"""


def inject_command_center_theme() -> None:
    st.markdown(SOC_CSS, unsafe_allow_html=True)


def badge_class(ok: bool, *, warn: bool = False) -> str:
    if warn:
        return "soc-badge soc-warn"
    return "soc-badge soc-ok" if ok else "soc-badge soc-bad"


def kpi_cards_html(items: Sequence[tuple[Any, str, str]]) -> str:
    parts = ['<div class="soc-kpi-grid">']
    for value, label, tone in items:
        parts.append(
            f'<div class="soc-kpi {tone}"><div class="v">{value}</div>'
            f'<div class="l">{label}</div></div>'
        )
    parts.append("</div>")
    return "".join(parts)
