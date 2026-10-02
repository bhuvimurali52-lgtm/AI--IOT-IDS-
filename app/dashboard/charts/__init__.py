"""Plotly chart builders for the SOC dashboard."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from app.dashboard.services.metrics import severity_distribution


def _empty_figure(message: str) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(
        text=message,
        xref="paper",
        yref="paper",
        x=0.5,
        y=0.5,
        showarrow=False,
        font={"size": 14, "color": "#64748b"},
    )
    fig.update_layout(
        xaxis={"visible": False},
        yaxis={"visible": False},
        height=320,
        margin={"l": 20, "r": 20, "t": 40, "b": 20},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def flow_timeline_figure(flows: Sequence[Mapping[str, Any]]) -> go.Figure:
    """Cumulative total / normal / anomalous flows over time."""
    if not flows:
        return _empty_figure("No traffic data available.")

    rows = []
    for row in flows:
        ts = row.get("_ts") or row.get("timestamp")
        is_anom = row.get("is_anomaly") in (1, True, "1", "true", "True")
        rows.append({"timestamp": ts, "is_anomaly": int(bool(is_anom))})
    frame = pd.DataFrame(rows)
    if frame.empty:
        return _empty_figure("No traffic data available.")
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    frame = frame.dropna(subset=["timestamp"]).sort_values("timestamp")
    if frame.empty:
        return _empty_figure("No traffic data available.")

    frame["total"] = 1
    frame["anomalous"] = frame["is_anomaly"]
    frame["normal"] = 1 - frame["is_anomaly"]
    frame["total_c"] = frame["total"].cumsum()
    frame["normal_c"] = frame["normal"].cumsum()
    frame["anomalous_c"] = frame["anomalous"].cumsum()

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=frame["timestamp"],
            y=frame["total_c"],
            name="Total",
            mode="lines+markers",
            line={"color": "#334155"},
        )
    )
    fig.add_trace(
        go.Scatter(
            x=frame["timestamp"],
            y=frame["normal_c"],
            name="Normal",
            mode="lines+markers",
            line={"color": "#16a34a"},
        )
    )
    fig.add_trace(
        go.Scatter(
            x=frame["timestamp"],
            y=frame["anomalous_c"],
            name="Anomalous",
            mode="lines+markers",
            line={"color": "#dc2626"},
        )
    )
    fig.update_layout(
        title="Real-Time Flow Timeline",
        xaxis_title="Timestamp",
        yaxis_title="Cumulative flows",
        height=360,
        legend={"orientation": "h"},
        margin={"l": 40, "r": 20, "t": 50, "b": 40},
    )
    return fig


def risk_timeline_figure(flows: Sequence[Mapping[str, Any]]) -> go.Figure:
    """Risk score over time (0–100 triage score, not a probability)."""
    if not flows:
        return _empty_figure("No traffic data available.")

    rows = []
    for row in flows:
        ts = row.get("_ts") or row.get("timestamp")
        try:
            risk = int(float(row.get("risk_score", 0) or 0))
        except (TypeError, ValueError):
            continue
        rows.append({"timestamp": ts, "risk_score": risk})
    frame = pd.DataFrame(rows)
    if frame.empty:
        return _empty_figure("No traffic data available.")
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    frame = frame.dropna(subset=["timestamp"]).sort_values("timestamp")
    if frame.empty:
        return _empty_figure("No traffic data available.")

    fig = px.line(
        frame,
        x="timestamp",
        y="risk_score",
        markers=True,
        title="RISK SCORE (0–100)",
    )
    fig.update_traces(line={"color": "#b45309"})
    fig.update_layout(
        xaxis_title="Timestamp",
        yaxis_title="Risk score",
        yaxis={"range": [0, 100]},
        height=360,
        margin={"l": 40, "r": 20, "t": 50, "b": 40},
    )
    return fig


def risk_distribution_figure(
    flows: Sequence[Mapping[str, Any]],
    *,
    low_max: int = 29,
    medium_max: int = 59,
    high_max: int = 79,
) -> go.Figure:
    counts = severity_distribution(
        flows, low_max=low_max, medium_max=medium_max, high_max=high_max
    )
    if sum(counts.values()) == 0:
        return _empty_figure("No traffic data available.")
    frame = pd.DataFrame(
        {"severity": list(counts.keys()), "count": list(counts.values())}
    )
    colors = {
        "LOW": "#22c55e",
        "MEDIUM": "#eab308",
        "HIGH": "#f97316",
        "CRITICAL": "#dc2626",
    }
    fig = px.bar(
        frame,
        x="severity",
        y="count",
        color="severity",
        color_discrete_map=colors,
        title="Risk Distribution",
    )
    fig.update_layout(
        showlegend=False,
        height=360,
        margin={"l": 40, "r": 20, "t": 50, "b": 40},
    )
    return fig


def explanation_contribution_figure(
    contributions: Sequence[Mapping[str, Any]],
    *,
    top_n: int = 11,
) -> go.Figure:
    """Horizontal bar chart of contribution magnitudes (signed colors)."""
    if not contributions:
        return _empty_figure("No explanation contributions available.")
    rows = sorted(
        [dict(c) for c in contributions],
        key=lambda r: int(r.get("rank", 999)),
    )[: max(1, int(top_n))]
    frame = pd.DataFrame(rows)
    if frame.empty:
        return _empty_figure("No explanation contributions available.")
    frame = frame.iloc[::-1]
    colors = [
        "#dc2626"
        if float(v) > 0
        else "#16a34a"
        if float(v) < 0
        else "#94a3b8"
        for v in frame["contribution"]
    ]
    fig = go.Figure(
        go.Bar(
            x=frame["contribution"],
            y=frame["feature"],
            orientation="h",
            marker_color=colors,
            text=[f"{float(v):.4f}" for v in frame["contribution"]],
            textposition="auto",
        )
    )
    fig.update_layout(
        title="Top feature contributions (local occlusion)",
        xaxis_title="Contribution to anomaly score (approx.)",
        yaxis_title="Feature",
        height=420,
        margin={"l": 120, "r": 20, "t": 50, "b": 40},
    )
    return fig


def threshold_analysis_figure(
    rows: Sequence[Mapping[str, Any]],
) -> go.Figure:
    """Plot precision/recall/F1 vs offline anomaly-score thresholds."""
    if not rows:
        return _empty_figure("No threshold-analysis data available.")
    frame = pd.DataFrame([dict(r) for r in rows])
    if frame.empty or "threshold" not in frame.columns:
        return _empty_figure("No threshold-analysis data available.")
    fig = go.Figure()
    for col, color in (
        ("precision", "#2563eb"),
        ("recall", "#16a34a"),
        ("f1", "#b45309"),
    ):
        if col in frame.columns:
            fig.add_trace(
                go.Scatter(
                    x=frame["threshold"],
                    y=frame[col],
                    mode="lines+markers",
                    name=col.upper(),
                    line={"color": color},
                )
            )
    fig.update_layout(
        title="Offline threshold analysis (synthetic evaluation only)",
        xaxis_title="Anomaly-score threshold",
        yaxis_title="Metric",
        yaxis={"range": [0, 1.05]},
        height=380,
        legend={"orientation": "h"},
        margin={"l": 40, "r": 20, "t": 50, "b": 40},
    )
    return fig
