"""Deterministic risk scoring for anomaly results.

Anomaly score ≠ probability of attack. Risk is a triage heuristic only.
"""

from __future__ import annotations

import math
from typing import Any, Mapping


def anomaly_score_to_base_risk(anomaly_score: float) -> float:
    """Map -decision_function score to (0, 100) via logistic."""
    return 100.0 / (1.0 + math.exp(-3.0 * float(anomaly_score)))


def intensity_adjustment(flow: Mapping[str, Any]) -> float:
    """Capped additive risk from extreme observed rates."""
    try:
        pps = float(flow.get("packets_per_second", 0.0) or 0.0)
    except (TypeError, ValueError):
        pps = 0.0
    try:
        bps = float(flow.get("bytes_per_second", 0.0) or 0.0)
    except (TypeError, ValueError):
        bps = 0.0
    adj = 0.0
    if pps >= 1000:
        adj += 10.0
    elif pps >= 200:
        adj += 5.0
    if bps >= 1_000_000:
        adj += 10.0
    elif bps >= 100_000:
        adj += 5.0
    return min(adj, 20.0)


def compute_risk_score(
    anomaly_score: float,
    flow: Mapping[str, Any] | None = None,
) -> int:
    """Return integer risk in [0, 100]."""
    base = anomaly_score_to_base_risk(anomaly_score)
    adj = intensity_adjustment(flow or {})
    return int(max(0, min(100, round(base + adj))))


def risk_severity(
    risk_score: int,
    *,
    low_max: int = 29,
    medium_max: int = 59,
    high_max: int = 79,
) -> str:
    """Map risk score to Low/Medium/High/Critical."""
    score = int(risk_score)
    if score <= low_max:
        return "Low"
    if score <= medium_max:
        return "Medium"
    if score <= high_max:
        return "High"
    return "Critical"
