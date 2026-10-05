"""Dashboard data helpers (pure functions — no Streamlit UI)."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from app.detection.risk import risk_severity

logger = logging.getLogger(__name__)

TIME_RANGE_MINUTES: dict[str, int] = {
    "Last 5 minutes": 5,
    "Last 15 minutes": 15,
    "Last 1 hour": 60,
    "Last 24 hours": 1440,
    "All time": 0,
}

SEVERITY_ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def anomaly_rate(anomalous_flows: int, total_flows: int) -> float:
    """Return anomaly rate percent; 0.0 when there are no flows."""
    total = int(total_flows)
    if total <= 0:
        return 0.0
    return round(100.0 * float(anomalous_flows) / float(total), 2)


def parse_timestamp(value: Any) -> datetime | None:
    """Parse ISO timestamps; return None for invalid values."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        logger.debug("Invalid timestamp skipped: %r", value)
        return None


def parse_features(record: Mapping[str, Any]) -> dict[str, Any]:
    """Extract feature dict from features / features_json fields."""
    features = record.get("features")
    if isinstance(features, dict):
        return features
    raw = record.get("features_json")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            logger.debug("Malformed features_json skipped")
    return {}


def normalize_mode(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text in {"LIVE", "SYNTHETIC"}:
        return text
    if text == "SYNTHETIC" or text.lower() == "synthetic":
        return "SYNTHETIC"
    if text.lower() == "live":
        return "LIVE"
    return text or "UNKNOWN"


def normalize_severity(
    record: Mapping[str, Any],
    *,
    low_max: int = 29,
    medium_max: int = 59,
    high_max: int = 79,
) -> str:
    sev = str(record.get("severity") or "").strip()
    if sev:
        return sev[:1].upper() + sev[1:].lower() if len(sev) > 1 else sev.upper()
    try:
        risk = int(float(record.get("risk_score", 0) or 0))
    except (TypeError, ValueError):
        risk = 0
    return risk_severity(
        risk, low_max=low_max, medium_max=medium_max, high_max=high_max
    )


def filter_records(
    records: Sequence[Mapping[str, Any]],
    *,
    mode: str = "ALL",
    severity: str = "ALL",
    time_range_label: str = "Last 24 hours",
    now: datetime | None = None,
    low_max: int = 29,
    medium_max: int = 59,
    high_max: int = 79,
) -> list[dict[str, Any]]:
    """Filter flow/alert records by mode, severity, and time window."""
    current = now or datetime.now(timezone.utc)
    minutes = TIME_RANGE_MINUTES.get(time_range_label, 1440)
    cutoff = None if int(minutes) <= 0 else current - timedelta(minutes=minutes)
    mode_key = str(mode).upper()
    sev_key = str(severity).upper()
    out: list[dict[str, Any]] = []
    for raw in records:
        row = dict(raw)
        row_mode = normalize_mode(row.get("mode") or row.get("data_source"))
        row["mode"] = row_mode
        if mode_key in {"LIVE", "SYNTHETIC"} and row_mode != mode_key:
            continue
        row_sev = normalize_severity(
            row, low_max=low_max, medium_max=medium_max, high_max=high_max
        )
        row["severity"] = row_sev
        if sev_key != "ALL" and row_sev.upper() != sev_key:
            continue
        ts = parse_timestamp(row.get("timestamp"))
        if ts is None:
            continue
        if cutoff is not None and ts < cutoff:
            continue
        row["_ts"] = ts
        feats = parse_features(row)
        row["packet_count"] = feats.get(
            "packet_count", row.get("packet_count")
        )
        row["byte_count"] = feats.get("byte_count", row.get("byte_count"))
        out.append(row)
    out.sort(key=lambda r: r.get("_ts") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return out


def severity_distribution(
    records: Sequence[Mapping[str, Any]],
    *,
    low_max: int = 29,
    medium_max: int = 59,
    high_max: int = 79,
) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITY_ORDER}
    for row in records:
        sev = normalize_severity(
            row, low_max=low_max, medium_max=medium_max, high_max=high_max
        ).upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def summarize_metrics(flows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    total = len(flows)
    anomalous = 0
    max_risk = 0
    for row in flows:
        is_anom = row.get("is_anomaly")
        if is_anom in (1, True, "1", "true", "True"):
            anomalous += 1
        try:
            risk = int(float(row.get("risk_score", 0) or 0))
        except (TypeError, ValueError):
            risk = 0
        max_risk = max(max_risk, risk)
    normal = total - anomalous
    return {
        "total_flows": total,
        "normal_flows": normal,
        "anomalous_flows": anomalous,
        "max_risk_score": max_risk,
        "anomaly_rate": anomaly_rate(anomalous, total),
    }
