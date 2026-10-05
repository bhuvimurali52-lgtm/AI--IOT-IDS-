"""Pure helpers for Phase 10 security-intelligence views.

Composes existing API payloads. Does not retrain, sniff, or modify firewalls.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping, Sequence

from app.dashboard.services.metrics import parse_features, summarize_metrics

logger = logging.getLogger(__name__)

_SEV_RANK = {
    "NONE": 0,
    "INFORMATIONAL": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}

_FEATURE_FIELDS = (
    "duration",
    "packet_count",
    "byte_count",
    "packets_per_second",
    "bytes_per_second",
    "average_packet_size",
    "min_packet_size",
    "max_packet_size",
    "source_port",
    "destination_port",
    "protocol",
)


def _is_anomaly(row: Mapping[str, Any]) -> bool:
    return row.get("is_anomaly") in (1, True, "1", "true", "True")


def _rank(severity: Any) -> int:
    return _SEV_RANK.get(str(severity or "NONE").upper(), 0)


def max_overall_severity(*severities: Any) -> str:
    best = "NONE"
    best_rank = 0
    for raw in severities:
        name = str(raw or "NONE").upper()
        rank = _rank(name)
        if rank > best_rank:
            best = name
            best_rank = rank
    return best


def high_risk_alert_count(alerts: Sequence[Mapping[str, Any]]) -> int:
    return sum(
        1
        for row in alerts
        if str(row.get("severity") or "").upper() in {"HIGH", "CRITICAL"}
    )


def _flow_risk(row: Mapping[str, Any]) -> int:
    try:
        return int(float(row.get("risk_score", 0) or 0))
    except (TypeError, ValueError):
        return 0


def investigation_sort_key(flow: Mapping[str, Any]) -> tuple[int, int, str, int]:
    """Anomalous first, then highest risk, newest timestamp, highest id."""
    anom = 1 if _is_anomaly(flow) else 0
    try:
        fid = int(flow.get("id") or 0)
    except (TypeError, ValueError):
        fid = 0
    return (anom, _flow_risk(flow), str(flow.get("timestamp") or ""), fid)


def rank_flows_for_investigation(
    flows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Order persisted flows for investigation / XAI selection. No fabrication."""
    rows = [dict(raw) for raw in flows if raw.get("id") is not None]
    rows.sort(key=investigation_sort_key, reverse=True)
    return rows


def record_ids(records: Sequence[Mapping[str, Any]]) -> set[int]:
    ids: set[int] = set()
    for row in records:
        raw = row.get("id")
        if raw is None:
            continue
        try:
            ids.add(int(raw))
        except (TypeError, ValueError):
            continue
    return ids


def select_anomalous_flow(
    flows: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    """Pick the newest highest-risk anomalous flow that has an id."""
    for row in rank_flows_for_investigation(flows):
        if _is_anomaly(row):
            return row
    return None


def flow_feature_view(flow: Mapping[str, Any]) -> dict[str, Any]:
    feats = parse_features(flow)
    out: dict[str, Any] = {}
    for name in _FEATURE_FIELDS:
        if name == "protocol" and flow.get("protocol") not in (None, ""):
            out[name] = flow.get("protocol")
            continue
        if name in feats:
            out[name] = feats[name]
        elif flow.get(name) is not None:
            out[name] = flow.get(name)
        else:
            out[name] = None
    return out


def build_overview(
    *,
    status: Mapping[str, Any],
    flows: Sequence[Mapping[str, Any]],
    alerts: Sequence[Mapping[str, Any]],
    firewall: Mapping[str, Any] | None = None,
    api_online: bool = True,
) -> dict[str, Any]:
    metrics = summarize_metrics(flows)
    mode = str(
        status.get("capture_mode") or status.get("ids_mode") or "SYNTHETIC"
    ).upper()
    if mode not in {"LIVE", "SYNTHETIC"}:
        mode = "SYNTHETIC"
    model_loaded = bool(status.get("model_loaded")) if api_online else False
    fw = dict(firewall or {})
    if not fw:
        posture = "Not assessed"
        fw_severity = "NONE"
        assessed_at = None
    elif fw.get("error"):
        posture = "Unavailable"
        fw_severity = "NONE"
        assessed_at = fw.get("assessed_at")
    else:
        fw_severity = str(fw.get("overall_severity") or "NONE").upper()
        posture = f"{fw_severity} / {fw.get('status') or 'unknown'}"
        assessed_at = fw.get("assessed_at")

    alert_severities = [row.get("severity") for row in alerts]
    overall = max_overall_severity(*alert_severities, fw_severity)
    return {
        "system_mode": mode,
        "model_status": "LOADED" if model_loaded else "NOT LOADED",
        "total_flows": int(metrics["total_flows"]),
        "normal_flows": int(metrics["normal_flows"]),
        "anomalous_flows": int(metrics["anomalous_flows"]),
        "total_alerts": len(alerts),
        "high_risk_alerts": high_risk_alert_count(alerts),
        "highest_risk": int(metrics["max_risk_score"]),
        "firewall_posture": posture,
        "overall_security_severity": overall,
        "last_assessment_time": assessed_at,
        "read_only_firewall": True,
    }


def build_timeline(
    flows: Sequence[Mapping[str, Any]],
    alerts: Sequence[Mapping[str, Any]],
    *,
    explanation: Mapping[str, Any] | None = None,
    firewall: Mapping[str, Any] | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Build events only from provided records. Skips rows without timestamps."""
    events: list[dict[str, Any]] = []
    for row in flows:
        ts = row.get("timestamp")
        if not ts:
            continue
        kind = "Anomalous flow" if _is_anomaly(row) else "Normal flow"
        events.append(
            {
                "timestamp": ts,
                "event": kind,
                "detail": (
                    f"#{row.get('id', '-')} {row.get('source_ip')} -> "
                    f"{row.get('destination_ip')} risk={row.get('risk_score')}"
                ),
            }
        )
    for row in alerts:
        ts = row.get("timestamp")
        if not ts:
            continue
        events.append(
            {
                "timestamp": ts,
                "event": "Alert generated",
                "detail": (
                    f"{row.get('source_ip')} -> {row.get('destination_ip')} "
                    f"{row.get('severity')} risk={row.get('risk_score')}"
                ),
            }
        )
    if explanation and explanation.get("flow_id") is not None:
        ts = explanation.get("timestamp") or explanation.get("assessed_at")
        if ts:
            events.append(
                {
                    "timestamp": ts,
                    "event": "XAI investigation",
                    "detail": f"Flow #{explanation.get('flow_id')} local_baseline_occlusion",
                }
            )
    if firewall and not firewall.get("error"):
        ts = firewall.get("assessed_at")
        if ts:
            events.append(
                {
                    "timestamp": ts,
                    "event": "Firewall assessment",
                    "detail": (
                        f"severity={firewall.get('overall_severity')} "
                        f"status={firewall.get('status')}"
                    ),
                }
            )
    events.sort(key=lambda e: str(e.get("timestamp") or ""), reverse=True)
    return events[: int(limit)]


def anomaly_recommendations(flow: Mapping[str, Any] | None) -> list[str]:
    if not flow:
        return []
    recs = [
        "Investigate the originating device.",
        "Review the traffic pattern.",
        "Compare against the expected baseline.",
    ]
    try:
        risk = int(float(flow.get("risk_score", 0) or 0))
    except (TypeError, ValueError):
        risk = 0
    if risk >= 60 or str(flow.get("severity") or "").upper() in {"HIGH", "CRITICAL"}:
        recs.append("Investigate repeated anomalous behavior.")
    recs.append(
        "These recommendations are for analyst review only and are not executed."
    )
    recs.append("Following a recommendation does not stop an attack.")
    return recs


def firewall_recommendations(assessment: Mapping[str, Any] | None) -> list[str]:
    if not assessment or assessment.get("error"):
        return []
    recs = [
        "Review firewall policy against organizational requirements.",
    ]
    findings = assessment.get("findings") or []
    if any(
        "outbound" in str(f.get("id") or "").lower()
        or "outbound" in str(f.get("title") or "").lower()
        for f in findings
        if isinstance(f, Mapping)
    ):
        recs.append("Review outbound policy if egress filtering is required.")
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        rem = str(finding.get("remediation") or "").strip()
        if rem and rem not in recs:
            recs.append(rem)
        if len(recs) >= 6:
            break
    recs.append(
        "Read-only security posture assessment \u2014 no firewall changes are performed."
    )
    recs.append("Recommendations are not applied automatically.")
    return recs


def run_safe_demonstration(client: Any) -> dict[str, Any]:
    """Orchestrate the existing synthetic test + XAI + read-only firewall GET."""
    payload: dict[str, Any] = {
        "ok": False,
        "warning": (
            "SAFE DEMONSTRATION uses SYNTHETIC fixtures only. "
            "No packets are injected and no firewall rules are changed."
        ),
        "synthetic": {},
        "selected_flow": None,
        "explanation": None,
        "firewall": None,
        "flows": [],
        "errors": [],
    }
    try:
        payload["synthetic"] = client.run_synthetic_test()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Safe demo synthetic test failed: %s", exc)
        payload["errors"].append("Synthetic demonstration failed.")
        return payload

    flows: list[dict[str, Any]] = []
    try:
        flows = client.flows(limit=200, mode="SYNTHETIC")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Safe demo flow fetch failed: %s", exc)
        payload["errors"].append("Unable to load synthetic flows after the test.")

    chosen = select_anomalous_flow(flows)
    payload["selected_flow"] = chosen
    if chosen and chosen.get("id") is not None:
        try:
            payload["explanation"] = client.explanation(int(chosen["id"]))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Safe demo explanation failed: %s", exc)
            payload["errors"].append("Unable to load XAI explanation for the selected flow.")
            payload["explanation"] = None
    else:
        payload["errors"].append("No anomalous synthetic flow with an id was available.")

    try:
        payload["firewall"] = client.firewall()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Safe demo firewall fetch failed: %s", exc)
        payload["errors"].append("Unable to load firewall posture.")
        payload["firewall"] = {"error": "unavailable", "read_only": True}

    payload["ok"] = bool(payload.get("synthetic"))
    payload["flows"] = flows
    return payload
