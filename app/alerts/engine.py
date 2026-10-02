"""Alert generation for high-risk anomalies (no blocking/enforcement)."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    timestamp: str
    source_ip: str
    destination_ip: str
    protocol: str
    risk_score: int
    anomaly_score: float
    severity: str
    message: str
    data_source: str
    mode: str
    is_synthetic: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def should_alert(risk_score: int, threshold: int) -> bool:
    return int(risk_score) >= int(threshold)


def generate_alert(
    *,
    flow: Mapping[str, Any],
    anomaly_score: float,
    risk_score: int,
    severity: str,
    data_source: str = "synthetic",
    mode: str | None = None,
) -> Alert:
    src = str(flow.get("source_ip", "unknown"))
    dst = str(flow.get("destination_ip", "unknown"))
    proto = str(flow.get("protocol", "OTHER"))
    resolved_mode = str(mode or flow.get("mode") or data_source).upper()
    if resolved_mode not in {"LIVE", "SYNTHETIC"}:
        resolved_mode = (
            "SYNTHETIC" if str(data_source).lower() == "synthetic" else "LIVE"
        )
    is_synthetic = resolved_mode == "SYNTHETIC"
    tag = "SYNTHETIC FIXTURE" if is_synthetic else "LIVE CAPTURE"
    message = (
        f"[{tag}] Anomalous flow {src} -> {dst} proto={proto} "
        f"risk={risk_score} severity={severity} anomaly_score={anomaly_score:.4f} "
        f"mode={resolved_mode}"
    )
    alert = Alert(
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_ip=src,
        destination_ip=dst,
        protocol=proto,
        risk_score=int(risk_score),
        anomaly_score=float(anomaly_score),
        severity=severity,
        message=message,
        data_source=str(data_source),
        mode=resolved_mode,
        is_synthetic=is_synthetic,
    )
    logger.warning("ALERT | %s", message)
    return alert
