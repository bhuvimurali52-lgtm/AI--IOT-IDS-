"""Prediction orchestration for flow anomaly detection."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from app.alerts.engine import generate_alert, should_alert
from app.core.config import Settings, get_settings
from app.database.models import IDSDatabase
from app.detection.anomaly_detector import AnomalyDetector
from app.detection.risk import compute_risk_score, risk_severity
from app.features.extractor import FLOW_FEATURE_NAMES, flow_records_to_matrix

logger = logging.getLogger(__name__)


class Predictor:
    """Score flows with a fitted Isolation Forest and optionally persist results."""

    def __init__(
        self,
        detector: AnomalyDetector | None = None,
        *,
        settings: Settings | None = None,
        database: IDSDatabase | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.detector = detector
        self.database = database

    def load_model(self, path: Path | str | None = None) -> AnomalyDetector:
        model_path = Path(path or self.settings.model_path)
        self.detector = AnomalyDetector.load(model_path)
        return self.detector

    def _ensure_detector(self) -> AnomalyDetector:
        if self.detector is not None and self.detector.is_fitted:
            return self.detector
        return self.load_model()

    def predict_flow(self, flow: Mapping[str, Any]) -> dict[str, Any]:
        detector = self._ensure_detector()
        X, _ = flow_records_to_matrix([flow])
        pred = int(detector.predict(X)[0])
        anomaly_score = float(detector.anomaly_scores(X)[0])
        is_anomaly = pred == -1
        risk = compute_risk_score(anomaly_score, flow)
        severity = risk_severity(
            risk,
            low_max=self.settings.risk_low_max,
            medium_max=self.settings.risk_medium_max,
            high_max=self.settings.risk_high_max,
        )
        data_source = str(flow.get("data_source", self.settings.ids_mode)).lower()
        mode = str(flow.get("mode", data_source)).upper()
        if mode not in {"LIVE", "SYNTHETIC"}:
            mode = "SYNTHETIC" if data_source == "synthetic" else "LIVE"
        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": str(flow.get("source_ip", "")),
            "destination_ip": str(flow.get("destination_ip", "")),
            "source_port": int(float(flow.get("source_port", 0) or 0)),
            "destination_port": int(float(flow.get("destination_port", 0) or 0)),
            "protocol": str(flow.get("protocol", "OTHER")),
            "label": "ANOMALOUS" if is_anomaly else "NORMAL",
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "risk_score": risk,
            "severity": severity,
            "data_source": data_source,
            "mode": mode,
            "is_synthetic": mode == "SYNTHETIC" or data_source == "synthetic",
            "features": {
                name: float(X[0, i]) for i, name in enumerate(FLOW_FEATURE_NAMES)
            },
        }
        logger.info(
            "Prediction | %s -> %s | %s | score=%.4f risk=%d source=%s",
            result["source_ip"],
            result["destination_ip"],
            result["label"],
            anomaly_score,
            risk,
            data_source,
        )
        if self.database is not None:
            self.database.insert_flow(result)
            if is_anomaly and should_alert(
                risk, self.settings.alert_risk_threshold
            ):
                alert = generate_alert(
                    flow=flow,
                    anomaly_score=anomaly_score,
                    risk_score=risk,
                    severity=severity,
                    data_source=data_source,
                    mode=mode,
                )
                self.database.insert_alert(alert.to_dict())
                result["alert"] = alert.to_dict()
        return result

    def predict_flows(
        self, flows: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        return [self.predict_flow(f) for f in flows]
