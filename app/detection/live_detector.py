"""Live detection service: completed flows → features → IsolationForest → alerts.

Loads the trained model once. Does not retrain. Does not block packet sniffing.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Mapping

import numpy as np

from app.core.config import Settings, get_settings
from app.database.models import IDSDatabase
from app.detection.anomaly_detector import AnomalyDetector
from app.detection.predictor import Predictor
from app.features.extractor import (
    MODEL_FEATURE_ORDER,
    FeatureValidationError,
    flow_to_model_vector,
)

logger = logging.getLogger(__name__)


class LiveDetector:
    """Score completed flows with the saved Phase 3 IsolationForest artifact."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        database: IDSDatabase | None = None,
        detector: AnomalyDetector | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.database = database
        self._detector = detector
        self._predictor: Predictor | None = None
        self.processed_flows = 0
        self.rejected_flows = 0
        self.alerts_created = 0

    def load_model(self, path: Path | str | None = None) -> AnomalyDetector:
        """Load the saved model once for the live session."""
        model_path = Path(path or self.settings.model_path)
        self._detector = AnomalyDetector.load(model_path)
        self._predictor = Predictor(
            detector=self._detector,
            settings=self.settings,
            database=self.database,
        )
        logger.info(
            "LiveDetector loaded model once from %s | features=%d samples=%d",
            model_path.resolve(),
            len(self._detector.feature_names or MODEL_FEATURE_ORDER),
            self._detector.n_training_samples,
        )
        return self._detector

    @property
    def is_ready(self) -> bool:
        return self._detector is not None and self._detector.is_fitted

    def _ensure_ready(self) -> AnomalyDetector:
        if self._detector is None or not self._detector.is_fitted:
            self.load_model()
        assert self._detector is not None
        if self._predictor is None:
            self._predictor = Predictor(
                detector=self._detector,
                settings=self.settings,
                database=self.database,
            )
        return self._detector

    def process_flow(self, flow: Mapping[str, Any]) -> dict[str, Any] | None:
        """Validate features, score with the loaded model, persist, and alert.

        Returns:
            Prediction dict, or ``None`` if the flow is invalid and skipped.
        """
        self._ensure_ready()
        assert self._predictor is not None

        data_source = str(flow.get("data_source", "live")).lower()
        mode = str(flow.get("mode", data_source)).upper()
        if mode not in {"LIVE", "SYNTHETIC"}:
            mode = "SYNTHETIC" if data_source == "synthetic" else "LIVE"
        enriched = dict(flow)
        enriched["data_source"] = data_source
        enriched["mode"] = mode

        try:
            vector = flow_to_model_vector(enriched)
            if len(vector) != len(MODEL_FEATURE_ORDER):
                raise FeatureValidationError(
                    f"Expected {len(MODEL_FEATURE_ORDER)} features, got {len(vector)}"
                )
            _ = np.asarray(vector, dtype=float).reshape(1, -1)
        except FeatureValidationError as exc:
            self.rejected_flows += 1
            logger.warning("Rejecting invalid live flow: %s", exc)
            return None
        except Exception as exc:  # noqa: BLE001
            self.rejected_flows += 1
            logger.warning("Rejecting unprocessable live flow: %s", exc)
            return None

        result = self._predictor.predict_flow(enriched)
        result["mode"] = mode
        result["source_port"] = int(float(enriched.get("source_port", 0) or 0))
        result["destination_port"] = int(
            float(enriched.get("destination_port", 0) or 0)
        )
        self.processed_flows += 1
        if result.get("alert"):
            self.alerts_created += 1
        return result

    def process_flows(
        self, flows: list[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for flow in flows:
            result = self.process_flow(flow)
            if result is not None:
                results.append(result)
        return results
