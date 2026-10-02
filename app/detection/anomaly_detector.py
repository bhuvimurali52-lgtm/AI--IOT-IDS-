"""Isolation Forest anomaly detector (Phase 3).

Detects deviations from a learned baseline. Does not name attack types.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Isolation Forest with StandardScaler.

    Predictions: 1 = NORMAL (inlier), -1 = ANOMALOUS (outlier).
    anomaly_scores = -decision_function (higher => more anomalous).
    Scores are not calibrated attack probabilities.
    """

    def __init__(
        self,
        *,
        contamination: float = 0.05,
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> None:
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self._is_fitted = False
        self.feature_names: list[str] = []
        self.n_training_samples = 0

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def fit(
        self, X: np.ndarray, feature_names: list[str] | None = None
    ) -> AnomalyDetector:
        if X.ndim != 2 or X.shape[0] == 0:
            raise ValueError("X must be a non-empty 2D array")
        self.feature_names = list(feature_names or [])
        self.n_training_samples = int(X.shape[0])
        xs = self.scaler.fit_transform(X)
        self.model.fit(xs)
        self._is_fitted = True
        logger.info(
            "AnomalyDetector fitted | samples=%d features=%d contamination=%.4f",
            self.n_training_samples,
            X.shape[1],
            self.contamination,
        )
        return self

    def _transform(self, X: np.ndarray) -> np.ndarray:
        if not self._is_fitted:
            raise RuntimeError("AnomalyDetector is not fitted")
        return self.scaler.transform(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(self._transform(X))

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        return self.model.decision_function(self._transform(X))

    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """Higher values indicate more anomalous samples."""
        return -self.decision_function(X)

    def predict_labels(self, X: np.ndarray) -> list[str]:
        return ["NORMAL" if p == 1 else "ANOMALOUS" for p in self.predict(X)]

    def save(self, path: Path | str) -> Path:
        if not self._is_fitted:
            raise RuntimeError("Cannot save an unfitted AnomalyDetector")
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {
            "model": self.model,
            "scaler": self.scaler,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "random_state": self.random_state,
            "feature_names": self.feature_names,
            "n_training_samples": self.n_training_samples,
            "is_fitted": True,
        }
        joblib.dump(payload, out)
        logger.info("Saved AnomalyDetector to %s", out.resolve())
        return out

    @classmethod
    def load(cls, path: Path | str) -> AnomalyDetector:
        payload = joblib.load(Path(path))
        detector = cls(
            contamination=float(payload.get("contamination", 0.05)),
            n_estimators=int(payload.get("n_estimators", 100)),
            random_state=int(payload.get("random_state", 42)),
        )
        detector.model = payload["model"]
        detector.scaler = payload["scaler"]
        detector.feature_names = list(payload.get("feature_names") or [])
        detector.n_training_samples = int(payload.get("n_training_samples") or 0)
        detector._is_fitted = bool(payload.get("is_fitted", True))
        logger.info("Loaded AnomalyDetector from %s", Path(path).resolve())
        return detector
