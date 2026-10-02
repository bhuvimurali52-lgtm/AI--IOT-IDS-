"""Explainable AI for IsolationForest anomaly decisions.

Method
------
Local baseline-occlusion (leave-one-feature-to-baseline) attributions.

For a scored flow feature vector ``x`` and the fitted ``AnomalyDetector``:

1. Compute the reference anomaly score ``s(x) = -decision_function(x)``
   using the same scaler + IsolationForest path as live inference.
2. For each feature ``i``, build ``x^(i)`` by replacing feature ``i`` with the
   training baseline ``scaler.mean_[i]`` (the value StandardScaler maps to 0).
3. Contribution_i = s(x) - s(x^(i)).

Interpretation (local approximation, not causal attribution):

- Positive contribution: restoring feature ``i`` to the training baseline
  *reduces* the anomaly score → the observed value pushed the decision toward
  anomalous / deviation-from-baseline.
- Negative contribution: restoring feature ``i`` to baseline *increases*
  the anomaly score → the observed value pushed toward more normal behavior.

This is a deterministic, model-querying local explanation. It is **not**
exact Shapley/SHAP attribution and does **not** claim causal feature effects
or named-attack classification.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

import numpy as np

from app.detection.anomaly_detector import AnomalyDetector
from app.features.extractor import MODEL_FEATURE_ORDER

logger = logging.getLogger(__name__)

METHOD_NAME = "local_baseline_occlusion"
METHOD_DESCRIPTION = (
    "Local leave-one-feature-to-baseline occlusion of IsolationForest "
    "anomaly scores. Approximates feature influence on the current decision; "
    "not exact Shapley values or causal attribution."
)


@dataclass(frozen=True)
class FeatureContribution:
    feature: str
    value: float
    contribution: float
    absolute_contribution: float
    direction: str
    rank: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ExplanationError(ValueError):
    """Raised when an explanation cannot be computed."""


def _as_feature_vector(
    features: Mapping[str, Any] | Sequence[float] | np.ndarray,
    feature_names: Sequence[str],
) -> np.ndarray:
    names = list(feature_names)
    if isinstance(features, Mapping):
        missing = [n for n in names if n not in features]
        if missing:
            raise ExplanationError(f"Missing features for explanation: {missing}")
        values = [float(features[n]) for n in names]
    else:
        arr = np.asarray(features, dtype=float).reshape(-1)
        if arr.shape[0] != len(names):
            raise ExplanationError(
                f"Expected {len(names)} features, got {arr.shape[0]}"
            )
        values = [float(v) for v in arr]

    vector = np.asarray(values, dtype=float)
    if not np.all(np.isfinite(vector)):
        raise ExplanationError("Feature vector contains NaN or Inf")
    return vector


def explain_anomaly(
    detector: AnomalyDetector,
    features: Mapping[str, Any] | Sequence[float] | np.ndarray,
    *,
    feature_names: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Explain an IsolationForest anomaly score for one feature vector.

    Args:
        detector: Fitted ``AnomalyDetector`` (scaler + IsolationForest).
        features: Mapping or length-11 vector in model feature order.
        feature_names: Optional override; defaults to detector names /
            ``MODEL_FEATURE_ORDER``.

    Returns:
        Normalized explanation dict with contributions for every feature.
    """
    if detector is None or not detector.is_fitted:
        raise ExplanationError("Detector must be fitted before explanation")

    names = list(
        feature_names
        or detector.feature_names
        or MODEL_FEATURE_ORDER
    )
    if len(names) != len(MODEL_FEATURE_ORDER):
        # Still allow if detector was trained with the same 11-feature contract.
        if len(names) == 0:
            names = list(MODEL_FEATURE_ORDER)

    x = _as_feature_vector(features, names)
    X = x.reshape(1, -1)

    # Preserve exact inference path: anomaly_scores uses scaler + IF.
    base_score = float(detector.anomaly_scores(X)[0])
    if not np.isfinite(base_score):
        raise ExplanationError("Base anomaly score is not finite")

    means = np.asarray(detector.scaler.mean_, dtype=float)
    if means.shape[0] != x.shape[0]:
        raise ExplanationError(
            f"Scaler mean dimension {means.shape[0]} != features {x.shape[0]}"
        )

    raw_contribs = np.zeros(x.shape[0], dtype=float)
    for i in range(x.shape[0]):
        x_i = x.copy()
        x_i[i] = float(means[i])
        score_i = float(detector.anomaly_scores(x_i.reshape(1, -1))[0])
        if not np.isfinite(score_i):
            raise ExplanationError(f"Occlusion score for '{names[i]}' is not finite")
        raw_contribs[i] = base_score - score_i

    # Stable ranking: higher absolute contribution first; ties by feature order.
    order = sorted(
        range(len(names)),
        key=lambda i: (-abs(float(raw_contribs[i])), i),
    )
    rank_of = {idx: rank for rank, idx in enumerate(order, start=1)}

    contributions: list[FeatureContribution] = []
    for i, name in enumerate(names):
        c = float(raw_contribs[i])
        if c > 0:
            direction = "toward_anomaly"
        elif c < 0:
            direction = "toward_normal"
        else:
            direction = "neutral"
        contributions.append(
            FeatureContribution(
                feature=str(name),
                value=float(x[i]),
                contribution=c,
                absolute_contribution=abs(c),
                direction=direction,
                rank=int(rank_of[i]),
            )
        )

    contributions_sorted = sorted(contributions, key=lambda item: item.rank)
    logger.info(
        "Explanation computed | method=%s score=%.6f top=%s",
        METHOD_NAME,
        base_score,
        contributions_sorted[0].feature if contributions_sorted else None,
    )
    return {
        "method": METHOD_NAME,
        "method_description": METHOD_DESCRIPTION,
        "anomaly_score": base_score,
        "feature_order": list(names),
        "contributions": [c.to_dict() for c in contributions_sorted],
        "disclaimer": (
            "Local approximation of feature influence on the IsolationForest "
            "anomaly score for this flow only. Not causal attribution and not "
            "named-attack classification."
        ),
    }


class IsolationForestExplainer:
    """Thin wrapper around :func:`explain_anomaly` for service use."""

    def __init__(self, detector: AnomalyDetector) -> None:
        self.detector = detector

    def explain(
        self,
        features: Mapping[str, Any] | Sequence[float] | np.ndarray,
    ) -> dict[str, Any]:
        return explain_anomaly(self.detector, features)
