"""Offline evaluation of the existing IsolationForest anomaly detector.

Scientifically scoped to a controlled synthetic labeled dataset.
Does not retrain the model and does not modify production thresholds.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import numpy as np

from app.detection.anomaly_detector import AnomalyDetector
from app.evaluation.datasets import (
    EVAL_DEFAULT_N_ANOMALOUS,
    EVAL_DEFAULT_N_NORMAL,
    EVAL_DEFAULT_SEED,
    build_labeled_evaluation_records,
    evaluation_matrix_from_records,
)
from app.features.extractor import MODEL_FEATURE_ORDER

logger = logging.getLogger(__name__)


def _safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return float(numerator) / float(denominator)


def confusion_counts(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, int]:
    """Binary confusion counts with positive class = anomalous (1)."""
    yt = np.asarray(y_true, dtype=int).ravel()
    yp = np.asarray(y_pred, dtype=int).ravel()
    if yt.shape != yp.shape:
        raise ValueError("y_true and y_pred length mismatch")
    tp = int(np.sum((yt == 1) & (yp == 1)))
    tn = int(np.sum((yt == 0) & (yp == 0)))
    fp = int(np.sum((yt == 0) & (yp == 1)))
    fn = int(np.sum((yt == 1) & (yp == 0)))
    return {"tn": tn, "fp": fp, "fn": fn, "tp": tp}


def metrics_from_confusion(cm: dict[str, int]) -> dict[str, float]:
    """Derive classification metrics with zero-division-safe formulas."""
    tn, fp, fn, tp = cm["tn"], cm["fp"], cm["fn"], cm["tp"]
    total = tn + fp + fn + tp
    accuracy = _safe_div(tp + tn, total)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    specificity = _safe_div(tn, tn + fp)
    fpr = _safe_div(fp, fp + tn)
    fnr = _safe_div(fn, fn + tp)
    # Anomaly detection rate == recall on the anomalous class for this binary setup.
    anomaly_detection_rate = recall
    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "specificity": float(specificity),
        "false_positive_rate": float(fpr),
        "false_negative_rate": float(fnr),
        "anomaly_detection_rate": float(anomaly_detection_rate),
    }


def predict_binary_from_isolation_forest(detector: AnomalyDetector, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Run existing inference path; return (anomaly_scores, y_pred 0/1).

    IsolationForest ``predict``: 1 = inlier/normal, -1 = outlier/anomalous.
    ``y_pred`` maps anomalous → 1, normal → 0. Labels are never used here.
    """
    scores = np.asarray(detector.anomaly_scores(X), dtype=float).ravel()
    raw = np.asarray(detector.predict(X), dtype=int).ravel()
    y_pred = (raw == -1).astype(int)
    return scores, y_pred


def predict_binary_from_scores(scores: np.ndarray, threshold: float) -> np.ndarray:
    """Offline threshold rule on anomaly scores (higher ⇒ more anomalous)."""
    return (np.asarray(scores, dtype=float).ravel() >= float(threshold)).astype(int)


def threshold_analysis(
    y_true: np.ndarray,
    scores: np.ndarray,
    *,
    thresholds: list[float] | None = None,
    n_thresholds: int = 21,
) -> list[dict[str, Any]]:
    """Sweep anomaly-score thresholds without changing the production detector."""
    scores = np.asarray(scores, dtype=float).ravel()
    y_true = np.asarray(y_true, dtype=int).ravel()
    if thresholds is None:
        lo = float(np.min(scores))
        hi = float(np.max(scores))
        if lo == hi:
            thresholds = [lo]
        else:
            thresholds = [
                float(v)
                for v in np.linspace(lo, hi, num=max(2, int(n_thresholds)))
            ]
    rows: list[dict[str, Any]] = []
    for thr in thresholds:
        y_pred = predict_binary_from_scores(scores, thr)
        cm = confusion_counts(y_true, y_pred)
        mets = metrics_from_confusion(cm)
        rows.append(
            {
                "threshold": float(thr),
                "tn": cm["tn"],
                "fp": cm["fp"],
                "fn": cm["fn"],
                "tp": cm["tp"],
                "precision": mets["precision"],
                "recall": mets["recall"],
                "f1": mets["f1"],
                "specificity": mets["specificity"],
                "false_positive_rate": mets["false_positive_rate"],
                "false_negative_rate": mets["false_negative_rate"],
            }
        )
    return rows


def evaluate_detector(
    detector: AnomalyDetector,
    X: np.ndarray,
    y_true: np.ndarray,
    *,
    feature_names: list[str] | None = None,
    include_threshold_analysis: bool = True,
) -> dict[str, Any]:
    """Evaluate a fitted detector on labeled features (labels unused in inference)."""
    if not detector.is_fitted:
        raise RuntimeError("Detector must be fitted/loaded before evaluation")
    X = np.asarray(X, dtype=float)
    y_true = np.asarray(y_true, dtype=int).ravel()
    if X.ndim != 2 or X.shape[0] != y_true.shape[0]:
        raise ValueError("X and y_true shape mismatch")
    if X.shape[1] != 11:
        raise ValueError(f"Expected 11 features, got {X.shape[1]}")

    names = list(feature_names or MODEL_FEATURE_ORDER)
    scores, y_pred = predict_binary_from_isolation_forest(detector, X)
    cm = confusion_counts(y_true, y_pred)
    mets = metrics_from_confusion(cm)

    n_normal = int(np.sum(y_true == 0))
    n_anom = int(np.sum(y_true == 1))
    result: dict[str, Any] = {
        "scope": "controlled_synthetic_evaluation",
        "limitation": (
            "These metrics measure performance on the controlled synthetic "
            "evaluation dataset and should not be interpreted as production "
            "IDS performance. The detector is an anomaly / deviation model, "
            "not a named-attack classifier."
        ),
        "feature_order": names,
        "dataset": {
            "total": int(y_true.shape[0]),
            "normal": n_normal,
            "anomalous": n_anom,
        },
        "predictions": {
            "normal": int(np.sum(y_pred == 0)),
            "anomalous": int(np.sum(y_pred == 1)),
        },
        "confusion_matrix": cm,
        "metrics": mets,
        "anomaly_scores_summary": {
            "min": float(np.min(scores)),
            "max": float(np.max(scores)),
            "mean": float(np.mean(scores)),
        },
    }
    if include_threshold_analysis:
        result["threshold_analysis"] = threshold_analysis(y_true, scores)
    return result


def run_offline_evaluation(
    *,
    model_path: Path | str,
    n_normal: int = EVAL_DEFAULT_N_NORMAL,
    n_anomalous: int = EVAL_DEFAULT_N_ANOMALOUS,
    seed: int = EVAL_DEFAULT_SEED,
    include_threshold_analysis: bool = True,
) -> dict[str, Any]:
    """Load existing model artifact and evaluate on a labeled synthetic set.

    Does not retrain. Does not modify the model file.
    """
    path = Path(model_path)
    if not path.exists():
        raise FileNotFoundError(f"Model artifact not found: {path}")

    records = build_labeled_evaluation_records(
        n_normal=n_normal, n_anomalous=n_anomalous, seed=seed
    )
    X, y_true, names = evaluation_matrix_from_records(records)
    detector = AnomalyDetector.load(path)
    result = evaluate_detector(
        detector,
        X,
        y_true,
        feature_names=names,
        include_threshold_analysis=include_threshold_analysis,
    )
    result["model_path"] = str(path)
    result["n_training_samples_in_artifact"] = int(detector.n_training_samples)
    result["evaluation_seed"] = int(seed)
    result["n_normal_requested"] = int(n_normal)
    result["n_anomalous_requested"] = int(n_anomalous)
    logger.info(
        "Offline evaluation complete | total=%d accuracy=%.4f f1=%.4f (synthetic only)",
        result["dataset"]["total"],
        result["metrics"]["accuracy"],
        result["metrics"]["f1"],
    )
    return result
