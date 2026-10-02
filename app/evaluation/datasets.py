"""Deterministic labeled evaluation datasets for Phase 7.

Ground-truth labels are for offline evaluation only and are never passed to
the IsolationForest during inference.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np

from app.capture.synthetic import generate_synthetic_flow_records
from app.features.extractor import MODEL_FEATURE_ORDER, flow_records_to_matrix

logger = logging.getLogger(__name__)

GROUND_TRUTH_NORMAL = 0
GROUND_TRUTH_ANOMALOUS = 1

EVAL_DEFAULT_N_NORMAL = 50
EVAL_DEFAULT_N_ANOMALOUS = 50
EVAL_DEFAULT_SEED = 42


def build_labeled_evaluation_records(
    *,
    n_normal: int = EVAL_DEFAULT_N_NORMAL,
    n_anomalous: int = EVAL_DEFAULT_N_ANOMALOUS,
    seed: int = EVAL_DEFAULT_SEED,
) -> list[dict[str, Any]]:
    """Build a controlled synthetic evaluation set with explicit ground_truth.

    Uses the existing synthetic flow generator (deterministic feature values).
    ``seed`` is retained for API/reproducibility documentation; the underlying
    synthetic fixtures are already index-deterministic.
    """
    if n_normal < 1 or n_anomalous < 1:
        raise ValueError("Evaluation dataset requires both normal and anomalous samples")

    # Fixed timestamp so wall-clock time cannot affect reproducibility metadata.
    fixed_ts = 1_700_000_000.0 + float(seed)
    raw = generate_synthetic_flow_records(n_normal=n_normal, n_anomalous=n_anomalous)
    records: list[dict[str, Any]] = []
    for row in raw:
        item = dict(row)
        item["created_at"] = fixed_ts
        profile = str(item.get("traffic_profile", "")).lower()
        if profile == "anomalous":
            item["ground_truth"] = GROUND_TRUTH_ANOMALOUS
            item["ground_truth_label"] = "anomalous"
        else:
            item["ground_truth"] = GROUND_TRUTH_NORMAL
            item["ground_truth_label"] = "normal"
        item["data_source"] = "synthetic"
        item["evaluation_set"] = "controlled_synthetic"
        records.append(item)

    n0 = sum(1 for r in records if r["ground_truth"] == GROUND_TRUTH_NORMAL)
    n1 = sum(1 for r in records if r["ground_truth"] == GROUND_TRUTH_ANOMALOUS)
    logger.info(
        "Built labeled evaluation set | total=%d normal=%d anomalous=%d seed=%d",
        len(records),
        n0,
        n1,
        seed,
    )
    return records


def evaluation_matrix_from_records(
    records: list[dict[str, Any]],
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Return ``(X, y_true, feature_names)`` without including labels in ``X``."""
    if not records:
        raise ValueError("No evaluation records provided")
    if any("ground_truth" not in r for r in records):
        raise ValueError("All evaluation records must include ground_truth")

    X, names = flow_records_to_matrix(records)
    if names != list(MODEL_FEATURE_ORDER):
        raise ValueError(
            f"Feature order mismatch: got {names}, expected {list(MODEL_FEATURE_ORDER)}"
        )
    if X.shape[1] != 11:
        raise ValueError(f"Expected 11 features, got {X.shape[1]}")

    y_true = np.asarray([int(r["ground_truth"]) for r in records], dtype=int)
    # Sanity: labels must not be columns of X (X only has the 11 model features).
    assert X.shape[0] == y_true.shape[0]
    return X, y_true, names
