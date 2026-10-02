"""Tests for preprocessing and leakage prevention (Phase 2)."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from app.data.preprocessing import (
    build_preprocessor,
    drop_exact_duplicates,
    identify_column_types,
    preprocess_dataset,
    replace_infinite_with_nan,
    save_processed_artifacts,
    separate_features_and_target,
)


def test_drop_exact_duplicates(synthetic_ids_frame: pd.DataFrame) -> None:
    """Exact duplicate rows are removed."""
    cleaned, dropped = drop_exact_duplicates(synthetic_ids_frame)
    assert dropped == 1
    assert len(cleaned) == len(synthetic_ids_frame) - 1
    assert cleaned.duplicated().sum() == 0


def test_missing_and_infinite_value_handling(synthetic_ids_frame: pd.DataFrame) -> None:
    """Missing and infinite values are handled and produce finite features."""
    assert synthetic_ids_frame["packet_count"].isna().sum() == 1
    assert np.isinf(synthetic_ids_frame["bytes_sent"]).sum() == 1

    result = preprocess_dataset(
        synthetic_ids_frame,
        target_column="label",
        test_size=0.3,
        random_state=42,
    )

    assert np.isfinite(result.X_train).all()
    assert np.isfinite(result.X_test).all()
    assert result.X_train.shape[0] + result.X_test.shape[0] == (
        len(synthetic_ids_frame) - result.dropped_duplicates
    )


def test_replace_infinite_with_nan() -> None:
    """Infinite values become NaN before imputation."""
    df = pd.DataFrame({"x": [1.0, np.inf, -np.inf]})
    cleaned = replace_infinite_with_nan(df)
    assert cleaned["x"].isna().sum() == 2


def test_categorical_encoding_produces_numeric_matrix(
    synthetic_ids_frame: pd.DataFrame,
) -> None:
    """Categorical columns are encoded into a numeric feature matrix."""
    numerical, categorical = identify_column_types(
        synthetic_ids_frame.drop(columns=["label"])
    )
    assert "protocol" in categorical
    assert "duration" in numerical

    result = preprocess_dataset(
        synthetic_ids_frame,
        target_column="label",
        test_size=0.3,
        random_state=0,
    )
    assert result.X_train.dtype.kind in {"f", "i", "u"}
    assert any("protocol" in name for name in result.feature_names)
    assert len(result.y_train) == result.X_train.shape[0]
    assert len(result.y_test) == result.X_test.shape[0]


def test_train_test_split_reproducible(synthetic_ids_frame: pd.DataFrame) -> None:
    """Same random_state yields identical splits/transforms."""
    a = preprocess_dataset(
        synthetic_ids_frame, target_column="label", test_size=0.3, random_state=7
    )
    b = preprocess_dataset(
        synthetic_ids_frame, target_column="label", test_size=0.3, random_state=7
    )
    np.testing.assert_allclose(a.X_train, b.X_train)
    np.testing.assert_allclose(a.X_test, b.X_test)
    assert list(a.y_train) == list(b.y_train)
    assert list(a.y_test) == list(b.y_test)


def test_no_preprocessing_leakage_scaler_uses_train_stats() -> None:
    """StandardScaler statistics must match the training split only."""
    # Unique rows so deduplication does not collapse the train/full mean gap.
    df = pd.DataFrame(
        {
            "feat": [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 90.0, 91.0, 92.0, 93.0],
            "noise": list(range(10)),
            "label": ["a", "b", "a", "b", "a", "b", "a", "b", "a", "b"],
        }
    )
    cleaned, dropped = drop_exact_duplicates(df)
    assert dropped == 0
    cleaned = replace_infinite_with_nan(cleaned)
    X, y = separate_features_and_target(cleaned, "label")
    X_train, X_test, _, _ = train_test_split(
        X, y, test_size=0.4, random_state=42, stratify=y
    )

    numerical, categorical = identify_column_types(X)
    preprocessor = build_preprocessor(numerical, categorical)
    preprocessor.fit(X_train)

    scaler: StandardScaler = preprocessor.named_transformers_["num"].named_steps[
        "scaler"
    ]
    # ColumnTransformer keeps column order: feat, noise
    expected_train_mean = float(X_train["feat"].mean())
    full_mean = float(X["feat"].mean())

    assert np.isclose(scaler.mean_[0], expected_train_mean)
    assert not np.isclose(expected_train_mean, full_mean), (
        "Test setup invalid: train mean equals full-data mean."
    )

    # End-to-end API must also center the training matrix near zero.
    result = preprocess_dataset(
        df, target_column="label", test_size=0.4, random_state=42
    )
    assert abs(float(np.mean(result.X_train[:, 0]))) < 1e-8


def test_unknown_category_in_test_does_not_fail() -> None:
    """Categories unseen during training do not crash transform()."""
    df = pd.DataFrame(
        {
            "duration": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0],
            "protocol": ["TCP", "TCP", "UDP", "UDP", "TCP", "UDP", "ICMP", "NEWPROTO"],
            "label": [
                "benign",
                "attack",
                "benign",
                "attack",
                "benign",
                "attack",
                "benign",
                "attack",
            ],
        }
    )
    result = preprocess_dataset(
        df, target_column="label", test_size=0.25, random_state=1
    )
    assert result.X_test.shape[1] == result.X_train.shape[1]
    assert np.isfinite(result.X_test).all()


def test_save_processed_artifacts(
    synthetic_ids_frame: pd.DataFrame,
    tmp_path,
) -> None:
    """Artifacts are written to the processed output directory."""
    result = preprocess_dataset(
        synthetic_ids_frame, target_column="label", test_size=0.3, random_state=0
    )
    paths = save_processed_artifacts(result, tmp_path / "processed")
    for key in ("X_train", "X_test", "y_train", "y_test", "preprocessor", "metadata"):
        assert paths[key].exists()
