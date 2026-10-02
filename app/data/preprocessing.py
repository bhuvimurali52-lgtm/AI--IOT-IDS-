"""Preprocessing pipeline for tabular IDS datasets.

Transformations are fit on the training split only to prevent data leakage.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

logger = logging.getLogger(__name__)


@dataclass
class PreprocessedData:
    """Container for leakage-safe train/test artifacts."""

    X_train: np.ndarray
    X_test: np.ndarray
    y_train: pd.Series
    y_test: pd.Series
    feature_names: list[str]
    numerical_columns: list[str]
    categorical_columns: list[str]
    preprocessor: ColumnTransformer
    target_column: str
    dropped_duplicates: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


def replace_infinite_with_nan(df: pd.DataFrame) -> pd.DataFrame:
    """Replace +/- inf with NaN so imputers can handle them safely.

    Args:
        df: Input dataframe.

    Returns:
        Copy with infinite values replaced by NaN.
    """
    cleaned = df.replace([np.inf, -np.inf], np.nan)
    return cleaned


def drop_exact_duplicates(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Remove exact duplicate rows.

    Args:
        df: Input dataframe.

    Returns:
        Tuple of ``(deduplicated_dataframe, n_dropped)``.
    """
    before = len(df)
    cleaned = df.drop_duplicates().reset_index(drop=True)
    dropped = before - len(cleaned)
    if dropped:
        logger.info("Removed %d exact duplicate rows", dropped)
    return cleaned, dropped


def identify_column_types(
    X: pd.DataFrame,
) -> tuple[list[str], list[str]]:
    """Identify numerical and categorical feature columns.

    Args:
        X: Feature dataframe (target already removed).

    Returns:
        Tuple of ``(numerical_columns, categorical_columns)``.
    """
    numerical_columns: list[str] = []
    categorical_columns: list[str] = []

    for col in X.columns:
        series = X[col]
        if pd.api.types.is_bool_dtype(series):
            categorical_columns.append(col)
        elif pd.api.types.is_numeric_dtype(series):
            numerical_columns.append(col)
        else:
            categorical_columns.append(col)

    logger.info(
        "Column types | numerical=%d categorical=%d",
        len(numerical_columns),
        len(categorical_columns),
    )
    return numerical_columns, categorical_columns


def build_preprocessor(
    numerical_columns: list[str],
    categorical_columns: list[str],
) -> ColumnTransformer:
    """Build a ColumnTransformer that imputes, scales, and encodes features.

    Args:
        numerical_columns: Names of numeric feature columns.
        categorical_columns: Names of categorical feature columns.

    Returns:
        Unfitted ColumnTransformer suitable for ``fit`` on training data only.
    """
    transformers: list[tuple[str, Any, list[str]]] = []

    if numerical_columns:
        numeric_pipeline = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
            ]
        )
        transformers.append(("num", numeric_pipeline, numerical_columns))

    if categorical_columns:
        categorical_pipeline = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="most_frequent")),
                (
                    "encoder",
                    OneHotEncoder(
                        handle_unknown="ignore",
                        sparse_output=False,
                    ),
                ),
            ]
        )
        transformers.append(("cat", categorical_pipeline, categorical_columns))

    if not transformers:
        raise ValueError("No feature columns available to build a preprocessor.")

    return ColumnTransformer(
        transformers=transformers,
        remainder="drop",
        verbose_feature_names_out=False,
    )


def separate_features_and_target(
    df: pd.DataFrame,
    target_column: str,
) -> tuple[pd.DataFrame, pd.Series]:
    """Split features from the target label column.

    Args:
        df: Cleaned dataframe including the target.
        target_column: Name of the label column.

    Returns:
        Tuple of ``(X, y)``.

    Raises:
        KeyError: If the target column is missing.
    """
    if target_column not in df.columns:
        raise KeyError(
            f"Target column '{target_column}' not found. "
            f"Available: {list(df.columns)}"
        )
    y = df[target_column].copy()
    X = df.drop(columns=[target_column])
    return X, y


def preprocess_dataset(
    df: pd.DataFrame,
    *,
    target_column: str,
    test_size: float = 0.2,
    random_state: int = 42,
) -> PreprocessedData:
    """Clean, split, and transform a dataset without leakage.

    Pipeline:
        1. Drop exact duplicates
        2. Replace infinite values with NaN
        3. Separate features/target
        4. Train/test split
        5. Fit preprocessor on training features only
        6. Transform train and test with the fitted preprocessor

    Args:
        df: Raw loaded dataframe.
        target_column: Label column name.
        test_size: Fraction reserved for the test set.
        random_state: Seed for reproducible splits.

    Returns:
        PreprocessedData with arrays, labels, feature names, and fitted pipeline.
    """
    if not 0.0 < test_size < 1.0:
        raise ValueError(f"test_size must be between 0 and 1, got {test_size}")

    working = df.copy()
    working, dropped_duplicates = drop_exact_duplicates(working)
    working = replace_infinite_with_nan(working)

    X, y = separate_features_and_target(working, target_column)
    numerical_columns, categorical_columns = identify_column_types(X)

    stratify = y if y.nunique() > 1 and y.value_counts().min() >= 2 else None
    if stratify is None:
        logger.warning(
            "Skipping stratified split (insufficient class counts for stratification)."
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )

    preprocessor = build_preprocessor(numerical_columns, categorical_columns)
    # Fit ONLY on training data to prevent leakage into the test set.
    X_train_transformed = preprocessor.fit_transform(X_train)
    X_test_transformed = preprocessor.transform(X_test)

    feature_names = list(preprocessor.get_feature_names_out())

    result = PreprocessedData(
        X_train=np.asarray(X_train_transformed),
        X_test=np.asarray(X_test_transformed),
        y_train=y_train.reset_index(drop=True),
        y_test=y_test.reset_index(drop=True),
        feature_names=feature_names,
        numerical_columns=numerical_columns,
        categorical_columns=categorical_columns,
        preprocessor=preprocessor,
        target_column=target_column,
        dropped_duplicates=dropped_duplicates,
        metadata={
            "test_size": test_size,
            "random_state": random_state,
            "n_train": int(len(y_train)),
            "n_test": int(len(y_test)),
            "n_features": len(feature_names),
            "class_counts_train": y_train.value_counts().to_dict(),
            "class_counts_test": y_test.value_counts().to_dict(),
        },
    )

    logger.info(
        "Preprocessing complete | train=%d test=%d features=%d duplicates_removed=%d",
        result.metadata["n_train"],
        result.metadata["n_test"],
        result.metadata["n_features"],
        dropped_duplicates,
    )
    return result


def save_processed_artifacts(
    data: PreprocessedData,
    output_dir: Path | str,
) -> dict[str, Path]:
    """Persist processed arrays, labels, preprocessor, and metadata.

    Args:
        data: Output of :func:`preprocess_dataset`.
        output_dir: Destination directory (created if missing).

    Returns:
        Mapping of artifact name to written path.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    paths: dict[str, Path] = {
        "X_train": out / "X_train.csv",
        "X_test": out / "X_test.csv",
        "y_train": out / "y_train.csv",
        "y_test": out / "y_test.csv",
        "preprocessor": out / "preprocessor.joblib",
        "metadata": out / "metadata.json",
        "feature_names": out / "feature_names.json",
    }

    pd.DataFrame(data.X_train, columns=data.feature_names).to_csv(
        paths["X_train"], index=False
    )
    pd.DataFrame(data.X_test, columns=data.feature_names).to_csv(
        paths["X_test"], index=False
    )
    data.y_train.to_frame(name=data.target_column).to_csv(
        paths["y_train"], index=False
    )
    data.y_test.to_frame(name=data.target_column).to_csv(
        paths["y_test"], index=False
    )
    joblib.dump(data.preprocessor, paths["preprocessor"])

    metadata = {
        **data.metadata,
        "target_column": data.target_column,
        "numerical_columns": data.numerical_columns,
        "categorical_columns": data.categorical_columns,
        "dropped_duplicates": data.dropped_duplicates,
        "feature_names": data.feature_names,
    }
    # Convert non-JSON-native keys (e.g. numpy ints in class counts)
    metadata["class_counts_train"] = {
        str(k): int(v) for k, v in metadata["class_counts_train"].items()
    }
    metadata["class_counts_test"] = {
        str(k): int(v) for k, v in metadata["class_counts_test"].items()
    }

    paths["metadata"].write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    paths["feature_names"].write_text(
        json.dumps(data.feature_names, indent=2), encoding="utf-8"
    )

    logger.info("Saved processed artifacts to %s", out.resolve())
    return paths
