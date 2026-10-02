"""Dataset loading utilities for CSV-based IoT/network IDS datasets."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)


class DatasetNotFoundError(FileNotFoundError):
    """Raised when the configured dataset file does not exist."""


class DatasetValidationError(ValueError):
    """Raised when a dataset fails structural validation."""


@dataclass(frozen=True)
class DatasetReport:
    """Summary statistics produced when a dataset is loaded."""

    path: Path
    n_rows: int
    n_columns: int
    columns: list[str]
    missing_values: dict[str, int]
    duplicate_rows: int
    target_column: str | None
    dtypes: dict[str, str] = field(default_factory=dict)

    @property
    def total_missing(self) -> int:
        """Total count of missing cell values across all columns."""
        return int(sum(self.missing_values.values()))


def _resolve_path(path: Path | str) -> Path:
    """Normalize a dataset path to an absolute Path."""
    return Path(path).expanduser().resolve()


def validate_dataset_path(path: Path | str) -> Path:
    """Validate that a dataset file exists and is a CSV.

    Args:
        path: Candidate dataset path.

    Returns:
        Resolved absolute path to the dataset file.

    Raises:
        DatasetNotFoundError: If the file does not exist.
        DatasetValidationError: If the path is not a CSV file.
    """
    resolved = _resolve_path(path)
    if not resolved.exists():
        raise DatasetNotFoundError(
            f"Dataset file not found: {resolved}. "
            "Place your IDS CSV under data/raw/ and set DATASET_PATH "
            "(or pass --dataset to scripts/prepare_dataset.py)."
        )
    if not resolved.is_file():
        raise DatasetValidationError(f"Dataset path is not a file: {resolved}")
    if resolved.suffix.lower() != ".csv":
        raise DatasetValidationError(
            f"Unsupported dataset format '{resolved.suffix}'. "
            "Phase 2 expects a CSV file."
        )
    return resolved


def build_dataset_report(
    df: pd.DataFrame,
    path: Path,
    target_column: str | None = None,
) -> DatasetReport:
    """Build a structured report of dataset statistics.

    Args:
        df: Loaded dataframe.
        path: Source file path.
        target_column: Optional label column name to validate/identify.

    Returns:
        DatasetReport with shape, missing values, duplicates, and dtypes.

    Raises:
        DatasetValidationError: If ``target_column`` is set but missing.
    """
    if target_column is not None and target_column not in df.columns:
        raise DatasetValidationError(
            f"Target column '{target_column}' not found in dataset. "
            f"Available columns: {list(df.columns)}"
        )

    missing = {
        col: int(count)
        for col, count in df.isna().sum().items()
        if int(count) > 0
    }
    report = DatasetReport(
        path=path,
        n_rows=int(df.shape[0]),
        n_columns=int(df.shape[1]),
        columns=list(df.columns.astype(str)),
        missing_values=missing,
        duplicate_rows=int(df.duplicated().sum()),
        target_column=target_column,
        dtypes={col: str(dtype) for col, dtype in df.dtypes.items()},
    )
    return report


def log_dataset_report(report: DatasetReport) -> None:
    """Log a concise human-readable summary of a DatasetReport."""
    logger.info(
        "Loaded dataset %s | rows=%d cols=%d missing_cells=%d duplicates=%d target=%s",
        report.path.name,
        report.n_rows,
        report.n_columns,
        report.total_missing,
        report.duplicate_rows,
        report.target_column,
    )
    if report.missing_values:
        logger.info("Missing values by column: %s", report.missing_values)
    else:
        logger.info("No missing values detected.")


def load_dataset(
    path: Path | str,
    *,
    target_column: str | None = None,
) -> tuple[pd.DataFrame, DatasetReport]:
    """Load a CSV intrusion-detection dataset and return it with a report.

    Args:
        path: Path to a CSV file.
        target_column: Optional label/target column to validate.

    Returns:
        Tuple of ``(dataframe, DatasetReport)``.

    Raises:
        DatasetNotFoundError: If the file is missing.
        DatasetValidationError: If the file is invalid or target is missing.
    """
    resolved = validate_dataset_path(path)
    logger.info("Loading dataset from %s", resolved)

    try:
        df = pd.read_csv(resolved)
    except pd.errors.EmptyDataError as exc:
        raise DatasetValidationError(f"Dataset CSV is empty: {resolved}") from exc
    except Exception as exc:  # noqa: BLE001 - surface parse errors clearly
        raise DatasetValidationError(
            f"Failed to read dataset CSV '{resolved}': {exc}"
        ) from exc

    if df.empty:
        raise DatasetValidationError(f"Dataset has no rows: {resolved}")
    if df.shape[1] == 0:
        raise DatasetValidationError(f"Dataset has no columns: {resolved}")

    # Normalize column names (strip whitespace common in IDS CSVs).
    df.columns = [str(c).strip() for c in df.columns]

    report = build_dataset_report(df, resolved, target_column=target_column)
    log_dataset_report(report)
    return df, report
