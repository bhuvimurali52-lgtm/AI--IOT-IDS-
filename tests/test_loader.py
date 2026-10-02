"""Tests for CSV dataset loading (Phase 2)."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from app.data.loader import (
    DatasetNotFoundError,
    DatasetValidationError,
    load_dataset,
    validate_dataset_path,
)


def test_load_dataset_success(synthetic_csv_path: Path) -> None:
    """Loader returns a dataframe and a useful report."""
    df, report = load_dataset(synthetic_csv_path, target_column="label")

    assert len(df) == 10
    assert report.n_rows == 10
    assert report.n_columns == 5
    assert report.target_column == "label"
    assert "packet_count" in report.missing_values
    assert report.duplicate_rows >= 0
    assert "label" in report.columns


def test_missing_file_raises_useful_error(tmp_path: Path) -> None:
    """Missing dataset paths raise DatasetNotFoundError with guidance."""
    missing = tmp_path / "does_not_exist.csv"
    with pytest.raises(DatasetNotFoundError, match="Dataset file not found"):
        load_dataset(missing)


def test_validate_dataset_path_rejects_non_csv(tmp_path: Path) -> None:
    """Non-CSV files are rejected."""
    bad = tmp_path / "notes.txt"
    bad.write_text("not a csv", encoding="utf-8")
    with pytest.raises(DatasetValidationError, match="Unsupported dataset format"):
        validate_dataset_path(bad)


def test_missing_target_column_raises(synthetic_csv_path: Path) -> None:
    """Unknown target columns raise DatasetValidationError."""
    with pytest.raises(DatasetValidationError, match="Target column"):
        load_dataset(synthetic_csv_path, target_column="not_a_real_column")


def test_report_identifies_duplicates(tmp_path: Path) -> None:
    """Duplicate rows are counted in the dataset report."""
    df = pd.DataFrame(
        {
            "a": [1, 1, 2],
            "b": ["x", "x", "y"],
            "label": ["benign", "benign", "attack"],
        }
    )
    path = tmp_path / "dupes.csv"
    df.to_csv(path, index=False)

    _, report = load_dataset(path, target_column="label")
    assert report.duplicate_rows == 1
