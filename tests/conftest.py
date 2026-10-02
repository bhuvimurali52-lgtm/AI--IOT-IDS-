"""Shared pytest fixtures for Phase 2 data-pipeline tests.

Synthetic CSVs here are **test fixtures only** — they are not a real IDS dataset.
Place the real dataset under ``data/raw/`` (see README).
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest


@pytest.fixture
def synthetic_ids_frame() -> pd.DataFrame:
    """Small clearly-labelled synthetic tabular fixture for preprocessing tests."""
    return pd.DataFrame(
        {
            "duration": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 2.0, 8.0, 9.0, 10.0],
            "packet_count": [10, 20, None, 40, 50, 60, 20, 80, 90, 100],
            "protocol": [
                "TCP",
                "UDP",
                "TCP",
                "ICMP",
                "TCP",
                "UDP",
                "UDP",
                "TCP",
                "ICMP",
                "TCP",
            ],
            "bytes_sent": [
                100.0,
                200.0,
                float("inf"),
                400.0,
                500.0,
                600.0,
                200.0,
                800.0,
                900.0,
                1000.0,
            ],
            "label": [
                "benign",
                "attack",
                "benign",
                "attack",
                "benign",
                "attack",
                "attack",
                "benign",
                "attack",
                "benign",
            ],
        }
    )


@pytest.fixture
def synthetic_csv_path(tmp_path: Path, synthetic_ids_frame: pd.DataFrame) -> Path:
    """Write the synthetic fixture to a temporary CSV path."""
    path = tmp_path / "synthetic_ids_fixture.csv"
    synthetic_ids_frame.to_csv(path, index=False)
    return path
