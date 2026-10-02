"""Tests for the tabular + flow feature extractor."""

from __future__ import annotations

import pandas as pd
import pytest

from app.features.extractor import (
    FLOW_FEATURE_NAMES,
    FeatureExtractor,
    extract_features,
    flow_record_to_feature_dict,
)


def test_extract_features_excludes_columns(synthetic_ids_frame: pd.DataFrame) -> None:
    features = extract_features(
        synthetic_ids_frame,
        exclude_columns=["label"],
    )
    assert "label" not in features.columns
    assert list(features.columns) == [
        "duration",
        "packet_count",
        "protocol",
        "bytes_sent",
    ]


def test_extract_features_explicit_order(synthetic_ids_frame: pd.DataFrame) -> None:
    ordered = extract_features(
        synthetic_ids_frame,
        feature_columns=["protocol", "duration"],
    )
    assert list(ordered.columns) == ["protocol", "duration"]


def test_missing_requested_feature_raises(synthetic_ids_frame: pd.DataFrame) -> None:
    with pytest.raises(KeyError, match="Requested feature columns"):
        extract_features(
            synthetic_ids_frame,
            feature_columns=["does_not_exist"],
        )


def test_resolve_target_alias() -> None:
    extractor = FeatureExtractor()
    assert (
        extractor.resolve_target_column(["src", "Label"], preferred="label")
        == "Label"
    )


def test_from_flow_record_deterministic() -> None:
    extractor = FeatureExtractor()
    record = {
        "duration": 1.5,
        "packet_count": 10,
        "byte_count": 1500,
        "source_port": 443,
        "destination_port": 8080,
        "protocol": "TCP",
    }
    a = extractor.from_flow_record(record)
    b = extractor.from_flow_record(record)
    assert list(a.columns) == FLOW_FEATURE_NAMES
    assert a.equals(b)
    assert a.loc[0, "protocol"] == 6.0


def test_missing_flow_fields_use_defaults() -> None:
    features = flow_record_to_feature_dict({})
    assert features == {name: 0.0 for name in FLOW_FEATURE_NAMES}


def test_from_packet_not_supported() -> None:
    extractor = FeatureExtractor()
    with pytest.raises(NotImplementedError, match="Aggregate packets"):
        extractor.from_packet(object())
