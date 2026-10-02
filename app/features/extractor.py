"""Feature extraction for tabular CSV rows and Phase 3 network flows.

Feature documentation (flow / Isolation Forest vector)
------------------------------------------------------
All flow features are deterministic. Missing values use documented defaults
(never random):

| Feature               | Meaning                                      | Default |
|-----------------------|----------------------------------------------|---------|
| duration              | Flow duration (seconds)                      | 0.0     |
| packet_count          | Number of packets in the flow                | 0.0     |
| byte_count            | Total bytes in the flow                      | 0.0     |
| packets_per_second    | packet_count / duration                      | 0.0     |
| bytes_per_second      | byte_count / duration                        | 0.0     |
| average_packet_size   | byte_count / packet_count                    | 0.0     |
| min_packet_size       | Smallest packet length                       | 0.0     |
| max_packet_size       | Largest packet length                        | 0.0     |
| source_port           | Source L4 port                               | 0.0     |
| destination_port      | Destination L4 port                          | 0.0     |
| protocol              | Encoded protocol (TCP=6, UDP=17, ICMP=1,     | 0.0     |
|                       | OTHER=0)                                     |         |

Tabular CSV extraction (Phase 2) only selects existing columns and does not
invent features.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

DATASET_COLUMN_ALIASES: dict[str, list[str]] = {
    "label": ["label", "Label", "attack", "Attack", "class", "Class", "y"],
}

# Deterministic Isolation Forest feature order for flow-based detection.
# MODEL_FEATURE_ORDER is the canonical Phase 3/4 contract — do not reorder.
FLOW_FEATURE_NAMES: list[str] = [
    "duration",
    "packet_count",
    "byte_count",
    "packets_per_second",
    "bytes_per_second",
    "average_packet_size",
    "min_packet_size",
    "max_packet_size",
    "source_port",
    "destination_port",
    "protocol",
]

# Exact 11-feature order used by the trained IsolationForest (Phase 3).
MODEL_FEATURE_ORDER: tuple[str, ...] = tuple(FLOW_FEATURE_NAMES)

PROTOCOL_ENCODING: dict[str, float] = {
    "TCP": 6.0,
    "UDP": 17.0,
    "ICMP": 1.0,
    "OTHER": 0.0,
}

_FLOW_DEFAULTS: dict[str, float] = {name: 0.0 for name in FLOW_FEATURE_NAMES}


def encode_protocol(value: Any) -> float:
    """Map a protocol label or number to a deterministic float code."""
    if value is None:
        return 0.0
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    key = str(value).strip().upper()
    return PROTOCOL_ENCODING.get(key, 0.0)


def flow_record_to_feature_dict(record: Mapping[str, Any]) -> dict[str, float]:
    """Convert a flow mapping into the fixed numerical feature dict.

    Missing keys use documented safe defaults (0.0). No random values.
    """
    features = dict(_FLOW_DEFAULTS)

    def _num(key: str, *aliases: str) -> float:
        for name in (key, *aliases):
            if name in record and record[name] is not None:
                try:
                    val = float(record[name])
                    if np.isfinite(val):
                        return val
                except (TypeError, ValueError):
                    return 0.0
        return 0.0

    features["duration"] = _num("duration")
    features["packet_count"] = _num("packet_count")
    features["byte_count"] = _num("byte_count", "bytes_sent", "total_bytes")
    features["packets_per_second"] = _num("packets_per_second")
    features["bytes_per_second"] = _num("bytes_per_second")
    features["average_packet_size"] = _num("average_packet_size")
    features["min_packet_size"] = _num("min_packet_size")
    features["max_packet_size"] = _num("max_packet_size")
    features["source_port"] = _num("source_port", "src_port")
    features["destination_port"] = _num("destination_port", "dst_port")
    features["protocol"] = encode_protocol(
        record.get("protocol", record.get("proto", "OTHER"))
    )

    # Derive rates if missing but counts/duration are present.
    duration = max(features["duration"], 1e-6)
    if features["packets_per_second"] == 0.0 and features["packet_count"] > 0:
        features["packets_per_second"] = features["packet_count"] / duration
    if features["bytes_per_second"] == 0.0 and features["byte_count"] > 0:
        features["bytes_per_second"] = features["byte_count"] / duration
    if features["average_packet_size"] == 0.0 and features["packet_count"] > 0:
        features["average_packet_size"] = (
            features["byte_count"] / features["packet_count"]
        )

    return features


def flow_records_to_matrix(
    records: Sequence[Mapping[str, Any]],
) -> tuple[np.ndarray, list[str]]:
    """Build a deterministic feature matrix from flow records.

    Returns:
        Tuple of ``(X, feature_names)`` with columns in FLOW_FEATURE_NAMES /
        MODEL_FEATURE_ORDER order.
    """
    rows = [flow_record_to_feature_dict(r) for r in records]
    if not rows:
        return np.empty((0, len(MODEL_FEATURE_ORDER)), dtype=float), list(
            MODEL_FEATURE_ORDER
        )
    frame = pd.DataFrame(rows, columns=list(MODEL_FEATURE_ORDER))
    return frame.to_numpy(dtype=float), list(MODEL_FEATURE_ORDER)


class FeatureValidationError(ValueError):
    """Raised when a flow cannot be converted into a valid model feature vector."""


def validate_model_features(features: Mapping[str, Any]) -> list[float]:
    """Validate and return the Phase 3 model feature vector in exact order.

    Args:
        features: Mapping of feature name -> value.

    Returns:
        List of 11 finite floats in ``MODEL_FEATURE_ORDER``.

    Raises:
        FeatureValidationError: If required features are missing, non-numeric,
            or non-finite.
    """
    values: list[float] = []
    missing = [name for name in MODEL_FEATURE_ORDER if name not in features]
    if missing:
        raise FeatureValidationError(f"Missing model features: {missing}")

    for name in MODEL_FEATURE_ORDER:
        try:
            val = float(features[name])
        except (TypeError, ValueError) as exc:
            raise FeatureValidationError(
                f"Feature '{name}' is not numeric: {features[name]!r}"
            ) from exc
        if not np.isfinite(val):
            raise FeatureValidationError(f"Feature '{name}' is not finite: {val}")
        values.append(val)
    return values


def flow_to_model_vector(record: Mapping[str, Any]) -> list[float]:
    """Convert a flow record to the validated Phase 3 model feature vector."""
    features = flow_record_to_feature_dict(record)
    return validate_model_features(features)


class FeatureExtractor:
    """Extract tabular CSV features (Phase 2) and flow vectors (Phase 3)."""

    def __init__(
        self,
        *,
        feature_columns: Sequence[str] | None = None,
        exclude_columns: Sequence[str] | None = None,
        column_aliases: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        self.feature_columns = list(feature_columns) if feature_columns else None
        self.exclude_columns = set(exclude_columns or [])
        self.column_aliases = {
            key: list(values)
            for key, values in (column_aliases or DATASET_COLUMN_ALIASES).items()
        }

    def resolve_target_column(
        self,
        columns: Sequence[str],
        preferred: str | None = None,
    ) -> str | None:
        """Resolve a target/label column from aliases if present."""
        colset = set(columns)
        if preferred and preferred in colset:
            return preferred
        for alias in self.column_aliases.get("label", []):
            if alias in colset:
                logger.info("Resolved target column via alias: %s", alias)
                return alias
        return preferred

    def from_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Select and order feature columns from a tabular dataframe."""
        working = df.copy()
        drop_cols = [c for c in self.exclude_columns if c in working.columns]
        if drop_cols:
            working = working.drop(columns=drop_cols)
            logger.debug("Excluded columns: %s", drop_cols)

        if self.feature_columns is None:
            logger.debug(
                "Using all remaining columns as features (%d)", working.shape[1]
            )
            return working

        missing = [c for c in self.feature_columns if c not in working.columns]
        if missing:
            raise KeyError(
                f"Requested feature columns not found in dataframe: {missing}"
            )
        return working.loc[:, list(self.feature_columns)]

    def from_flow_record(self, record: Mapping[str, Any]) -> pd.DataFrame:
        """Convert a network-flow record into a single-row feature frame.

        Args:
            record: Mapping of flow attributes.

        Returns:
            One-row DataFrame with FLOW_FEATURE_NAMES columns.
        """
        features = flow_record_to_feature_dict(record)
        return pd.DataFrame([features], columns=FLOW_FEATURE_NAMES)

    def from_flow_records(
        self, records: Sequence[Mapping[str, Any]]
    ) -> pd.DataFrame:
        """Convert many flow records into a feature DataFrame."""
        if not records:
            return pd.DataFrame(columns=FLOW_FEATURE_NAMES)
        rows = [flow_record_to_feature_dict(r) for r in records]
        return pd.DataFrame(rows, columns=FLOW_FEATURE_NAMES)

    def from_packet(self, packet: Any) -> pd.DataFrame:
        """Extract features from a single raw packet.

        Single packets lack full flow context. Prefer aggregating into flows
        first. This method raises to avoid inventing flow-level statistics.

        Raises:
            NotImplementedError: Always — use flow aggregation instead.
        """
        logger.debug("from_packet called: type=%s", type(packet).__name__)
        raise NotImplementedError(
            "Per-packet feature extraction is not supported. "
            "Aggregate packets into flows first, then call from_flow_record()."
        )


def extract_features(
    df: pd.DataFrame,
    *,
    feature_columns: Sequence[str] | None = None,
    exclude_columns: Sequence[str] | None = None,
) -> pd.DataFrame:
    """Convenience wrapper around :class:`FeatureExtractor.from_dataframe`."""
    extractor = FeatureExtractor(
        feature_columns=feature_columns,
        exclude_columns=exclude_columns,
    )
    return extractor.from_dataframe(df)
