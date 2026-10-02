"""Feature engineering package."""

from app.features.extractor import (
    FLOW_FEATURE_NAMES,
    MODEL_FEATURE_ORDER,
    FeatureExtractor,
    FeatureValidationError,
    extract_features,
    flow_records_to_matrix,
    flow_to_model_vector,
    validate_model_features,
)
from app.features.flow_aggregator import FlowAggregator, aggregate_packets

__all__ = [
    "FLOW_FEATURE_NAMES",
    "MODEL_FEATURE_ORDER",
    "FeatureExtractor",
    "FeatureValidationError",
    "FlowAggregator",
    "aggregate_packets",
    "extract_features",
    "flow_records_to_matrix",
    "flow_to_model_vector",
    "validate_model_features",
]
