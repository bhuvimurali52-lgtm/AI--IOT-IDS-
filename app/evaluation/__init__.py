"""Phase 7 offline evaluation package."""

from app.evaluation.datasets import (
    build_labeled_evaluation_records,
    evaluation_matrix_from_records,
)
from app.evaluation.evaluator import (
    evaluate_detector,
    run_offline_evaluation,
    threshold_analysis,
)

__all__ = [
    "build_labeled_evaluation_records",
    "evaluation_matrix_from_records",
    "evaluate_detector",
    "run_offline_evaluation",
    "threshold_analysis",
]
