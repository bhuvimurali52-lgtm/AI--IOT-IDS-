"""CLI script to load, preprocess, and save an IDS dataset (Phase 2).

Example:
    python scripts/prepare_dataset.py --dataset data/raw/dataset.csv --target label
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Ensure project root is on sys.path when run as a script.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import get_settings
from app.core.logging_config import setup_logging
from app.data.loader import load_dataset
from app.data.preprocessing import preprocess_dataset, save_processed_artifacts
from app.features.extractor import FeatureExtractor


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for dataset preparation."""
    settings = get_settings()
    parser = argparse.ArgumentParser(
        description=(
            "Load a CSV IDS dataset, preprocess it without leakage, "
            "and write train/test artifacts to data/processed/."
        )
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=settings.dataset_path,
        help=f"Path to CSV dataset (default: {settings.dataset_path})",
    )
    parser.add_argument(
        "--target",
        type=str,
        default=settings.target_column,
        help=f"Target/label column name (default: {settings.target_column})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=settings.data_processed_dir,
        help=f"Directory for processed artifacts (default: {settings.data_processed_dir})",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=settings.test_size,
        help=f"Test split fraction (default: {settings.test_size})",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=settings.random_state,
        help=f"Random seed for reproducible splits (default: {settings.random_state})",
    )
    parser.add_argument(
        "--exclude",
        nargs="*",
        default=[],
        help="Optional columns to exclude from features (e.g. Flow ID Timestamp)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the Phase 2 dataset preparation pipeline.

    Returns:
        Process exit code (0 on success).
    """
    settings = get_settings()
    setup_logging(log_level=settings.log_level, log_dir=settings.log_dir)
    logger = logging.getLogger("prepare_dataset")

    args = parse_args(argv)
    logger.info("Preparing dataset from %s", args.dataset)

    df, report = load_dataset(args.dataset, target_column=args.target)

    extractor = FeatureExtractor(exclude_columns=args.exclude or None)
    resolved_target = extractor.resolve_target_column(df.columns, preferred=args.target)
    if resolved_target is None:
        raise SystemExit(
            f"Could not resolve target column '{args.target}'. "
            f"Available columns: {list(df.columns)}"
        )

    # Keep target in the frame; extractor selects/excludes feature helpers only.
    feature_frame = extractor.from_dataframe(df)
    if resolved_target not in feature_frame.columns:
        feature_frame[resolved_target] = df[resolved_target]

    processed = preprocess_dataset(
        feature_frame,
        target_column=resolved_target,
        test_size=args.test_size,
        random_state=args.random_state,
    )
    paths = save_processed_artifacts(processed, args.output_dir)

    print("\n=== Dataset preparation summary ===")
    print(f"Source            : {report.path}")
    print(f"Raw rows x cols   : {report.n_rows} x {report.n_columns}")
    print(f"Missing cells     : {report.total_missing}")
    print(f"Duplicates found  : {report.duplicate_rows}")
    print(f"Duplicates removed: {processed.dropped_duplicates}")
    print(f"Target column     : {resolved_target}")
    print(f"Numerical cols    : {len(processed.numerical_columns)}")
    print(f"Categorical cols  : {len(processed.categorical_columns)}")
    print(f"Train / test size : {processed.metadata['n_train']} / {processed.metadata['n_test']}")
    print(f"Output features   : {processed.metadata['n_features']}")
    print(f"Artifacts written : {args.output_dir.resolve()}")
    for name, path in paths.items():
        print(f"  - {name}: {path.name}")
    print("===================================\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
