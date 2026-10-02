"""Train an Isolation Forest baseline for local-lab anomaly detection.

Modes:
  synthetic — clearly labelled local fixtures (NOT real traffic)
  live      — capture local traffic with Scapy (may require privileges)

Example:
  python scripts/train_baseline.py --mode synthetic
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.capture.packet_capture import PacketCapture
from app.capture.synthetic import generate_synthetic_flow_records
from app.core.config import get_settings
from app.core.logging_config import setup_logging
from app.database.models import IDSDatabase
from app.detection.anomaly_detector import AnomalyDetector
from app.features.extractor import FLOW_FEATURE_NAMES, flow_records_to_matrix
from app.features.flow_aggregator import aggregate_packets


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Train Isolation Forest baseline")
    parser.add_argument(
        "--mode",
        choices=["synthetic", "live"],
        default="synthetic",
        help="Training data source (default: synthetic)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=settings.model_path,
        help=f"Model output path (default: {settings.model_path})",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=settings.anomaly_contamination,
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=settings.n_estimators,
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=settings.random_state,
    )
    return parser.parse_args(argv)


def load_training_flows(mode: str) -> tuple[list[dict], str]:
    """Load baseline flows for training.

    Synthetic mode returns only traffic_profile=normal fixtures.
    Live mode captures packets and aggregates flows (may fail without privileges).
    """
    settings = get_settings()
    if mode == "synthetic":
        all_flows = generate_synthetic_flow_records(n_normal=120, n_anomalous=0)
        note = (
            "SYNTHETIC baseline fixtures only — not real network traffic. "
            "Do not report attack-detection accuracy from this mode."
        )
        return all_flows, note

    capture = PacketCapture(
        mode="live",
        interface=settings.capture_interface,
        duration=settings.capture_duration,
        packet_count=max(settings.capture_packet_count, 50),
        bpf_filter=settings.capture_bpf_filter,
    )
    result = capture.start()
    if result.error:
        raise RuntimeError(
            f"Live capture failed: {result.error}. "
            f"{result.privilege_note or PacketCapture.PRIVILEGE_HELP}"
        )
    if not result.packets:
        raise RuntimeError(
            "Live capture returned no IP packets. "
            "Generate local lab traffic or use --mode synthetic."
        )
    flows = aggregate_packets(result.packets, data_source="live")
    note = (
        f"LIVE baseline from {len(result.packets)} packets / {len(flows)} flows "
        "on this host. Not an evaluated attack-detection benchmark."
    )
    return flows, note


def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    setup_logging(log_level=settings.log_level, log_dir=settings.log_dir)
    logger = logging.getLogger("train_baseline")
    args = parse_args(argv)

    flows, note = load_training_flows(args.mode)
    if len(flows) < 10:
        raise SystemExit(
            f"Need at least 10 baseline flows to train; got {len(flows)}."
        )

    X, feature_names = flow_records_to_matrix(flows)
    detector = AnomalyDetector(
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        random_state=args.random_state,
    )
    detector.fit(X, feature_names=feature_names)
    out = detector.save(args.output)

    db = IDSDatabase(settings.database_path)
    db.insert_model_metadata(
        {
            "model_path": str(out),
            "training_mode": args.mode,
            "n_samples": int(X.shape[0]),
            "n_features": int(X.shape[1]),
            "contamination": args.contamination,
            "random_state": args.random_state,
            "notes": note,
        }
    )

    print("=== Baseline training complete ===")
    print(f"Mode            : {args.mode}")
    print(f"Samples         : {X.shape[0]}")
    print(f"Features        : {X.shape[1]} ({', '.join(FLOW_FEATURE_NAMES)})")
    print(f"Contamination   : {args.contamination}")
    print(f"Random state    : {args.random_state}")
    print(f"Model saved     : {out.resolve()}")
    print(f"Note            : {note}")
    print(
        "Limitation      : No accuracy/precision/recall is claimed. "
        "This trains a baseline anomaly model only."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
