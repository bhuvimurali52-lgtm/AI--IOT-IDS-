"""Generate synthetic flow fixtures for local IDS pipeline testing.

These records are NOT real network traffic and must not be presented as such.

Example:
  python scripts/generate_test_traffic.py --output data/sample/synthetic_flows.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.capture.synthetic import generate_synthetic_flow_records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate SYNTHETIC flow fixtures (not real traffic)"
    )
    parser.add_argument("--normal", type=int, default=80)
    parser.add_argument("--anomalous", type=int, default=20)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/sample/synthetic_flows.json"),
    )
    args = parser.parse_args(argv)

    records = generate_synthetic_flow_records(
        n_normal=args.normal, n_anomalous=args.anomalous
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(records, indent=2), encoding="utf-8")
    print(
        f"Wrote {len(records)} SYNTHETIC flow records to {args.output.resolve()} "
        "(fixture only — not live traffic)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
