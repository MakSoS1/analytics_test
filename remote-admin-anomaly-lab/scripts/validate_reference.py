#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.reference_validation import compare_reference_distributions  # noqa: E402

DEFAULT_COLUMNS = [
    "duration", "bytes_total", "src_bytes", "dst_bytes", "packets_total",
    "connections_1m", "connections_15m", "connections_1h", "connections_24h",
    "pair_seen_count", "src_out_degree_1h", "protocol_entropy_1h",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--bootstrap", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=20260814)
    args = parser.parse_args()

    generated = pd.read_parquet(args.generated)
    reference = None
    if args.reference is not None and args.reference.exists():
        reference = pd.read_parquet(args.reference)
    report = compare_reference_distributions(
        generated,
        reference,
        columns=DEFAULT_COLUMNS,
        bootstrap=args.bootstrap,
        seed=args.seed,
    )
    if args.reference is not None:
        report["reference_path_requested"] = str(args.reference)
        report["reference_path_exists"] = bool(args.reference.exists())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
