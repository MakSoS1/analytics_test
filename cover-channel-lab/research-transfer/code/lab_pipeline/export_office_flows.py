#!/usr/bin/env python3
"""Export de-identified flow-tier features from office Suricata EVE.

Runs on the SPAN host. Emits the same 16 numbers per flow that `flow_tier.py`
computes and `train_flow_tier.py` trains on, so office rows and lab rows share
one schema. Applies the same filters as `score_eve_flows.py` (skip DNS, skip
flows too short to judge) so the training negatives match what is scored at
serve time.

Privacy: no IP address, no hostname and no SNI ever reaches the output. The
only non-feature columns are `app_proto`, `dest_port` and a coarse time bucket,
all of which are needed to split train/holdout and to triage false positives.
Ports and app_proto are QC columns — they are in the leakage list and are
dropped before the model sees a row.

Labels: office traffic is UNLABELED. This writes `y_presumed=0` and
`label_source=office_unlabeled`, never a plain `y`. A tunnel really present in
the office background is label noise, and the training script must say so.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
from lab_pipeline.flow_tier import FLOW_TIER_FEATURES, flow_features  # noqa: E402
from lab_pipeline.quic_filter import is_quic_flow  # noqa: E402

DNS_PORTS = {53, 5353}
_TS_FMT = "%Y-%m-%dT%H:%M:%S.%f%z"


def iter_eve(paths: list[Path]) -> Iterator[dict[str, Any]]:
    for path in paths:
        opener = gzip.open if path.suffix == ".gz" else open
        try:
            with opener(path, "rt", errors="replace") as fh:
                for line in fh:
                    if '"event_type":"flow"' not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    rec["_src_file"] = path.name
                    yield rec
        except OSError:
            continue


def _duration(flow: dict[str, Any]) -> float:
    age = flow.get("age")
    if isinstance(age, (int, float)) and age > 0:
        return float(age)
    start, end = flow.get("start"), flow.get("end")
    if isinstance(start, str) and isinstance(end, str):
        try:
            return max((datetime.strptime(end, _TS_FMT) - datetime.strptime(start, _TS_FMT)).total_seconds(), 0.0)
        except ValueError:
            return 0.0
    return 0.0


def _time_bucket(rec: dict[str, Any]) -> str:
    """Hour bucket, so a later slice can be held out for an honest FPR."""
    ts = rec.get("timestamp") or ""
    return ts[:13] if len(ts) >= 13 else "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--eve", nargs="+", required=True, help="eve.json and/or .gz archives")
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--min-packets", type=int, default=4, help="match score_eve_flows")
    ap.add_argument("--max-rows", type=int, default=0, help="0 = no cap")
    args = ap.parse_args()

    paths = [Path(p) for p in args.eve]
    out = Path(args.out_csv)
    out.parent.mkdir(parents=True, exist_ok=True)

    cols = list(FLOW_TIER_FEATURES) + ["app_proto", "dest_port", "time_bucket", "capture_id",
                                      "y_presumed", "label_source"]
    seen = kept = skipped_dns = skipped_short = skipped_quic = 0

    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        for rec in iter_eve(paths):
            seen += 1
            f = rec.get("flow") or {}
            dport = int(rec.get("dest_port") or 0)
            sport = int(rec.get("src_port") or 0)
            if dport in DNS_PORTS or sport in DNS_PORTS:
                skipped_dns += 1
                continue
            # QUIC is out of scope by policy. Excluded here on the app_proto /
            # port evidence Suricata already provides — not on a payload
            # first-byte guess, which would also drop ordinary UDP and WireGuard.
            if is_quic_flow(rec):
                skipped_quic += 1
                continue
            up_p = int(f.get("pkts_toserver") or 0)
            dn_p = int(f.get("pkts_toclient") or 0)
            if up_p + dn_p < args.min_packets:
                skipped_short += 1
                continue
            row = flow_features(
                up_p, dn_p,
                int(f.get("bytes_toserver") or 0), int(f.get("bytes_toclient") or 0),
                _duration(f), str(rec.get("proto") or ""),
            )
            row["app_proto"] = str(rec.get("app_proto") or "unknown")
            row["dest_port"] = dport
            row["time_bucket"] = _time_bucket(rec)
            # EVE has no capture window; the archive file is the closest
            # independent unit, so rows group by the file they came from.
            row["capture_id"] = rec.get("_src_file", "eve")
            row["y_presumed"] = 0
            row["label_source"] = "office_unlabeled"
            writer.writerow(row)
            kept += 1
            if args.max_rows and kept >= args.max_rows:
                break

    print(json.dumps({
        "flows_seen": seen,
        "rows_written": kept,
        "skipped_dns": skipped_dns,
        "skipped_short": skipped_short,
        "skipped_quic": skipped_quic,
        "csv": str(out),
        "columns": len(cols),
        "note": "y_presumed=0; office traffic is unlabeled, treat as noisy negatives",
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
