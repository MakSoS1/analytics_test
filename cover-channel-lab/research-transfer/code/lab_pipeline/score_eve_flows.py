#!/usr/bin/env python3
"""Score real office SPAN flows with an exported flow-tier model.

Runs on the SPAN host, which has no numpy/scikit-learn — inference is the pure
Python tree walk in flow_tier.py. Reads Suricata EVE (plain or .gz), keeps
`event_type == "flow"`, and reports how many flows cross the threshold.

Prints aggregates only: counts, rate, and a breakdown by destination port and
app_proto. No IPs, no per-flow rows — the office capture stays on the host.
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
from lab_pipeline.flow_tier import flow_features, predict_proba  # noqa: E402
from lab_pipeline.quic_filter import is_quic_flow  # noqa: E402

DNS_PORTS = {53, 5353}


def iter_eve(paths: list[Path]) -> Iterator[dict[str, Any]]:
    for path in paths:
        opener = gzip.open if path.suffix == ".gz" else open
        try:
            with opener(path, "rt", errors="replace") as fh:
                for line in fh:
                    if '"event_type":"flow"' not in line:
                        continue
                    try:
                        yield json.loads(line)
                    except ValueError:
                        continue
        except OSError:
            continue


def _duration(flow: dict[str, Any]) -> float:
    age = flow.get("age")
    if isinstance(age, (int, float)) and age > 0:
        return float(age)
    start, end = flow.get("start"), flow.get("end")
    if isinstance(start, str) and isinstance(end, str):
        from datetime import datetime

        try:
            fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
            return max((datetime.strptime(end, fmt) - datetime.strptime(start, fmt)).total_seconds(), 0.0)
        except ValueError:
            return 0.0
    return 0.0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True)
    ap.add_argument("--eve", nargs="+", required=True, help="eve.json and/or .gz archives")
    ap.add_argument("--threshold", type=float, default=None)
    ap.add_argument("--min-packets", type=int, default=4,
                    help="skip flows too short for any tier to judge")
    ap.add_argument("--out-json", default="")
    args = ap.parse_args()

    model = json.loads(Path(args.model).read_text())
    thr = args.threshold if args.threshold is not None else float(model.get("threshold", 0.5))

    paths: list[Path] = []
    for spec in args.eve:
        p = Path(spec)
        paths.extend(sorted(p.glob("*")) if p.is_dir() else [p])

    total = scored = hits = quic_skipped = 0
    by_port: Counter[int] = Counter()
    by_app: Counter[str] = Counter()
    scores: list[float] = []
    for rec in iter_eve(paths):
        total += 1
        f = rec.get("flow") or {}
        dport = int(rec.get("dest_port") or 0)
        if dport in DNS_PORTS or int(rec.get("src_port") or 0) in DNS_PORTS:
            continue
        # Same scope gate the exporter applies, so train and serve agree on
        # which flows are even eligible for a decision.
        if is_quic_flow(rec):
            quic_skipped += 1
            continue
        up_p = int(f.get("pkts_toserver") or 0)
        dn_p = int(f.get("pkts_toclient") or 0)
        if up_p + dn_p < args.min_packets:
            continue
        row = flow_features(
            up_p, dn_p,
            int(f.get("bytes_toserver") or 0), int(f.get("bytes_toclient") or 0),
            _duration(f), str(rec.get("proto") or ""),
        )
        scored += 1
        p = predict_proba(model, row)
        scores.append(p)
        if p >= thr:
            hits += 1
            by_port[dport] += 1
            by_app[str(rec.get("app_proto") or "unknown")] += 1

    # What threshold would each alert budget demand on THIS traffic? The lab
    # cannot answer that (a few hundred negatives); office volume can. Feeding
    # these back into the lab test set says what recall such a threshold costs.
    scores.sort(reverse=True)
    budget_thresholds = {}
    for target in (1e-2, 1e-3, 1e-4):
        k = int(scored * target)
        budget_thresholds[f"fpr_{target:g}"] = scores[k] if 0 <= k < scored else None
    out = {
        "flows_seen": total,
        "flows_scored": scored,
        "quic_excluded": quic_skipped,
        "flagged": hits,
        "flag_rate": (hits / scored) if scored else 0.0,
        "threshold": thr,
        "score_quantiles": {
            "p50": scores[scored // 2] if scored else None,
            "p90": scores[scored // 10] if scored else None,
            "p99": scores[scored // 100] if scored else None,
        },
        "threshold_for_office_fpr": budget_thresholds,
        "top_ports": by_port.most_common(10),
        "top_app_proto": by_app.most_common(10),
    }
    print(json.dumps(out, indent=2))
    if args.out_json:
        Path(args.out_json).write_text(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
