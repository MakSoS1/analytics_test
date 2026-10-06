#!/usr/bin/env python3
"""Host-behaviour windows from our session table, using the repository's own table.

The session rows answer "what did this connection look like".  A behavioural
model asks "what does this host look like over twenty minutes", which is a
different unit and is already specified in `lab_pipeline/host_schema.py` as the
`host20-v1` contract: 25 features over a trailing 20-minute window held as 20
one-minute bins.  This driver only turns session rows into `FlowEvent`s and lets
`HostWindowTable` do the rest, so the contract stays the single definition.

Two honest limits, both inherited from that contract and worth repeating here:

* Only `full` windows are written.  A window without its twenty bins is warmup
  or partial and is never padded to look complete, so one hour of capture yields
  at most a couple of windows per host, and only for hosts seen for 20+ minutes.
* Windows do not overlap.  Twenty sliding windows from one capture share
  nineteen bins and are not twenty independent observations.

`fast_score` stays unset: no fast-v1 model is scored here, so the features that
depend on it are zero and the rows say so rather than implying the fast tier
saw nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# `lab_pipeline` sits flat beside this file on the processing VM and in
# `detector/` in the repository. The absolute home directory that used to be
# hardcoded here made the script run on exactly one account on one host.
_HERE = Path(__file__).resolve().parent
for _cand in [_HERE, _HERE / "detector", *(_p / "detector" for _p in _HERE.parents)]:
    if (_cand / "lab_pipeline").is_dir():
        sys.path.insert(0, str(_cand))
        break
else:
    raise ImportError(f"lab_pipeline not found next to {_HERE} nor in any parent's detector/")

from lab_pipeline.host_schema import HOST_FEATURES  # noqa: E402
from lab_pipeline.host_windows import FlowEvent, HostWindowTable  # noqa: E402

csv.field_size_limit(1 << 24)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sessions", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--stats-json", default="")
    ap.add_argument("--include-partial", action="store_true",
                    help="also write warmup/partial windows, clearly marked")
    args = ap.parse_args()

    table = HostWindowTable()
    events = 0
    end = 0.0
    # Only the ten fields an event needs are kept: a whole session row carries
    # its packet arrays, and three hours of those do not fit in memory.
    rows = []
    with open(args.sessions) as fh:
        for r in csv.DictReader(fh):
            rows.append((
                float(r["session_start_epoch"]) + float(r["flow_duration"]),
                r["host_key"], r["server_key"],
                int(float(r["up_bytes"])), int(float(r["down_bytes"])),
                float(r["flow_duration"]),
                r["start_observed"] == "0" or r["truncated_at_capture_end"] == "1",
                r["closed_cleanly"] == "1",
            ))
    # Events must arrive in the order the sensor would have reported them:
    # at flow end, not at flow start.
    rows.sort(key=lambda e: e[0])
    for ts, host, peer, up, down, dur, partial, completed in rows:
        end = max(end, ts)
        table.add(FlowEvent(
            ts=ts, host_key=host, peer_id=peer, bytes_up=up, bytes_down=down,
            duration=dur, fast_score=None, fast_flagged=False,
            partial=partial, completed=completed,
        ), now=ts)
        events += 1

    wins = table.windows(end)
    status = {}
    for w in wins:
        status[w.get("window_status")] = status.get(w.get("window_status"), 0) + 1
    keep = [w for w in wins if args.include_partial or w.get("window_status") == "full"]

    cols = ["host_key", "window_end_epoch", "window_status"] + list(HOST_FEATURES)
    out = Path(args.out_csv)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for row in keep:
            row.setdefault("window_end_epoch", end)
            w.writerow(row)

    report = {
        "status": "ok",
        "sessions_in": events,
        "hosts_tracked": table.host_count(),
        "windows_returned": len(wins),
        "window_status_counts": status,
        "windows_written": len(keep),
        "feature_count": len(HOST_FEATURES),
        "out_csv": str(out),
        "note": "host20-v1; only `full` windows unless --include-partial; fast_* features are 0 because no fast model was scored",
    }
    print(json.dumps(report, indent=2))
    if args.stats_json:
        Path(args.stats_json).write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
