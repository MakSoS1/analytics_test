#!/usr/bin/env python3
"""Check a run of packet-row minutes the way `audit_pcap_series.py` checks pcaps.

Once the pcap is deleted the rows are the only evidence, so the checks cannot be
"does the file parse". They are the ones that can still catch a loss:

* **The journal and the files agree.** `consume_minutes.py` wrote, per minute,
  how many frames it read and how many rows it produced. A `.pkts` file is a
  fixed 35 bytes per row, so its size says the same number independently. If the
  two disagree, a file was truncated or replaced after it was written.

  One journal covers a whole capture while a batch is usually one hour of it, so
  only the entries for files in this batch are checked. A file that was
  converted and then lost is still caught, by the gap it leaves in the series.
* **Every frame of every minute is accounted for.** Rows plus the non-flow
  counts must equal the frames the capture reported for that minute.
* **The intervals are consecutive.** A gap in the `chunk-<stamp>` series is an
  interval the capture lost, and it has to be named rather than averaged away.
  The rotation period is given rather than assumed: it is chosen from how much
  disk the sensor has, so it is not always 60 seconds.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re

ROW_SIZE = 35
NAME = re.compile(r"chunk-(\d{8}T\d{6}Z)\.pkts$")


def audit(rows_dir: Path, journal: Path, glob: str = "chunk-*.pkts",
          rotate_seconds: int = 60) -> dict:
    files = sorted(rows_dir.glob(glob))
    if not files:
        raise ValueError(f"no {glob} in {rows_dir}")

    stamps, problems = [], []
    by_name = {}
    for path in files:
        match = NAME.fullmatch(path.name)
        if not match:
            raise ValueError(f"unexpected minute filename: {path.name}")
        size = path.stat().st_size
        if size % ROW_SIZE:
            problems.append({"file": path.name, "problem": "size is not whole rows",
                             "bytes": size})
        by_name[path.name] = size // ROW_SIZE
        stamps.append(datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ")
                      .replace(tzinfo=timezone.utc))

    missing = []
    step = timedelta(seconds=rotate_seconds)
    for prev, nxt in zip(stamps, stamps[1:]):
        if nxt <= prev or (nxt - prev).total_seconds() % rotate_seconds:
            raise ValueError(f"rotation is not a multiple of {rotate_seconds}s: {prev} -> {nxt}")
        t = prev + step
        while t < nxt:
            missing.append(t.strftime("%Y%m%dT%H%M%SZ"))
            t += step

    frames = packets = nonflow = 0
    entries = other_batches = 0
    errors = []
    seen = set()
    # A pcap that failed and was converted again later has both entries; the
    # later success is what counts, the failure is not a loss any more.
    redone = {json.loads(l).get("pcap") for l in journal.read_text().splitlines()
              if l.strip() and json.loads(l).get("status") == "ok"}
    for line in journal.read_text().splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("status") != "ok" and e.get("pcap") in redone:
            continue
        if e.get("status") != "ok":
            # Only this batch's own failures are its business: one journal
            # covers the whole capture, and a failure a week ago must not stop
            # every batch after it.
            m = re.search(r"(\d{8}T\d{6}Z)", str(e.get("pcap", "")))
            when = (datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
                    if m else None)
            if when is None or stamps[0] <= when <= stamps[-1] + step:
                errors.append({"pcap": e.get("pcap"), "error": e.get("error")})
            continue
        name = e["rows_file"]
        if name not in by_name:
            other_batches += 1
            continue
        entries += 1
        seen.add(name)
        frames += e["frames"]
        packets += e["packets"]
        nonflow += sum(e.get("nonflow", {}).values())
        if by_name[name] != e["packets"]:
            problems.append({"file": name, "problem": "row count differs from the journal",
                             "rows_on_disk": by_name[name], "journal": e["packets"]})
        if e["packets"] + sum(e.get("nonflow", {}).values()) + e["truncated"] != e["frames"]:
            problems.append({"file": name, "problem": "frames do not add up in the journal"})

    for name in sorted(set(by_name) - seen):
        problems.append({"file": name, "problem": "on disk, not in the journal"})

    return {
        "rotate_seconds": rotate_seconds,
        "files": len(files),
        "journal_entries": entries,
        "journal_entries_other_batches": other_batches,
        "rows_on_disk": sum(by_name.values()),
        "frames_total": frames,
        "packets_total": packets,
        "nonflow_total": nonflow,
        "unaccounted": frames - (packets + nonflow),
        "missing_minutes": missing,
        "conversion_errors": errors,
        "problems": problems,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rows-dir", type=Path, required=True)
    ap.add_argument("--journal", type=Path, required=True)
    ap.add_argument("--out-json", type=Path, required=True)
    ap.add_argument("--glob", default="chunk-*.pkts")
    ap.add_argument("--rotate-seconds", type=int, default=60,
                    help="the capture's -G value; gaps are counted in these")
    args = ap.parse_args()
    result = audit(args.rows_dir, args.journal, args.glob, args.rotate_seconds)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items()
                      if k not in ("problems", "conversion_errors")}))
    # A failed conversion is a named loss, not a stop: the interval is missing
    # from the rows, its pcap stays on the sensor to be looked at, and the
    # report lists it. Halting a month-long capture over one interval would
    # lose far more than the interval. What the rows that ARE here say about
    # themselves still has to be exact.
    bad = result["problems"] or result["unaccounted"]
    if bad:
        print(json.dumps({"problems": result["problems"][:10],
                          "conversion_errors": result["conversion_errors"][:10]}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
