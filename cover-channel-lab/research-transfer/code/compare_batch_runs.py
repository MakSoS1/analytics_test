#!/usr/bin/env python3
"""Do two runs of `office_batches.py` over the same rows give the same tables?

Run one with a batch longer than the capture (the reference: nothing is ever
carried) and one with short batches, and every session, every LoTS connection
and every LoTS window must come out the same -- the batch boundary may change
WHEN a row is written, never WHAT it says. Anything else is a boundary effect,
and the report names the columns it shows up in.

Rows are matched by flow, segment number and start time, and compared by a hash
of all their other values. Not by `segment_uid`: its instance number is a
counter, and a session pass split into shards counts per shard. It is still
checked that the uids are unique within each run.

Rows are compared by hash,
so a month of rows is compared without holding either side in memory. Host20
windows are left out on purpose: they are a snapshot at each batch's end, so
their number depends on the batching by definition.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
from collections import Counter
from pathlib import Path

csv.field_size_limit(1 << 24)


def _open(path: Path):
    return gzip.open(path, "rt", newline="") if path.suffix == ".gz" else path.open(newline="")


def _rows(paths):
    for p in paths:
        with _open(p) as fh:
            yield from csv.DictReader(fh)


def _digest(row: dict, cols: list[str]) -> bytes:
    return hashlib.blake2b("\x1f".join(row.get(c, "") for c in cols).encode(),
                           digest_size=12).digest()


def sessions(work: Path) -> list[Path]:
    return sorted(work.glob("batches/*/office_sessions.csv"))


ID_COLUMNS = ("session_uid", "segment_uid")


def _key(r: dict) -> tuple:
    return (r["session_uid"].split("#")[0], r["segment_index"], r["session_start_epoch"])


def compare_sessions(a: list[Path], b: list[Path], examples: int) -> dict:
    with _open(a[0]) as fh:
        cols = [c for c in next(csv.reader(fh)) if c not in ID_COLUMNS]
    ha, uids_a, rows_a_total = {}, set(), 0
    for r in _rows(a):
        rows_a_total += 1
        ha[_key(r)] = _digest(r, cols)
        uids_a.add(r["segment_uid"])
    key_collisions_a = rows_a_total - len(ha)
    uid_duplicates_a = rows_a_total - len(uids_a)
    del uids_a
    differing, only_b, rows_b, uids_b = set(), 0, 0, set()
    for r in _rows(b):
        rows_b += 1
        uids_b.add(r["segment_uid"])
        d = ha.pop(_key(r), None)
        if d is None:
            only_b += 1
        elif d != _digest(r, cols):
            differing.add(_key(r))
    # Every row of B either matched one of A (and was popped) or was only in B.
    report = {"rows_a": rows_a_total, "rows_b": rows_b,
              "only_in_a": len(ha), "only_in_b": only_b, "differing": len(differing),
              "match_key_collisions_a": key_collisions_a,
              "segment_uid_duplicates_a": uid_duplicates_a,
              "segment_uid_duplicates_b": rows_b - len(uids_b)}
    if differing:
        # Second pass over just the differing rows: which columns, how often.
        keep_a = {_key(r): r for r in _rows(a) if _key(r) in differing}
        by_col: Counter = Counter()
        shown = []
        for r in _rows(b):
            other = keep_a.get(_key(r))
            if other is None:
                continue
            diff = [c for c in cols if other.get(c) != r.get(c)]
            by_col.update(diff)
            if len(shown) < examples:
                shown.append({"segment_uid": r["segment_uid"],
                              **{c: [other.get(c)[:80], r.get(c)[:80]] for c in diff[:8]}})
        report["columns_differing"] = dict(by_col.most_common())
        report["examples"] = shown
    report["only_in_a_examples"] = [list(k) for k in sorted(ha)[:examples]]
    return report


def compare_multiset(a, b, drop=()) -> dict:
    def bag(paths):
        c = Counter()
        n = 0
        for r in _rows(paths):
            for k in drop:
                r.pop(k, None)
            c[_digest(r, sorted(r))] += 1
            n += 1
        return c, n
    ca, na = bag(a)
    cb, nb = bag(b)
    return {"rows_a": na, "rows_b": nb,
            "only_in_a": sum((ca - cb).values()), "only_in_b": sum((cb - ca).values())}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--a", type=Path, required=True, help="reference run (one batch)")
    ap.add_argument("--b", type=Path, required=True, help="batched run")
    ap.add_argument("--out-json", type=Path)
    ap.add_argument("--examples", type=int, default=5)
    args = ap.parse_args()

    report = {"sessions": compare_sessions(sessions(args.a), sessions(args.b), args.examples)}
    # The LoTS tables exist only in runs made with --extra-tables.
    conns_a, conns_b = sorted(args.a.glob("lots_conns/*.csv.gz")), sorted(args.b.glob("lots_conns/*.csv.gz"))
    if conns_a and conns_b:
        report["lots_conns"] = compare_multiset(conns_a, conns_b)
    win_a = args.a / "batches/lots-windows/office_lots_windows.csv"
    win_b = args.b / "batches/lots-windows/office_lots_windows.csv"
    if win_a.exists() and win_b.exists():
        report["lots_windows"] = compare_multiset([win_a], [win_b])
    s = report["sessions"]
    report["identical"] = (
        not (s["only_in_a"] or s["only_in_b"] or s["differing"]
             or s["match_key_collisions_a"]
             or s["segment_uid_duplicates_a"] or s["segment_uid_duplicates_b"])
        and all(not (v["only_in_a"] or v["only_in_b"])
                for k, v in report.items() if k in ("lots_conns", "lots_windows")))
    text = json.dumps(report, indent=2, ensure_ascii=False)
    print(text)
    if args.out_json:
        args.out_json.write_text(text + "\n")
    return 0 if report["identical"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
