#!/usr/bin/env python3
"""Traffic volume of every internal host, minute by minute, from the packet rows.

Sessions are the wrong unit for "how much did this host move, and when": a
session that was already open when the capture started, or a download inside a
day-long session, has all of its bytes stamped at the session's start. A burst
belongs to the minute its packets were on the wire, so this counts the packets
themselves, while a batch's rows are still on disk.

One row per (internal host, UTC minute):

  host_key          the same salted key as `host_key` in the sessions table
  minute_epoch      start of the minute, Unix seconds
  bytes_out/_in     frame bytes the host sent / received (on-wire length)
  pkts_out/_in      packets sent / received
  peers             distinct addresses it exchanged packets with
  top_peer_bytes    bytes to and from its heaviest peer in that minute

A host is an endpoint whose address is private (the flag travels in the row);
a packet between two internal hosts counts for both. A minute can be split
between two batches (a capture interval straddles the batch boundary): the
tables that read this add rows of the same (host, minute) together.

  host_minutes.py --rows-dir BATCH/_rows --out-csv BATCH/office_host_minutes.csv
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import os
from pathlib import Path

import numpy as np
import pandas as pd

ROW = np.dtype([("ts", "<f8"), ("src", "<u8"), ("dst", "<u8"), ("len", "<u2"),
                ("sport", "<u2"), ("dport", "<u2"), ("pay", "<u2"),
                ("proto", "u1"), ("flags", "u1"), ("meta", "u1")])
assert ROW.itemsize == 35                      # struct "<d8s8sHHHHBBB"
COLUMNS = ["host_key", "minute_epoch", "bytes_out", "bytes_in", "pkts_out", "pkts_in",
           "peers", "top_peer_bytes"]
LAG = 120        # rows of one file reach back this far at most; older minutes are final


def _pairs(rows: np.ndarray, bin_seconds: int) -> pd.DataFrame:
    """(host, minute, peer) -> bytes and packets, both directions, for one file."""
    minute = (rows["ts"] // bin_seconds).astype(np.int64) * bin_seconds
    length = np.maximum(rows["len"], 1).astype(np.int64)
    parts = []
    out = (rows["meta"] & 1) == 1
    if out.any():
        parts.append(pd.DataFrame({"host": rows["src"][out], "minute": minute[out],
                                   "peer": rows["dst"][out], "bytes_out": length[out],
                                   "bytes_in": 0, "pkts_out": 1, "pkts_in": 0}))
    inn = (rows["meta"] & 2) == 2
    if inn.any():
        parts.append(pd.DataFrame({"host": rows["dst"][inn], "minute": minute[inn],
                                   "peer": rows["src"][inn], "bytes_out": 0,
                                   "bytes_in": length[inn], "pkts_out": 0, "pkts_in": 1}))
    if not parts:
        return pd.DataFrame(columns=["host", "minute", "peer", "bytes_out", "bytes_in",
                                     "pkts_out", "pkts_in"])
    return (pd.concat(parts, ignore_index=True)
            .groupby(["host", "minute", "peer"], sort=False, as_index=False).sum())


def _finish(acc: pd.DataFrame, key) -> pd.DataFrame:
    acc = acc.groupby(["host", "minute", "peer"], sort=False, as_index=False).sum()
    acc["both"] = acc.bytes_out + acc.bytes_in
    g = acc.groupby(["host", "minute"], sort=False)
    res = g.agg(bytes_out=("bytes_out", "sum"), bytes_in=("bytes_in", "sum"),
                pkts_out=("pkts_out", "sum"), pkts_in=("pkts_in", "sum"),
                peers=("peer", "nunique"), top_peer_bytes=("both", "max")).reset_index()
    res.insert(0, "host_key", res.pop("host").map(key))
    return res.rename(columns={"minute": "minute_epoch"})[COLUMNS]


def host_minutes(files: list[Path], salt: bytes, out_csv: Path, bin_seconds: int = 60) -> dict:
    keys: dict[int, str] = {}

    def key(raw: int) -> str:
        k = keys.get(raw)
        if k is None:
            # Row keys are 8 raw bytes; sessions hash their hex form with this salt.
            hex_ = int(raw).to_bytes(8, "little").hex()
            k = keys[raw] = hmac.new(salt, hex_.encode(), hashlib.sha256).hexdigest()[:16]
        return k

    report = {"files": 0, "packets": 0, "host_minutes": 0, "bytes": 0}
    acc = None
    tmp = out_csv.with_suffix(".csv.tmp")
    with tmp.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(COLUMNS)

        def flush(frame: pd.DataFrame) -> None:
            if len(frame):
                res = _finish(frame, key)
                w.writerows(res.itertuples(index=False, name=None))
                report["host_minutes"] += len(res)
                report["bytes"] += int(res.bytes_out.sum() + res.bytes_in.sum())

        for f in sorted(files):
            data = f.read_bytes()
            if len(data) % ROW.itemsize:
                raise ValueError(f"{f}: not a whole number of packet rows")
            rows = np.frombuffer(data, dtype=ROW)
            report["files"] += 1
            report["packets"] += len(rows)
            if not len(rows):
                continue
            part = _pairs(rows, bin_seconds)
            acc = part if acc is None else pd.concat([acc, part], ignore_index=True)
            # Files come in time order; minutes well behind this file are complete.
            done = acc.minute < (float(rows["ts"].min()) // bin_seconds) * bin_seconds - LAG
            if done.any():
                flush(acc[done])
                acc = acc[~done].reset_index(drop=True)
        if acc is not None:
            flush(acc)
    os.replace(tmp, out_csv)
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rows-dir", type=Path, required=True)
    ap.add_argument("--glob", default="*.pkts")
    ap.add_argument("--salt-file", default="~/.office_iter_salt",
                    help="the salt extract_office_sessions.py hashes host_key with")
    ap.add_argument("--out-csv", type=Path, required=True)
    ap.add_argument("--bin-seconds", type=int, default=60)
    a = ap.parse_args()
    salt = Path(os.path.expanduser(a.salt_file)).read_bytes()
    report = host_minutes(sorted(a.rows_dir.glob(a.glob)), salt, a.out_csv, a.bin_seconds)
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
