#!/usr/bin/env python3
"""Run the LoTS project's own `features.py` over our connection records.

The 12 contract features, the 1200/600 grid and the TLS-with-SNI scope are NOT
reimplemented here: `lots_features.build_windows` is the file from
`~/lots_ngfw/features.py` on the sensor, copied byte-identical (sha256
b86a9d9c...).  This driver only feeds it and writes what it returns, so the LoTS
contract stays the single definition of its own features.

The one thing worth care is types: CSV gives back strings, and `in_scope` tests
`has_sni` for truthiness -- the string "0" is truthy, which would have put every
connection in scope and silently doubled the table.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import sys
import tempfile
import zlib
from pathlib import Path

# Одна ячейка держит всю последовательность пакетов сессии, поэтому
# стандартный лимит поля в 128 КиБ пробивается на первой же длинной сессии.
csv.field_size_limit(1 << 24)

sys.path.insert(0, str(Path(__file__).resolve().parent))
# `lots_features` is `~/lots_ngfw/features.py` copied byte-identical; the
# vendored file in this directory has the sha256 the docstring above names.
import lots_features as lf


def _open_text(path: str):
    return gzip.open(path, "rt", newline="") if path.endswith(".gz") else open(path, newline="")


def _conn(r: dict) -> dict:
    return {
        "ts": float(r["ts"]),
        "duration": float(r["duration"] or 0.0),
        "bytes_up": int(r["bytes_up"] or 0),
        "bytes_down": int(r["bytes_down"] or 0),
        "host": r["host"],
        "service": r["service"],
        "dst": r["dst"],
        "ja3": r.get("ja3") or "",
        "ja4": r.get("ja4") or "",
        "has_sni": bool(int(r["has_sni"] or 0)),
    }


def _shards(paths: list[str], n: int, tmp: Path):
    """Yield the connections one host shard at a time.

    A window key is (host, service), so every window of a host is built from
    that host's connections alone and a host never has to share memory with
    the rest of a month. One pass splits the input by host, then each shard is
    read back on its own.
    """
    if n <= 1:
        conns = []
        for p in paths:
            with _open_text(p) as fh:
                conns.extend(_conn(r) for r in csv.DictReader(fh))
        yield conns
        return
    names = [tmp / f"shard-{i:03d}.csv.gz" for i in range(n)]
    outs = [gzip.open(name, "wt", newline="") for name in names]
    writers = [None] * n
    try:
        for p in paths:
            with _open_text(p) as fh:
                reader = csv.DictReader(fh)
                for r in reader:
                    i = zlib.crc32(r["host"].encode()) % n
                    if writers[i] is None:
                        writers[i] = csv.DictWriter(outs[i], fieldnames=reader.fieldnames)
                        writers[i].writeheader()
                    writers[i].writerow(r)
    finally:
        for fh in outs:
            fh.close()
    for i, name in enumerate(names):
        if writers[i] is None:
            continue
        with gzip.open(name, "rt", newline="") as fh:
            conns = [_conn(r) for r in csv.DictReader(fh)]
        name.unlink()
        yield conns


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--conns", required=True, nargs="+",
                    help="one or more lots_conns tables (.csv or .csv.gz), e.g. every "
                         "batch of a capture: a window can only be built once every "
                         "connection that started in it has ended")
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--stats-json", default="")
    ap.add_argument("--shards", type=int, default=1,
                    help="split the work by host into this many parts to bound memory")
    ap.add_argument("--no-scope", action="store_true",
                    help="keep connections without an SNI too (outside the LoTS contract)")
    args = ap.parse_args()

    # An hour with no in-scope connection is a normal outcome, not a failure --
    # a quiet hour, or one where nothing reached the 20-minute grid. It used to
    # return without writing the CSV or the stats file, which left that hour
    # looking exactly like one where this step had crashed. Write both, always,
    # and let the row count say what happened.
    cols = ["host", "service", "window_index", "window_start_epoch",
            "n_windows_in_key", "row_weight"] + list(lf.FEATURES)
    out = Path(args.out_csv)
    out.parent.mkdir(parents=True, exist_ok=True)
    conns_n = in_scope_n = rows_n = 0
    keys = set()
    with out.open("w", newline="", encoding="utf-8") as fh, \
         tempfile.TemporaryDirectory(dir=out.parent) as tmp:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for conns in _shards(args.conns, args.shards, Path(tmp)):
            conns_n += len(conns)
            in_scope_n += sum(1 for c in conns if lf.in_scope(c))
            rows = lf.build_windows(conns, window_s=lf.WINDOW_S, stride_s=lf.STRIDE_S,
                                    key="host_service", scope=not args.no_scope)
            for r in rows:
                w.writerow(r)
                keys.add((r["host"], r["service"]))
            rows_n += len(rows)

    report = {
        "status": "ok" if rows_n else "empty",
        "features_module_sha256_expected": "b86a9d9cf252e928407a49a8dce3e6a307499c362d35ec03ada011b33235c9f0",
        "window_s": lf.WINDOW_S, "stride_s": lf.STRIDE_S,
        "feature_count": len(lf.FEATURES),
        "features": list(lf.FEATURES),
        "conns_in": conns_n,
        "conns_in_scope_tls_with_sni": in_scope_n,
        "scope_applied": not args.no_scope,
        "window_rows": rows_n,
        "distinct_keys": len(keys),
        "shards": args.shards,
        "out_csv": str(out),
    }
    print(json.dumps(report, indent=2))
    if args.stats_json:
        Path(args.stats_json).write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
