#!/usr/bin/env python3
"""Is every feature in the published table actually there? Runs in the Jupyter pod.

For each column of a parquet table: its type, the share of rows where it is
filled, the share where it is non-zero, how many distinct values it takes and
its range. A column that is never filled, or never anything but one value, is
named -- together with the rows' payload schema version, because a feature the
sensor code did not measure yet is empty by design, not by accident.

  python3 audit_parquet_features.py --table RUN/parquet/office_sessions.parquet --out audit.json
"""
from __future__ import annotations

import argparse
import json

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.dataset as ds


def audit(path: str) -> dict:
    table = ds.dataset(path, format="parquet", partitioning="hive").to_table()
    n = table.num_rows
    cols = {}
    for name in table.column_names:
        col = table.column(name)
        t = col.type
        filled = n - col.null_count
        info = {"type": str(t), "filled": round(filled / n, 4) if n else 0}
        if pa.types.is_list(t):
            lengths = pc.list_value_length(col)
            info["mean_len"] = round(pc.mean(lengths).as_py() or 0, 1)
            info["nonzero"] = round(pc.sum(pc.greater(lengths, 0)).as_py() / n, 4) if n else 0
        elif pa.types.is_integer(t) or pa.types.is_floating(t) or pa.types.is_boolean(t):
            c = pc.cast(col, pa.float64())
            info["nonzero"] = round((pc.sum(pc.not_equal(c, 0.0)).as_py() or 0) / n, 4) if n else 0
            mm = pc.min_max(c)
            info["min"], info["max"] = mm["min"].as_py(), mm["max"].as_py()
            info["distinct"] = min(pc.count_distinct(c).as_py(), 10**6)
        else:
            s = pc.cast(col, pa.string())
            info["nonzero"] = round((pc.sum(pc.and_(pc.is_valid(s), pc.not_equal(s, ""))).as_py() or 0) / n, 4) if n else 0
            info["distinct"] = min(pc.count_distinct(s).as_py(), 10**6)
        cols[name] = info
    versions = {}
    if "payload_schema_version" in table.column_names:
        vc = pc.value_counts(table.column("payload_schema_version"))
        versions = {str(v["values"].as_py()): v["counts"].as_py() for v in vc}
    return {
        "rows": n, "columns": len(cols),
        "never_filled": [c for c, i in cols.items() if i["filled"] == 0],
        "filled_but_always_zero_or_empty": [c for c, i in cols.items() if i["filled"] > 0 and i["nonzero"] == 0],
        "single_value": [c for c, i in cols.items() if i.get("distinct") == 1 and i["filled"] > 0],
        "payload_schema_versions": versions,
        "column_stats": cols,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--table", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    report = audit(args.table)
    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=1, default=str)
    print(json.dumps({k: v for k, v in report.items() if k != "column_stats"}, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
