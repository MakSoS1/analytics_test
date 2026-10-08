#!/usr/bin/env python3
"""One parquet file with every session of a run -- to hand to someone.

The published table is a folder of parts, one partition per batch, because a
month is appended to it batch by batch. For sharing, one file is easier. This
writes that file one batch at a time, never holding the whole run in memory: a
Jupyter pod that had to sort all of it at once ran out of memory and took the
server down with it. Batches are already in time order, and within a batch the
rows are sorted by session start, so the file comes out in time order too.

  python3 export_single_parquet.py --table RUN/parquet/office_sessions.parquet --out sessions.parquet
"""
from __future__ import annotations

import argparse
import json
import os

import pyarrow.compute as pc
import pyarrow.dataset as ds
import pyarrow.parquet as pq


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--table", required=True, help="the partitioned dataset folder")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    dataset = ds.dataset(args.table, format="parquet", partitioning="hive")
    batches = sorted({str(f.partition_expression).split("\"")[1]
                      for f in dataset.get_fragments()})
    writer = None
    rows = 0
    try:
        for b in batches:
            part = dataset.to_table(filter=ds.field("batch") == b)
            part = part.drop_columns(["batch"])
            part = part.take(pc.sort_indices(part, sort_keys=[
                ("session_start_epoch", "ascending"), ("segment_index", "ascending")]))
            if writer is None:
                writer = pq.ParquetWriter(args.out, part.schema, compression="zstd",
                                          compression_level=9)
            writer.write_table(part.cast(writer.schema))
            rows += part.num_rows
    finally:
        if writer is not None:
            writer.close()
    check = pq.ParquetFile(args.out).metadata.num_rows
    print(json.dumps({"out": args.out, "batches": len(batches), "rows": rows,
                      "rows_in_file": check, "all_rows": check == dataset.count_rows(),
                      "MB": round(os.path.getsize(args.out) / 2**20, 2)}))
    return 0 if check == rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
