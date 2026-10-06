#!/usr/bin/env python3
"""Pack verified batch CSVs into one typed Parquet, preserving a pinned schema."""
from __future__ import annotations

import argparse
import csv
import itertools
import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

csv.field_size_limit(1 << 24)


def convert(value: str, typ: pa.DataType):
    if pa.types.is_string(typ):
        return value
    if value == "":
        return None
    if pa.types.is_list(typ):
        return [int(x) for x in value.split()]
    if pa.types.is_integer(typ):
        return int(value)
    if pa.types.is_floating(typ):
        return float(value)
    return value


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--work", required=True, type=Path)
    ap.add_argument("--schema-from", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    schema = pq.read_schema(args.schema_from)
    batches = sorted(args.work.glob("batches/*/office_sessions.csv"))
    if not batches:
        raise ValueError("no batch CSVs")
    if any(not (p.parent / "verified.json").exists() for p in batches):
        raise ValueError("unverified batch CSV")
    writer = pq.ParquetWriter(args.out, schema, compression="zstd")
    total = 0
    try:
        for path in batches:
            with path.open(newline="") as fh:
                reader = csv.DictReader(fh)
                if set(reader.fieldnames or []) != set(schema.names):
                    raise ValueError(f"schema mismatch in {path}")
                while rows := list(itertools.islice(reader, 1000)):
                    columns = {field.name: pa.array(
                        [convert(row[field.name], field.type) for row in rows], type=field.type)
                        for field in schema}
                    writer.write_table(pa.Table.from_pydict(columns, schema=schema))
                    total += len(rows)
    finally:
        writer.close()
    actual = pq.ParquetFile(args.out).metadata.num_rows
    print(json.dumps({"rows": actual, "batches": len(batches), "columns": len(schema),
                      "source_rows": total, "valid": actual == total}))
    return 0 if actual == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
