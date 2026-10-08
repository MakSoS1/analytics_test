#!/usr/bin/env python3
"""One verified batch's tables -> typed parquet, ready for Cosmolake.

Runs on the processing VM right after a batch is verified, so what leaves the
VM is already the final file format: no CSV reaches the platform and no Spark
has to guess a type. Three outputs, one file each:

  office_sessions.parquet         every row of the batch, types pinned by
                                  office_sessions.schema.json, plus the keys
                                  that make rows from many runs one table
  office_capture_quality.parquet  every capture interval of the batch
  manifest.json                   rows, packets, sha256 of each file -- what
                                  Silver is later checked against

Keys added to every session row:

  run_id, batch_id            where the row came from; (run_id, segment_uid)
                              is unique across every run ever loaded
  global_session_uid          run_id:session_uid -- all parts of one session
  segment_start_ts / _end_ts  first / last packet of the row, UTC, microseconds
  event_date                  UTC day of segment_start_ts (the partition)
  seq_first_dir / _last_dir   +1 client, -1 server: who sent the row's first and
                              last packet -- joins the parts of a long session
                              without reading its packet arrays

The schema is a contract, not a guess. A column the CSV has and the schema does
not, or the other way round, stops the batch: a new feature is added to the
schema on purpose (with a note), never slipped in by one batch's inference. An
integer column that turns up with a fraction stops it too, rather than being
rounded. A column that is empty in this batch is simply null.

  office_to_parquet.py --batch-dir BATCH --out-dir OUT --run-id RUN \\
      [--journal consumed.jsonl ...] [--rotate-seconds 20]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pcsv
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parent
SCHEMA = ROOT / "office_sessions.schema.json"
_IDENT = re.compile(r"^[A-Za-z0-9_.-]+$")
_TYPES = {"int64": pa.int64(), "double": pa.float64(), "string": pa.string(),
          "list<int32>": pa.list_(pa.int32()), "list<int64>": pa.list_(pa.int64())}
CQ_INT = ("frames", "flow_packets", "truncated_frames", "non_ip_frames", "ip_fragments",
          "other_l4_frames", "bad_header_frames", "pcap_bytes", "interval_seconds")
STORE_COLUMNS = ["run_id", "batch_id", "global_session_uid", "global_segment_uid",
                 "segment_start_ts", "segment_end_ts", "event_date",
                 "seq_first_dir", "seq_last_dir"]


def identifier(value: str) -> str:
    if not _IDENT.fullmatch(value) or value in (".", ".."):
        raise ValueError(f"not a safe identifier: {value!r}")
    return value


def pinned_schema(path: Path = SCHEMA) -> pa.Schema:
    spec = json.loads(path.read_text())
    return pa.schema([pa.field(n, _TYPES[t]) for n, t in spec["columns"]])


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def iter_sessions(csv_path: Path, schema: pa.Schema, block_bytes: int = 16 << 20):
    """Parse one bounded CSV block at a time, including the packet arrays."""
    with csv_path.open(encoding="utf-8") as fh:
        header = fh.readline().rstrip("\r\n").split(",")
    extra = sorted(set(header) - set(schema.names))
    missing = sorted(set(schema.names) - set(header))
    if extra or missing:
        raise ValueError(f"{csv_path.name} does not match {SCHEMA.name}: "
                         f"not in schema {extra}, not in csv {missing}")
    # Everything is read as text first and cast once, so a type comes from the
    # contract and never from what one batch happened to contain.
    with pcsv.open_csv(
        csv_path, read_options=pcsv.ReadOptions(block_size=block_bytes),
        convert_options=pcsv.ConvertOptions(
            column_types={n: pa.string() for n in header},
            strings_can_be_null=True, null_values=[""])) as reader:
        for batch in reader:
            table = pa.Table.from_batches([batch])
            cols = []
            for field in schema:
                col = table.column(field.name)
                if pa.types.is_list(field.type):
                    # The packet arrays travel as space-separated numbers; every
                    # row has at least one packet, so an empty cell is an error.
                    col = col.combine_chunks()
                    if col.null_count:
                        raise ValueError(f"{field.name}: row without packets")
                    parts = pc.split_pattern(col, " ")
                    values = pc.cast(parts.values, field.type.value_type)
                    cols.append(pa.ListArray.from_arrays(parts.offsets, values))
                elif pa.types.is_integer(field.type):
                    as_float = pc.cast(col, pa.float64())
                    frac = pc.not_equal(as_float, pc.floor(as_float))
                    if pc.any(frac).as_py():
                        raise ValueError(f"{field.name}: fractional value in an integer column")
                    cols.append(pc.cast(as_float, field.type))
                else:
                    cols.append(pc.cast(col, field.type))
            yield pa.Table.from_arrays(cols, schema=schema)


def read_sessions(csv_path: Path, schema: pa.Schema) -> pa.Table:
    """Small inputs/tests only; production conversion consumes iter_sessions."""
    return pa.concat_tables(list(iter_sessions(csv_path, schema)))


def add_keys(t: pa.Table, run_id: str, batch_id: str) -> pa.Table:
    n = t.num_rows
    start_us = pc.cast(pc.round(pc.multiply(t.column("session_start_epoch"), 1e6)), pa.int64())
    end_us = pc.cast(pc.round(pc.multiply(
        pc.add(t.column("session_start_epoch"), t.column("flow_duration")), 1e6)), pa.int64())
    seq = t.column("seq_signed_len").combine_chunks()
    first_dir = pc.cast(pc.sign(pc.list_element(seq, 0)), pa.int8())
    last_dir = pc.cast(pc.sign(pc.take(seq.values, pc.subtract(seq.offsets[1:], 1))), pa.int8())
    ts = pa.timestamp("us", tz="UTC")
    start = pc.cast(start_us, ts)
    extra = {
        "run_id": pa.array([run_id] * n, pa.string()),
        "batch_id": pa.array([batch_id] * n, pa.string()),
        "global_session_uid": pc.binary_join_element_wise(run_id, t.column("session_uid"), ":"),
        "global_segment_uid": pc.binary_join_element_wise(run_id, t.column("segment_uid"), ":"),
        "segment_start_ts": start,
        "segment_end_ts": pc.cast(end_us, ts),
        "event_date": pc.cast(start, pa.date32()),
        "seq_first_dir": first_dir,
        "seq_last_dir": last_dir,
    }
    for name in STORE_COLUMNS:
        t = t.append_column(name, extra[name])
    return t


def check(t: pa.Table) -> dict:
    uids = t.column("global_segment_uid")
    bad = pc.sum(pc.cast(pc.or_(pc.is_null(t.column("segment_start_ts")),
                                pc.less(t.column("segment_end_ts"), t.column("segment_start_ts"))),
                         pa.int64())).as_py() or 0
    report = {"rows": t.num_rows, "unique_segments": pc.count_distinct(uids).as_py(),
              "packets": pc.sum(t.column("pkt_count")).as_py() or 0, "bad_rows": bad}
    if not report["rows"] or report["rows"] != report["unique_segments"] or bad:
        raise ValueError(f"batch fails its own checks: {report}")
    return report


def capture_quality(journals: list[Path], rotate: int, start: float, end: float) -> pa.Table | None:
    import build_context_tables as ctx     # pandas; only this part needs it
    # Gaps are found on the capture's own grid (it starts when it starts, e.g.
    # at :41, not on a round second); the batch bounds only cut the result.
    # Anchoring the grid at the batch start would call every grid point that
    # is not a real interval start "missing".
    q = ctx.capture_quality(journals, rotate)
    q = q[(q.interval_start_epoch >= start) & (q.interval_start_epoch < end)]
    # How long a conversion took is a property of that run, not of the traffic:
    # kept out, so the same batch always makes the same file.
    q = q.drop(columns=["convert_seconds"], errors="ignore")
    if not len(q):
        return None
    # Counters are integers; pandas turns them into floats as soon as one
    # interval is missing. Types are fixed here so every batch agrees.
    for c in CQ_INT:
        if c in q.columns:
            q[c] = q[c].astype("Int64")
    return pa.Table.from_pandas(q, preserve_index=False)


HM_TYPES = {"host_key": pa.string(), "minute_epoch": pa.int64(), "bytes_out": pa.int64(),
            "bytes_in": pa.int64(), "pkts_out": pa.int64(), "pkts_in": pa.int64(),
            "peers": pa.int64(), "top_peer_bytes": pa.int64()}


def host_minutes_table(path: Path, run_id: str, batch_id: str) -> pa.Table:
    """host_minutes.py's CSV with fixed types, run keys and UTC time."""
    t = pcsv.read_csv(path, convert_options=pcsv.ConvertOptions(column_types=HM_TYPES))
    if t.column_names != list(HM_TYPES):
        raise ValueError(f"{path.name}: columns {t.column_names} != {list(HM_TYPES)}")
    ts = pc.cast(pc.multiply(t.column("minute_epoch"), 1_000_000), pa.timestamp("us", tz="UTC"))
    n = t.num_rows
    return (t.append_column("minute_ts", ts)
             .append_column("event_date", pc.cast(ts, pa.date32()))
             .append_column("run_id", pa.array([run_id] * n, pa.string()))
             .append_column("batch_id", pa.array([batch_id] * n, pa.string())))


def convert(batch_dir: Path, out_dir: Path, run_id: str, batch_id: str,
            journals: list[Path], rotate: int, batch_seconds: int | None,
            schema_path: Path = SCHEMA) -> dict:
    identifier(run_id)
    identifier(batch_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {"run_id": run_id, "batch_id": batch_id, "files": {}}
    tmp = out_dir / ".office_sessions.parquet.tmp"
    writer = None
    seen: set[str] = set()
    rows = packets = bad_rows = 0
    try:
        for chunk in iter_sessions(batch_dir / "office_sessions.csv", pinned_schema(schema_path)):
            t = add_keys(chunk, run_id, batch_id)
            part = check(t)
            ids = t.column("global_segment_uid").to_pylist()
            if any(uid in seen for uid in ids):
                raise ValueError("batch fails its own checks: duplicate segment across CSV blocks")
            seen.update(ids)
            rows += part["rows"]
            packets += part["packets"]
            bad_rows += part["bad_rows"]
            if writer is None:
                writer = pq.ParquetWriter(tmp, t.schema, compression="zstd",
                                          compression_level=6, write_statistics=True)
            writer.write_table(t, row_group_size=20000)
    finally:
        if writer is not None:
            writer.close()
    report["office_sessions"] = {"rows": rows, "unique_segments": len(seen),
                                 "packets": packets, "bad_rows": bad_rows}
    if not rows or rows != len(seen) or bad_rows:
        raise ValueError(f"batch fails its own checks: {report['office_sessions']}")
    back = pq.read_table(tmp, columns=["global_segment_uid", "pkt_count"])
    if back.num_rows != rows or pc.sum(back.column("pkt_count")).as_py() != packets:
        raise ValueError("parquet read back differs from the batch")
    final = out_dir / "office_sessions.parquet"
    tmp.replace(final)
    report["files"]["office_sessions.parquet"] = {"rows": rows, "sha256": sha256(final),
                                                  "bytes": final.stat().st_size}
    hm_csv = batch_dir / "office_host_minutes.csv"
    if hm_csv.exists():
        hm = host_minutes_table(hm_csv, run_id, batch_id)
        f = out_dir / "office_host_minutes.parquet"
        pq.write_table(hm, f, compression="zstd")
        report["files"][f.name] = {"rows": hm.num_rows, "sha256": sha256(f), "bytes": f.stat().st_size,
                                   "bytes_total": int((pc.sum(hm.column("bytes_out")).as_py() or 0)
                                                      + (pc.sum(hm.column("bytes_in")).as_py() or 0))}
    if journals:
        m = re.fullmatch(r"(\d{8}T\d{6})Z", batch_id)
        if m and batch_seconds:
            from datetime import datetime, timezone
            s = datetime.strptime(m.group(1), "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc).timestamp()
            q = capture_quality(journals, rotate, s, s + batch_seconds)
            if q is not None:
                q = q.append_column("run_id", pa.array([run_id] * q.num_rows, pa.string()))
                q = q.append_column("batch_id", pa.array([batch_id] * q.num_rows, pa.string()))
                f = out_dir / "office_capture_quality.parquet"
                pq.write_table(q, f, compression="zstd")
                report["files"][f.name] = {"rows": q.num_rows, "sha256": sha256(f),
                                           "bytes": f.stat().st_size}
    (out_dir / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--batch-dir", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--batch-id", help="default: the batch directory name")
    ap.add_argument("--journal", type=Path, nargs="*", default=[])
    ap.add_argument("--rotate-seconds", type=int, default=20)
    ap.add_argument("--batch-seconds", type=int)
    a = ap.parse_args()
    report = convert(a.batch_dir, a.out_dir, a.run_id, a.batch_id or a.batch_dir.name,
                     a.journal, a.rotate_seconds, a.batch_seconds)
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
