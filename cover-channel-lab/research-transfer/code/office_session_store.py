#!/usr/bin/env python3
"""Publish and query office session segments in one time-addressable Parquet dataset.

This is the filesystem-backed test implementation. Each publish targets one
immutable (UTC start day, run, batch) leaf, so a retry cannot append duplicates.
A governed Cosmolake table will need a transactional catalog before using this
as a shared production table.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import uuid
from pathlib import Path


_IDENT = re.compile(r"^[A-Za-z0-9_.-]+$")


def _identifier(value: str) -> str:
    if not _IDENT.fullmatch(value) or value in (".", ".."):
        raise ValueError(f"invalid identifier: {value!r}")
    return value


def _spark(cores: int, driver_memory: str = "4g"):
    from pyspark.sql import SparkSession
    return (SparkSession.builder.master(f"local[{cores}]")
            .appName("office_session_store")
            .config("spark.driver.memory", driver_memory)
            .config("spark.sql.session.timeZone", "UTC")
            .config("spark.sql.shuffle.partitions", "8")
            # A single packet-sequence cell may hold hundreds of thousands of
            # elements. The vectorized reader reserves a whole column batch.
            .config("spark.sql.parquet.enableVectorizedReader", "false")
            .config("spark.sql.sources.partitionColumnTypeInference.enabled", "false")
            .getOrCreate())


def prepare(source, run_id: str, batch_id: str):
    """Keep every feature, adding stable global keys and typed UTC bounds."""
    from pyspark.sql import functions as F

    _identifier(run_id)
    _identifier(batch_id)
    required = {"session_uid", "segment_uid", "segment_index", "session_continues",
                "session_start_epoch", "flow_duration", "pkt_count"}
    missing = required - set(source.columns)
    if missing:
        raise ValueError(f"source lacks session fields: {sorted(missing)}")
    if "batch" in source.columns:
        source = source.drop("batch")
    if any(c in source.columns for c in ("run_id", "batch_id", "segment_start_utc",
                                          "segment_end_utc", "event_date", "global_segment_uid",
                                          "global_session_uid")):
        raise ValueError("source already has store columns")
    return (source.withColumn("run_id", F.lit(run_id))
            .withColumn("batch_id", F.lit(batch_id))
            .withColumn("global_session_uid", F.concat_ws(":", F.lit(run_id), F.col("session_uid")))
            .withColumn("global_segment_uid", F.concat_ws(":", F.lit(run_id), F.col("segment_uid")))
            .withColumn("segment_start_utc", F.expr("timestamp_micros(CAST(round(session_start_epoch * 1000000) AS BIGINT))"))
            .withColumn("segment_end_utc", F.expr("timestamp_micros(CAST(round((session_start_epoch + flow_duration) * 1000000) AS BIGINT))"))
            .withColumn("event_date", F.date_format(F.col("segment_start_utc"), "yyyy-MM-dd")))


def _check(frame) -> dict:
    from pyspark.sql import functions as F

    counts = frame.agg(
        F.count("*").alias("rows"),
        F.countDistinct("global_segment_uid").alias("unique_segments"),
        F.sum(F.col("pkt_count").cast("long")).alias("packets"),
        F.sum(F.when(F.col("segment_start_utc").isNull() |
                     F.col("segment_end_utc").isNull() |
                     (F.col("segment_end_utc") < F.col("segment_start_utc")) |
                     (F.col("session_uid").isNull()) |
                     (F.col("segment_uid").isNull()), 1).otherwise(0)).alias("bad_rows"),
    ).first().asDict()
    return {k: int(v or 0) for k, v in counts.items()}


def publish(spark, source_path: Path, store_root: Path, run_id: str, batch_id: str,
            source_manifest: Path | None = None) -> dict:
    """Publish an immutable batch; re-run verifies existing leaves and skips them."""
    from pyspark.sql import functions as F

    root = Path(store_root)
    if not root.is_absolute():
        raise ValueError("store root must be an absolute local path")
    manifest_sha = (hashlib.sha256(source_manifest.read_bytes()).hexdigest()
                    if source_manifest else None)
    if "batch=" in str(source_path):
        source = spark.read.parquet(str(source_path))
    else:
        source = (spark.read.option("basePath", str(source_path))
                  .parquet(str(source_path)))
        if "batch" in source.columns:
            source = source.where(F.col("batch") == batch_id)
    frame = prepare(source, run_id, batch_id)
    before = _check(frame)
    if not before["rows"] or before["rows"] != before["unique_segments"] or before["bad_rows"]:
        raise ValueError(f"invalid source batch: {before}")
    days = [r[0] for r in frame.select("event_date").distinct().collect()]
    if None in days:
        raise ValueError("null event_date")
    outcomes = []
    for day in sorted(days):
        leaf = root / f"event_date={day}" / f"run_id={run_id}" / f"batch_id={batch_id}"
        subset = frame.where(F.col("event_date") == day).drop("event_date", "run_id", "batch_id")
        expected = _check(subset)
        if leaf.exists():
            marker = leaf / "_source_manifest.json"
            if manifest_sha is not None and (
                not marker.exists() or
                json.loads(marker.read_text()).get("sha256") != manifest_sha
            ):
                raise ValueError(f"existing leaf has another source manifest: {leaf}")
            got = _check(spark.read.parquet(str(leaf)))
            if got != expected:
                raise ValueError(f"existing leaf differs: {leaf}: {got} != {expected}")
            outcomes.append({"day": day, "status": "already_present", **got})
            continue
        leaf.parent.mkdir(parents=True, exist_ok=True)
        # Readers ignore hidden pending directories. Rename on the same local
        # filesystem makes a verified batch visible in one step.
        pending = leaf.parent / f"._pending_{batch_id}_{uuid.uuid4().hex}"
        subset.write.mode("errorifexists").parquet(str(pending))
        got = _check(spark.read.parquet(str(pending)))
        if got != expected:
            raise ValueError(f"written leaf differs: {pending}: {got} != {expected}")
        (pending / "_source_manifest.json").write_text(
            json.dumps({"sha256": manifest_sha, "store_format": 1}) + "\n")
        if leaf.exists():
            raise ValueError(f"concurrent publication created {leaf}")
        pending.rename(leaf)
        outcomes.append({"day": day, "status": "written", **got})
    if sum(x["rows"] for x in outcomes) != before["rows"]:
        raise ValueError("published row count differs from source")
    return {"run_id": run_id, "batch_id": batch_id, "source": before, "leaves": outcomes}


def read_store(spark, root: Path):
    # Feature columns can be added between runs. Without mergeSchema Spark
    # silently uses one part-file schema and hides the newer columns.
    return (spark.read.option("basePath", str(root)).option("mergeSchema", "true")
            .parquet(str(root)))


def overlapping(frame, start_utc: str, end_utc: str):
    """Return segments active in [start, end), including earlier starts."""
    from datetime import datetime, timezone
    from pyspark.sql import functions as F

    def parse(value: str):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError("timestamps must include UTC offset")
        return dt.astimezone(timezone.utc).replace(tzinfo=None)

    start, end = parse(start_utc), parse(end_utc)
    if end <= start:
        raise ValueError("end must be after start")
    return frame.where((F.col("segment_start_utc") < F.lit(end)) &
                       (F.col("segment_end_utc") >= F.lit(start)))


def session(frame, run_id: str, session_uid: str):
    from pyspark.sql import functions as F
    return (frame.where((F.col("run_id") == run_id) &
                        (F.col("session_uid") == session_uid))
            .orderBy("segment_index"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cores", type=int, default=4)
    ap.add_argument("--driver-memory", default="4g")
    sub = ap.add_subparsers(dest="command", required=True)
    pub = sub.add_parser("publish")
    pub.add_argument("--source", required=True, type=Path)
    pub.add_argument("--root", required=True, type=Path)
    pub.add_argument("--run-id", required=True)
    pub.add_argument("--batch-id", required=True)
    pub.add_argument("--source-manifest", type=Path)
    ran = sub.add_parser("range")
    ran.add_argument("--root", required=True, type=Path)
    ran.add_argument("--start-utc", required=True)
    ran.add_argument("--end-utc", required=True)
    ran.add_argument("--limit", type=int, default=20)
    one = sub.add_parser("session")
    one.add_argument("--root", required=True, type=Path)
    one.add_argument("--run-id", required=True)
    one.add_argument("--session-uid", required=True)
    one.add_argument("--export-parquet", type=Path)
    args = ap.parse_args()
    spark = _spark(args.cores, args.driver_memory)
    spark.sparkContext.setLogLevel("ERROR")
    try:
        if args.command == "publish":
            result = publish(spark, args.source, args.root, args.run_id, args.batch_id,
                             args.source_manifest)
        elif args.command == "range":
            from pyspark.sql import functions as F
            hits = overlapping(read_store(spark, args.root), args.start_utc, args.end_utc)
            result = [r.asDict() for r in hits.groupBy("run_id", "session_uid")
                      .agg(F.min("segment_start_utc").cast("string").alias("first_matching_segment"),
                           F.max("segment_end_utc").cast("string").alias("last_matching_segment"),
                           F.count("*").alias("matching_segments"))
                      .orderBy("run_id", "session_uid").limit(args.limit).collect()]
        else:
            found = session(read_store(spark, args.root), args.run_id, args.session_uid)
            if args.export_parquet:
                if args.export_parquet.exists():
                    raise ValueError("export destination already exists")
                found.write.mode("errorifexists").parquet(str(args.export_parquet))
            result = [r.asDict(recursive=True) for r in found.select(
                "run_id", "batch_id", "session_uid", "segment_uid", "segment_index",
                "session_continues", "segment_start_utc", "segment_end_utc", "pkt_count")
                      .collect()]
        print(json.dumps(result, ensure_ascii=False, default=str))
        return 0
    finally:
        spark.stop()


if __name__ == "__main__":
    raise SystemExit(main())
