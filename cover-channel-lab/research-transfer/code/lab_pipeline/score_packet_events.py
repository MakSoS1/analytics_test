#!/usr/bin/env python3
"""Continuous consumer: observations in, SOC alerts out, with backpressure.

Reads fast-v1 observation records (the Lua exporter's JSON lines, or the offline
reducer's), scores each against a validated bundle, and submits alerts to a local
sink.

Three behaviours that matter more than throughput:

* **A full queue drops explicitly.** When the consumer cannot keep up, records
  are dropped and counted. They are never silently scored later as if they had
  been timely, and a dropped record is not a benign verdict.
* **A failed score is an error, not a negative.** A malformed record, a NaN, a
  vector that does not match the contract — each increments its own counter and
  the record is skipped. Nothing downstream may read "no alert" as "clean".
* **Bounded memory.** The queue has a hard cap; the dedup table has a hard cap.
  Neither grows with traffic.

Not a SOC transport. Alerts land in a local sink; routing is a separate decision.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from pathlib import Path
from typing import Any, Iterable, Iterator

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
from lab_pipeline.alert_schema import AlertSink, DurableWriteError, build_alert  # noqa: E402
from lab_pipeline.jsonl_tail import CheckpointedTail
from lab_pipeline.model_bundle import BundleError, ModelBundle  # noqa: E402


class ObservationConsumer:
    def __init__(
        self,
        bundle: ModelBundle,
        sink: AlertSink,
        *,
        sensor_id: str = "sensor-0",
        sensor_epoch: str = "epoch-0",
        queue_limit: int = 10_000,
        batch_size: int = 256,
    ) -> None:
        self.bundle = bundle
        self.sink = sink
        self.sensor_id = sensor_id
        self.sensor_epoch = sensor_epoch
        self.queue_limit = queue_limit
        self.batch_size = batch_size
        self._q: deque[dict[str, Any]] = deque()
        self.counters: dict[str, int] = {
            "offered": 0, "queued": 0, "dropped_backpressure": 0,
            "scored": 0, "skipped_unscorable": 0,
            "rejected_schema": 0, "rejected_vector": 0, "errors": 0,
        }

    # ---- ingestion -------------------------------------------------------
    def offer(self, rec: dict[str, Any]) -> bool:
        """Accept a record, or drop it loudly when the queue is full."""
        self.counters["offered"] += 1
        if len(self._q) >= self.queue_limit:
            self.counters["dropped_backpressure"] += 1
            return False
        self._q.append(rec)
        self.counters["queued"] += 1
        return True

    def pending(self) -> int:
        return len(self._q)

    # ---- processing ------------------------------------------------------
    def drain(self, limit: int | None = None) -> int:
        n = 0
        budget = limit if limit is not None else self.batch_size
        while self._q and n < budget:
            rec = self._q.popleft()
            try:
                self._process(rec)
            except DurableWriteError:
                self._q.appendleft(rec)
                raise
            n += 1
        return n

    def _process(self, rec: dict[str, Any]) -> None:
        try:
            if rec.get("schema_version") != self.bundle.schema_version:
                self.counters["rejected_schema"] += 1
                return
            if rec.get("contract_hash") != self.bundle.contract_hash:
                self.counters["rejected_schema"] += 1
                return
            if not rec.get("scorable", True):
                # Recorded, never scored, and never counted as clean.
                self.counters["skipped_unscorable"] += 1
                self.sink.counters["suppressed_not_scorable"] += 1
                return
            features = rec.get("features")
            if not isinstance(features, dict):
                self.counters["rejected_vector"] += 1
                return
            try:
                score = self.bundle.score(features)
            except ValueError:
                self.counters["rejected_vector"] += 1
                return
            alert = build_alert(
                rec, score,
                bundle_id=self.bundle.model_id,
                threshold=self.bundle.threshold,
                sensor_id=self.sensor_id,
                sensor_epoch=self.sensor_epoch,
            )
            self.counters["scored"] += 1
            if alert.tunnel_detected:
                self.sink.submit(alert)
            else:
                self.sink.counters["decisions"] += 1
        except DurableWriteError:
            raise
        except Exception:  # noqa: BLE001 - one bad record must not stop the stream
            self.counters["errors"] += 1

    def run(self, records: Iterable[dict[str, Any]]) -> None:
        for rec in records:
            if not self.offer(rec):
                self.drain()
                self.offer(rec)
            if self.pending() >= self.batch_size:
                self.drain()
        while self.pending():
            self.drain()

    def report(self) -> dict[str, Any]:
        return {
            "model": self.bundle.describe(),
            "consumer": dict(self.counters),
            "sink": dict(self.sink.counters),
            "alerts_held": len(self.sink),
            "note": "dropped_backpressure and skipped_unscorable are NOT benign verdicts",
        }


def process_available(tail: CheckpointedTail, consumer: "ObservationConsumer") -> int:
    """Read what is on disk, score all of it, then checkpoint.

    Drain while reading so a large file cannot overflow the queue and then
    have its offset committed past the drops. A durable-write failure leaves
    the checkpoint unmoved so the records can be retried.
    """
    offered = 0
    try:
        for rec in tail.read_available():
            if not consumer.offer(rec):
                while consumer.pending():
                    consumer.drain()
                consumer.offer(rec)
            offered += 1
        while consumer.pending():
            consumer.drain()
    except DurableWriteError:
        consumer.counters["errors"] += 1
        raise
    tail.commit()
    return offered


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    opener: Any = open
    if path.suffix == ".gz":
        import gzip

        opener = gzip.open
    with opener(path, "rt", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except ValueError:
                continue


def _follow(args: Any, consumer: "ObservationConsumer") -> int:
    """Run until told to stop, surviving appends, rotation and restart.

    Read, process, then commit — in that order. A checkpoint written before the
    records were acted on turns a crash into a gap in coverage; written after,
    it turns a crash into a repeat, and repeats are what the alert dedup already
    absorbs. Losing a decision is not a benign verdict, so the two are never
    traded for each other.
    """
    import signal
    import time

    ckpt = Path(args.checkpoint) if args.checkpoint else Path(str(args.observations) + ".ckpt")
    tail = CheckpointedTail(Path(args.observations), ckpt)

    stopping = {"now": False}

    def _stop(_signum, _frame):
        stopping["now"] = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    last_status = time.monotonic()
    print(json.dumps({"status": "following", "observations": str(args.observations),
                      "checkpoint": str(ckpt)}), flush=True)
    while not stopping["now"]:
        try:
            offered = process_available(tail, consumer)
        except DurableWriteError as exc:
            print(json.dumps({
                "status": "durable_write_failed",
                "error": str(exc),
                "note": "checkpoint not advanced; undelivered alerts will be retried",
                "pending": consumer.pending(),
            }), flush=True)
            time.sleep(args.poll_seconds)
            continue

        now = time.monotonic()
        if now - last_status >= args.status_seconds:
            rep = consumer.report()
            rep["tail"] = dict(tail.counters)
            print(json.dumps(rep), flush=True)
            last_status = now
        if offered == 0:
            time.sleep(args.poll_seconds)

    try:
        process_available(tail, consumer)
    except DurableWriteError as exc:
        print(json.dumps({
            "status": "durable_write_failed",
            "error": str(exc),
            "note": "stopped with checkpoint unmoved",
            "pending": consumer.pending(),
        }), flush=True)
    report = consumer.report()
    report["tail"] = dict(tail.counters)
    report["status"] = "stopped"
    if args.out_json:
        Path(args.out_json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report), flush=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True)
    ap.add_argument("--observations", required=True, help="JSON lines from the exporter")
    ap.add_argument("--sensor-id", default="sensor-0")
    ap.add_argument("--sensor-epoch", default="epoch-0")
    ap.add_argument("--queue-limit", type=int, default=10_000)
    ap.add_argument("--allow-contract-mismatch", action="store_true",
                    help="load the bundle without the contract check (diagnostics only)")
    ap.add_argument("--out-json", default=None)
    ap.add_argument("--follow", action="store_true",
                    help="keep running: tail the file across appends and rotations")
    ap.add_argument("--checkpoint", default=None,
                    help="where --follow remembers its position (default: <observations>.ckpt)")
    ap.add_argument("--poll-seconds", type=float, default=1.0)
    ap.add_argument("--status-seconds", type=float, default=60.0,
                    help="how often --follow prints counters")
    ap.add_argument("--alerts-jsonl", default=None,
                    help="durable local JSONL journal for alerts (survives restart)")
    args = ap.parse_args()

    try:
        bundle = ModelBundle.load(args.model, strict=not args.allow_contract_mismatch)
    except BundleError as exc:
        print(json.dumps({"status": "refused", "reason": str(exc)}))
        return 2

    consumer = ObservationConsumer(
        bundle, AlertSink(journal_path=args.alerts_jsonl),
        sensor_id=args.sensor_id, sensor_epoch=args.sensor_epoch,
        queue_limit=args.queue_limit,
    )
    if args.follow:
        return _follow(args, consumer)

    consumer.run(iter_jsonl(Path(args.observations)))
    report = consumer.report()
    if args.out_json:
        Path(args.out_json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
