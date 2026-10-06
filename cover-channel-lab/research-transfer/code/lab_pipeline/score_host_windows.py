#!/usr/bin/env python3
"""Score host20 windows and raise alerts that update the fast incident.

A host20 finding is a second opinion about the same host, not a second alarm
about the same connection. It therefore:

* never suppresses a fast alert — the fast level publishes immediately and this
  arrives later by construction, after the window has accumulated;
* carries `source="host20"`, so correlation is possible while dedup stays
  per-source;
* refuses to score a window that is not `full` — a `warmup` or `partial` window
  is missing minutes, and scoring it would silently treat absence as quiet.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterator

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
from lab_pipeline.alert_schema import AlertSink, build_alert  # noqa: E402
from lab_pipeline.host_schema import (  # noqa: E402
    HOST_FEATURES,
    HOST_SCHEMA_VERSION,
    contract_hash,
    validate_host_vector,
)


class HostScorer:
    def __init__(self, model: dict[str, Any], sink: AlertSink,
                 sensor_id: str = "sensor-0", sensor_epoch: str = "epoch-0") -> None:
        if model.get("schema_version") != HOST_SCHEMA_VERSION:
            raise ValueError(f"host model schema {model.get('schema_version')!r} != {HOST_SCHEMA_VERSION!r}")
        if model.get("contract_hash") != contract_hash():
            raise ValueError("host contract hash mismatch: the aggregator computes something else")
        if list(model.get("features") or []) != list(HOST_FEATURES):
            raise ValueError("host feature list or order differs from the contract")
        self.model = model
        self.sink = sink
        self.sensor_id = sensor_id
        self.sensor_epoch = sensor_epoch
        self.threshold = float(model.get("threshold", 0.5))
        self.counters = {"seen": 0, "scored": 0, "skipped_not_full": 0, "rejected": 0}

    def score_window(self, window: dict[str, Any]) -> float | None:
        from lab_pipeline.flow_tier import predict_proba

        self.counters["seen"] += 1
        if window.get("window_status") != "full":
            self.counters["skipped_not_full"] += 1
            return None
        feats = window.get("features") or {}
        try:
            validate_host_vector(feats)
        except ValueError:
            self.counters["rejected"] += 1
            return None
        self.counters["scored"] += 1
        return predict_proba(self.model, feats)

    def process(self, window: dict[str, Any]) -> str | None:
        score = self.score_window(window)
        if score is None or score < self.threshold:
            return None
        observation = {
            "schema_version": HOST_SCHEMA_VERSION,
            "contract_hash": window.get("contract_hash", ""),
            # One incident per host window end, so a re-delivered window collapses.
            "flow_instance_id": f"{window['host_key']}@{int(float(window['window_end']))}",
            "decision_reason": "host_window",
            "start_observed": True,
            "observed_packets": int(window["features"].get("flows_started", 0)),
            "observation_start": float(window["window_end"]) - 20 * 60,
            "observation_end": float(window["window_end"]),
            "features": window["features"],
        }
        alert = build_alert(
            observation, score,
            bundle_id=str(self.model.get("model_id", "host20")),
            threshold=self.threshold,
            sensor_id=self.sensor_id, sensor_epoch=self.sensor_epoch,
            source="host20", host_key=window["host_key"],
        )
        return self.sink.submit(alert)


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("rt", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except ValueError:
                    continue


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True)
    ap.add_argument("--windows", required=True, help="JSON lines from host_windows")
    ap.add_argument("--sensor-id", default="sensor-0")
    ap.add_argument("--sensor-epoch", default="epoch-0")
    ap.add_argument("--out-json", default=None)
    args = ap.parse_args()

    model = json.loads(Path(args.model).read_text())
    try:
        scorer = HostScorer(model, AlertSink(), args.sensor_id, args.sensor_epoch)
    except ValueError as exc:
        print(json.dumps({"status": "refused", "reason": str(exc)}))
        return 2

    for w in iter_jsonl(Path(args.windows)):
        scorer.process(w)

    report = {
        "status": "ok",
        "scorer": scorer.counters,
        "sink": dict(scorer.sink.counters),
        "alerts": len(scorer.sink),
        "note": "host20 never suppresses a fast alert; it arrives later by construction",
    }
    if args.out_json:
        Path(args.out_json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
