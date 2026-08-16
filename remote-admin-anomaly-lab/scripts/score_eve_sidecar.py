#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.online_features import EveFeatureState, is_remote_admin_flow  # noqa:E402


def load_state(path: Path | None) -> EveFeatureState:
    if path is None or not path.exists():
        return EveFeatureState()
    payload = json.loads(path.read_text(encoding="utf-8"))
    return EveFeatureState.from_dict(payload)


def save_state(path: Path | None, state: EveFeatureState) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp-{os.getpid()}")
    tmp.write_text(json.dumps(state.to_dict(), sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--eve", default="-")
    parser.add_argument("--emit-all", action="store_true")
    parser.add_argument("--state-file", type=Path)
    parser.add_argument("--checkpoint-every", type=int, default=100)
    args = parser.parse_args()
    if args.checkpoint_every <= 0:
        raise SystemExit("--checkpoint-every must be positive")

    model = joblib.load(args.model)
    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    threshold = float(metrics["threshold"])
    columns = list(model.feature_names_in_)
    state = load_state(args.state_file)
    fh = sys.stdin if args.eve == "-" else open(args.eve, encoding="utf-8")
    consumed = 0
    try:
        for line in fh:
            if not line.strip():
                continue
            event = json.loads(line)
            if not is_remote_admin_flow(event):
                continue
            row = state.consume_flow(event)
            consumed += 1
            features = row["features"]
            data = {
                column: features.get(column, "unknown" if column == "app_proto" else 0.0)
                for column in columns
            }
            score = float(model.predict_proba(pd.DataFrame([data], columns=columns))[:, 1][0])
            alert = score >= threshold
            if alert or args.emit_all:
                out = {
                    "event_type": "remote_admin_ml",
                    "risk_score": score,
                    "threshold": threshold,
                    "alert": alert,
                    "model": "M1-lightgbm-flow",
                    "candidate_stream": "remote-admin",
                    "state_persistent": args.state_file is not None,
                    "context": row["context"],
                }
                print(json.dumps(out, sort_keys=True), flush=True)
            if consumed % args.checkpoint_every == 0:
                save_state(args.state_file, state)
    finally:
        save_state(args.state_file, state)
        if fh is not sys.stdin:
            fh.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
