#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def read_jsonl(path: Path) -> pd.DataFrame:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        raise SystemExit(f"empty manifest: {path}")
    return pd.DataFrame(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--executed", type=Path, required=True)
    parser.add_argument("--planned", type=Path, required=True)
    parser.add_argument("--bronze", type=Path, required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--shard", required=True)
    parser.add_argument("--seed", type=int, required=True)
    args = parser.parse_args()

    manifests = args.bronze / "manifests"
    manifests.mkdir(parents=True, exist_ok=True)

    sessions = read_jsonl(args.executed)
    planned = read_jsonl(args.planned)
    if sessions["session_id"].duplicated().any():
        raise SystemExit("duplicate executed session_id")
    if len(sessions) != len(planned):
        raise SystemExit("planned/executed session count mismatch")
    if set(sessions["session_id"]) != set(planned["session_id"]):
        raise SystemExit("planned/executed session IDs differ")

    shutil.copy2(args.executed, manifests / "sessions.jsonl")
    shutil.copy2(args.planned, manifests / "sessions-planned.jsonl")
    sessions.to_parquet(manifests / "sessions.parquet", index=False)

    ground_truth_cols = [
        "campaign_id", "scenario_id", "session_id", "pair_id", "label_binary", "label_family",
        "mitre_technique", "src_role", "dst_role", "src_host_id", "dst_host_id", "src_ip", "dst_ip",
        "dst_port", "protocol", "action", "wire_fidelity", "semantic_fidelity", "ground_truth_source",
        "netem_profile", "generator_seed", "start_ts", "end_ts", "status",
    ]
    sessions[ground_truth_cols].to_parquet(manifests / "ground_truth.parquet", index=False)

    with args.topology.open(encoding="utf-8") as fh:
        topology = yaml.safe_load(fh)
    hosts = pd.DataFrame(topology["hosts"])
    hosts.to_parquet(manifests / "hosts.parquet", index=False)

    campaigns = (
        sessions.groupby("campaign_id", as_index=False)
        .agg(
            session_count=("session_id", "count"),
            suspicious_count=("label_binary", "sum"),
            start_ts=("start_ts", "min"),
            end_ts=("end_ts", "max"),
        )
    )
    campaigns["benign_count"] = campaigns["session_count"] - campaigns["suspicious_count"]
    campaigns["stage"] = args.stage
    campaigns.to_parquet(manifests / "campaigns.parquet", index=False)

    repro = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "github_sha": os.environ.get("GITHUB_SHA", "local"),
        "github_run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "runner_os": os.environ.get("RUNNER_OS", "local"),
        "runner_arch": os.environ.get("RUNNER_ARCH", "unknown"),
        "stage": args.stage,
        "shard": args.shard,
        "seed": args.seed,
        "session_count": int(len(sessions)),
        "ground_truth_source": "scenario_orchestrator",
        "source_port_policy": "0 means unknown until network parser observation",
        "external_routing": False,
        "payload_execution": False,
        "bronze_contract_version": 1,
    }
    (args.bronze / "reproducibility.json").write_text(
        json.dumps(repro, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
