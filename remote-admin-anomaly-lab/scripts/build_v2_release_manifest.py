#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--shard", required=True)
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--data-source-run-id", default="")
    parser.add_argument("--data-source-git-sha", default="")
    args = parser.parse_args()

    release = args.release.resolve()
    if not release.is_dir():
        raise SystemExit(f"release directory missing: {release}")
    decision = json.loads(args.decision.read_text(encoding="utf-8"))
    if decision.get("dataset_release_status") != "READY":
        raise SystemExit("cannot manifest technically incomplete V2 release")

    required = [
        release / "bronze" / args.shard / "manifests" / "sessions.parquet",
        release / "silver" / args.shard / "suricata" / "eve.json.zst",
        release / "gold" / args.shard / "production_flow_features.parquet",
        release / "gold" / args.shard / "session_features.parquet",
        release / "gold" / args.shard / "campaign_features.parquet",
        release / "gold" / args.shard / "models" / "session-primary.joblib",
        release / "quality" / args.shard / "production_flow_gold.json",
        release / "quality" / args.shard / "V2_RESEARCH_DECISION.json",
        release / "quality" / args.shard / "external" / "lanl" / "reference_quality.json",
        release / "quality" / args.shard / "external" / "windows" / "windows_fidelity.json",
    ]
    pcaps = list((release / "bronze" / args.shard / "captures").glob("*.pcap.zst"))
    if len(pcaps) != 1:
        raise SystemExit(f"expected exactly one Linux Bronze PCAP, got {len(pcaps)}")
    required.append(pcaps[0])
    missing = [str(path.relative_to(release)) for path in required if not path.is_file() or path.stat().st_size <= 0]
    if missing:
        raise SystemExit("required V2 release files missing/empty: " + ", ".join(missing))

    out_resolved = args.out.resolve()
    files: list[dict] = []
    layer_bytes: dict[str, int] = {}
    for path in sorted(item for item in release.rglob("*") if item.is_file()):
        if path.resolve() == out_resolved:
            continue
        rel = path.relative_to(release).as_posix()
        size = path.stat().st_size
        top = rel.split("/", 1)[0]
        layer_bytes[top] = layer_bytes.get(top, 0) + size
        files.append({"path": rel, "bytes": size, "sha256": sha256(path)})

    finalize_run_id = os.environ.get("GITHUB_RUN_ID", "")
    finalize_git_sha = os.environ.get("GITHUB_SHA", "")
    source_run_id = str(args.data_source_run_id or finalize_run_id)
    source_git_sha = str(args.data_source_git_sha or finalize_git_sha)
    payload = {
        "schema_version": 2,
        "dataset": "remote-admin-anomaly-v2",
        "shard": args.shard,
        "git_sha": finalize_git_sha,
        "github_run_id": finalize_run_id,
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "provenance": {
            "data_generation_run_id": source_run_id,
            "data_generation_git_sha": source_git_sha,
            "finalization_run_id": finalize_run_id,
            "finalization_git_sha": finalize_git_sha,
            "recovered_from_retained_artifact": bool(source_run_id and source_run_id != finalize_run_id),
        },
        "dataset_release_status": decision.get("dataset_release_status"),
        "research_status": decision.get("research_status"),
        "scale_decision": decision.get("scale_decision"),
        "file_count": len(files),
        "total_bytes": sum(item["bytes"] for item in files),
        "layer_bytes": dict(sorted(layer_bytes.items())),
        "files": files,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: payload[k] for k in ("dataset_release_status", "research_status", "scale_decision", "file_count", "total_bytes", "layer_bytes", "provenance")}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
