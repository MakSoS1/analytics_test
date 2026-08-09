#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

from huggingface_hub import HfApi, snapshot_download

from coverlab.validate_dataset_contract import validate


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--source-release", required=True)
    ap.add_argument("--shard", required=True)
    ap.add_argument("--dest-release", required=True)
    ap.add_argument("--cache-dir", required=True)
    ap.add_argument("--allow-legacy-trusted-bg", action="store_true")
    args = ap.parse_args()

    token = os.environ.get("HF_TOKEN")
    if not token:
        raise SystemExit("HF_TOKEN is required for private shard reuse")

    # Stage G from pre-contract-revision-2 releases is intentionally invalidated:
    # it used a post-hoc manifest rewrite and an unsafe split rule.
    if args.shard.startswith("trusted-bg-") and not args.allow_legacy_trusted_bg:
        print(json.dumps({"reused": False, "reason": "trusted_background_policy_changed", "shard": args.shard}))
        raise SystemExit(3)

    cache = Path(args.cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    pattern = f"releases/{args.source_release}/{args.shard}/**"
    try:
        root = Path(
            snapshot_download(
                repo_id=args.repo,
                repo_type="dataset",
                token=token,
                allow_patterns=[pattern],
                local_dir=cache,
            )
        )
    except Exception as exc:
        print(json.dumps({"reused": False, "reason": "download_failed", "error": str(exc), "shard": args.shard}))
        raise SystemExit(3)

    source = root / "releases" / args.source_release / args.shard
    quality = source / "quality" / args.shard / "capture_health.json"
    checksums = source / "quality" / args.shard / "checksums.json"
    bronze = source / "bronze" / args.shard
    pcap_files = list((bronze / "captures").glob("*.pcap.zst")) if bronze.exists() else []

    if not source.exists() or not quality.exists() or not checksums.exists() or not pcap_files:
        print(json.dumps({"reused": False, "reason": "incomplete_source_shard", "shard": args.shard}))
        raise SystemExit(3)

    try:
        health = json.loads(quality.read_text())
        checksum_map = json.loads(checksums.read_text())
    except Exception as exc:
        print(json.dumps({"reused": False, "reason": "invalid_quality_metadata", "error": str(exc), "shard": args.shard}))
        raise SystemExit(3)

    if health.get("passed") is not True or health.get("mapping_coverage_ge_0_95") is not True:
        print(json.dumps({"reused": False, "reason": "quality_gate_not_passed", "health": health, "shard": args.shard}))
        raise SystemExit(3)
    if not checksum_map:
        print(json.dumps({"reused": False, "reason": "empty_checksum_manifest", "shard": args.shard}))
        raise SystemExit(3)
    if not all(p.stat().st_size > 32 for p in pcap_files):
        print(json.dumps({"reused": False, "reason": "empty_pcap", "shard": args.shard}))
        raise SystemExit(3)

    contract = validate(bronze)
    if not contract["passed"]:
        print(json.dumps({"reused": False, "reason": "contract_failed", "contract": contract, "shard": args.shard}))
        raise SystemExit(3)

    dest = Path(args.dest_release)
    dest.mkdir(parents=True, exist_ok=True)
    for child in source.iterdir():
        target = dest / child.name
        if child.is_dir():
            shutil.copytree(child, target, dirs_exist_ok=True)
        else:
            shutil.copy2(child, target)

    info = HfApi(token=token).repo_info(repo_id=args.repo, repo_type="dataset")
    provenance = {
        "reused": True,
        "source_release": args.source_release,
        "source_hf_revision": getattr(info, "sha", None),
        "shard": args.shard,
        "source_capture_health": health,
        "contract": contract,
        "reuse_policy_revision": 2,
    }
    qdir = dest / "quality" / args.shard
    qdir.mkdir(parents=True, exist_ok=True)
    (qdir / "reuse_provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"reused": True, "shard": args.shard, "source_release": args.source_release}))


if __name__ == "__main__":
    main()
