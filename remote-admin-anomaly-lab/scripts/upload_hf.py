#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from huggingface_hub import HfApi, create_repo

DEFAULT_REPO = "Maksim123321/remote-admin-anomaly-v1"
REQUIRED_LAYERS = ("bronze", "silver", "gold", "quality")


def validate_release_shard(release: Path, shard: str) -> dict[str, int]:
    sizes: dict[str, int] = {}
    missing: list[str] = []
    for layer in REQUIRED_LAYERS:
        path = release / layer / shard
        if not path.is_dir():
            missing.append(f"{layer}/{shard}")
            continue
        total = sum(item.stat().st_size for item in path.rglob("*") if item.is_file())
        if total <= 0:
            missing.append(f"{layer}/{shard}:empty")
        sizes[layer] = total
    if missing:
        raise ValueError(f"release shard is incomplete: {missing}")
    bronze_pcaps = list((release / "bronze" / shard / "captures").glob("*.pcap.zst"))
    if len(bronze_pcaps) != 1 or bronze_pcaps[0].stat().st_size <= 0:
        raise ValueError("Bronze must contain exactly one non-empty full .pcap.zst capture")
    return sizes


def write_status(path: Path | None, payload: dict) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--shard", required=True)
    parser.add_argument("--remote-path", required=True)
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--status", type=Path)
    args = parser.parse_args()

    token = os.environ.get("HF_TOKEN", "").strip()
    token_present = bool(token)
    base = {
        "repo": args.repo,
        "repo_type": "dataset",
        "private": True,
        "shard": args.shard,
        "remote_path": args.remote_path.strip("/"),
        "token_present": token_present,
    }
    if not token:
        payload = {**base, "status": "skipped", "reason": "HF_TOKEN missing"}
        write_status(args.status, payload)
        print(json.dumps(payload, sort_keys=True))
        return 0

    release = args.release.resolve()
    sizes = validate_release_shard(release, args.shard)
    create_repo(
        repo_id=args.repo,
        repo_type="dataset",
        private=True,
        exist_ok=True,
        token=token,
    )
    api = HfApi(token=token)

    uploaded: dict[str, str] = {}
    for layer in REQUIRED_LAYERS:
        local = release / layer / args.shard
        remote = f"{args.remote_path.strip('/')}/{layer}/{args.shard}"
        api.upload_folder(
            repo_id=args.repo,
            repo_type="dataset",
            folder_path=str(local),
            path_in_repo=remote,
            token=token,
            commit_message=f"Remote Admin V1 {args.shard} {layer}",
        )
        uploaded[layer] = remote

    payload = {
        **base,
        "status": "uploaded",
        "reason": "complete recoverable shard uploaded",
        "layer_bytes": sizes,
        "uploaded_paths": uploaded,
    }
    write_status(args.status, payload)
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
