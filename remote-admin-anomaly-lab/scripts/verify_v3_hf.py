#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from huggingface_hub import snapshot_download

from adminlab.v3_persistence import expected_remote_paths
from adminlab.v3_remote_verify import verify_downloaded_remote_tree


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--upload-status", type=Path, required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--shard", required=True)
    parser.add_argument("--remote-prefix", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    token = os.environ.get("HF_TOKEN", "").strip()
    if not token:
        raise SystemExit("HF_TOKEN required for V3 remote verification")
    manifest = load_json(args.manifest)
    upload = load_json(args.upload_status)
    if upload.get("status") != "uploaded":
        raise SystemExit(f"V3 HF upload did not complete: {upload}")
    if str(upload.get("remote_path", "")).strip("/") != args.remote_prefix.strip("/"):
        raise SystemExit("HF upload remote path differs from requested verification prefix")

    expected = expected_remote_paths(
        manifest,
        upload,
        shard=args.shard,
        remote_prefix=args.remote_prefix,
    )
    prefix = args.remote_prefix.strip("/")
    with tempfile.TemporaryDirectory(prefix="v3-hf-verify-") as tmp:
        local = Path(tmp)
        snapshot_download(
            repo_id=args.repo,
            repo_type="dataset",
            token=token,
            allow_patterns=[f"{prefix}/**"],
            local_dir=local,
            force_download=True,
        )
        report = verify_downloaded_remote_tree(local, expected)

    report.update({
        "status": "PASS",
        "repo": args.repo,
        "repo_type": "dataset",
        "remote_prefix": prefix,
        "shard": args.shard,
        "upload_status": upload.get("status"),
        "full_remote_download_verified": True,
    })
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
