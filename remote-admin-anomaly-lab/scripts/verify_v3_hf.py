#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Callable

# The V3 verifier optimizes for deterministic verification rather than maximum
# transfer throughput. Xet token fan-out can itself be rate-limited on repos
# containing >1k small files, so use the regular resolver path for this job.
os.environ.setdefault("HF_HUB_DISABLE_XET", "1")

from huggingface_hub import snapshot_download

from adminlab.v3_persistence import expected_remote_paths
from adminlab.v3_remote_verify import verify_downloaded_remote_tree


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _is_rate_limit_error(exc: BaseException) -> bool:
    text = str(exc).lower()
    return "429" in text or "too many requests" in text or "rate limit" in text


def download_snapshot_with_retries(
    *,
    snapshot_fn: Callable[..., str],
    repo_id: str,
    token: str,
    prefix: str,
    local_dir: Path,
    attempts: int = 3,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> str:
    """Download the V3 prefix conservatively and resume partial local state.

    Only explicit rate-limit failures are retried. All other errors are surfaced
    immediately so repository/auth/data faults can never be hidden by retries.
    """
    if attempts < 1:
        raise ValueError("attempts must be >= 1")
    delays = (10, 30, 60, 120)
    last_error: BaseException | None = None
    for attempt in range(attempts):
        try:
            return snapshot_fn(
                repo_id=repo_id,
                repo_type="dataset",
                token=token,
                allow_patterns=[f"{prefix.strip('/')}/**"],
                local_dir=local_dir,
                force_download=False,
                max_workers=2,
            )
        except BaseException as exc:
            if not _is_rate_limit_error(exc):
                raise
            last_error = exc
            if attempt + 1 >= attempts:
                break
            sleep_fn(delays[min(attempt, len(delays) - 1)])
    assert last_error is not None
    raise last_error


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
        download_snapshot_with_retries(
            snapshot_fn=snapshot_download,
            repo_id=args.repo,
            token=token,
            prefix=prefix,
            local_dir=local,
            attempts=3,
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
        "download_policy": {
            "hf_hub_disable_xet": os.environ.get("HF_HUB_DISABLE_XET", ""),
            "max_workers": 2,
            "rate_limit_attempts": 3,
            "force_download": False,
        },
    })
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
