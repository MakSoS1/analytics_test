#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from huggingface_hub import HfApi, create_repo

DEFAULT_REPO = "Maksim123321/remote-admin-anomaly-v1"
REQUIRED_LAYERS = ("bronze", "silver", "gold", "quality")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


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


def stage_quality_for_hf(source: Path, target: Path) -> list[dict]:
    """Create a recoverable HF transport copy without mutating the release.

    `pktmon format` writes UTF-16 text. Hugging Face's commit endpoint can reject
    such bytes under a `.txt` filename as binary regular-Git content. We retain
    the exact original in the authoritative retained artifact and losslessly gzip
    only the HF transport copy. The transform manifest records hashes and sizes
    so the original bytes can be reconstructed and verified exactly.
    """
    shutil.copytree(source, target)
    transforms: list[dict] = []
    raw = target / "external" / "windows" / "capture.txt"
    if raw.is_file() and raw.stat().st_size > 0:
        original_bytes = raw.stat().st_size
        original_sha = sha256_file(raw)
        compressed = raw.with_name(raw.name + ".gz")
        with raw.open("rb") as src, compressed.open("wb") as dst:
            with gzip.GzipFile(filename="capture.txt", mode="wb", fileobj=dst, mtime=0) as gz:
                shutil.copyfileobj(src, gz, length=1024 * 1024)
        compressed_sha = sha256_file(compressed)
        compressed_bytes = compressed.stat().st_size
        raw.unlink()
        transforms.append(
            {
                "original_path": "external/windows/capture.txt",
                "stored_path": "external/windows/capture.txt.gz",
                "transform": "gzip_lossless_mtime0",
                "original_sha256": original_sha,
                "original_bytes": original_bytes,
                "stored_sha256": compressed_sha,
                "stored_bytes": compressed_bytes,
                "restore": "gzip -dc capture.txt.gz > capture.txt",
            }
        )
    manifest = {
        "schema_version": 1,
        "purpose": "lossless transport transforms applied only to the Hugging Face persistence copy",
        "release_mutated": False,
        "transforms": transforms,
    }
    (target / "HF_PERSISTENCE_TRANSFORMS.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return transforms


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
    transforms: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="remote-admin-v2-hf-") as tmp:
        tmp_root = Path(tmp)
        for layer in REQUIRED_LAYERS:
            source = release / layer / args.shard
            local = source
            if layer == "quality":
                local = tmp_root / "quality" / args.shard
                local.parent.mkdir(parents=True, exist_ok=True)
                transforms = stage_quality_for_hf(source, local)
            remote = f"{args.remote_path.strip('/')}/{layer}/{args.shard}"
            api.upload_folder(
                repo_id=args.repo,
                repo_type="dataset",
                folder_path=str(local),
                path_in_repo=remote,
                token=token,
                commit_message=f"Remote Admin dataset {args.shard} {layer}",
            )
            uploaded[layer] = remote

    payload = {
        **base,
        "status": "uploaded",
        "reason": "complete recoverable shard uploaded; transport-only transforms are lossless and documented",
        "layer_bytes_original_release": sizes,
        "uploaded_paths": uploaded,
        "transport_transforms": transforms,
    }
    write_status(args.status, payload)
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
