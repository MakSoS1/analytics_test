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


def _validate_v3_bronze(bronze: Path) -> None:
    giant = list((bronze / "captures").rglob("*.pcap*")) if (bronze / "captures").exists() else []
    if giant:
        raise ValueError("V3 Bronze must not persist merged/full capture files")
    compressed = list(bronze.rglob("*.pcap.zst"))
    if compressed:
        raise ValueError(f"corrected V3 Bronze must contain raw .pcap only; compressed PCAPs present: {len(compressed)}")
    required_dirs = {
        "sessions": list((bronze / "sessions").rglob("*.pcap")),
        "campaigns": list((bronze / "campaigns").rglob("*.pcap")),
        "raw_chunks": list((bronze / "raw_chunks").glob("*.pcap")),
    }
    empty = [name for name, rows in required_dirs.items() if not rows]
    if empty:
        raise ValueError(f"V3 Bronze missing authoritative raw PCAP groups: {empty}")
    for name in ("pcap_index.csv", "pcap_index.parquet"):
        path = bronze / "manifests" / name
        if not path.is_file() or path.stat().st_size <= 0:
            raise ValueError(f"V3 Bronze missing non-empty manifests/{name}")


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

    bronze = release / "bronze" / shard
    if str(shard).upper().startswith("V3-"):
        _validate_v3_bronze(bronze)
    else:
        bronze_pcaps = list((bronze / "captures").glob("*.pcap.zst"))
        if len(bronze_pcaps) != 1 or bronze_pcaps[0].stat().st_size <= 0:
            raise ValueError("Legacy Bronze must contain exactly one non-empty full .pcap.zst capture")
    return sizes


def write_status(path: Path | None, payload: dict) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _is_binary_like_text(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size <= 0:
        return False
    with path.open("rb") as fh:
        sample = fh.read(1024 * 1024)
    if b"\x00" in sample:
        return True
    try:
        sample.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return True
    return False


def _binary_windows_texts(source: Path) -> list[Path]:
    windows = source / "external" / "windows"
    if not windows.is_dir():
        return []
    return sorted((path for path in windows.rglob("*.txt") if _is_binary_like_text(path)), key=lambda path: path.as_posix())


def _quality_transport_ignore(source: Path, binary_texts: list[Path]):
    ignored = {path.resolve() for path in binary_texts}
    def ignore(directory: str, names: list[str]) -> list[str]:
        current = Path(directory).resolve()
        return sorted(name for name in names if (current / name).resolve() in ignored)
    return ignore


def stage_quality_for_hf(source: Path, target: Path) -> list[dict]:
    binary_texts = _binary_windows_texts(source)
    shutil.copytree(source, target, ignore=_quality_transport_ignore(source, binary_texts))
    transforms: list[dict] = []
    for raw_source in binary_texts:
        relative = raw_source.relative_to(source)
        original_bytes = raw_source.stat().st_size
        original_sha = sha256_file(raw_source)
        compressed = target / Path(str(relative) + ".gz")
        compressed.parent.mkdir(parents=True, exist_ok=True)
        with raw_source.open("rb") as src, compressed.open("wb") as dst:
            with gzip.GzipFile(filename=raw_source.name, mode="wb", fileobj=dst, mtime=0) as gz:
                shutil.copyfileobj(src, gz, length=1024 * 1024)
        transforms.append({
            "original_path": relative.as_posix(),
            "stored_path": Path(str(relative) + ".gz").as_posix(),
            "transform": "gzip_lossless_mtime0",
            "original_sha256": original_sha,
            "original_bytes": original_bytes,
            "stored_sha256": sha256_file(compressed),
            "stored_bytes": compressed.stat().st_size,
            "restore": f"gzip -dc {raw_source.name}.gz > {raw_source.name}",
        })
    manifest = {
        "schema_version": 1,
        "purpose": "lossless transport transforms applied only to the Hugging Face persistence copy",
        "release_mutated": False,
        "transforms": transforms,
    }
    (target / "HF_PERSISTENCE_TRANSFORMS.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
    base = {
        "repo": args.repo,
        "repo_type": "dataset",
        "private": True,
        "shard": args.shard,
        "remote_path": args.remote_path.strip("/"),
        "token_present": bool(token),
    }
    if not token:
        payload = {**base, "status": "skipped", "reason": "HF_TOKEN missing"}
        write_status(args.status, payload)
        print(json.dumps(payload, sort_keys=True))
        return 0

    release = args.release.resolve()
    sizes = validate_release_shard(release, args.shard)
    create_repo(repo_id=args.repo, repo_type="dataset", private=True, exist_ok=True, token=token)
    api = HfApi(token=token)

    uploaded: dict[str, str] = {}
    transforms: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="remote-admin-hf-") as tmp:
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
        "reason": "complete recoverable shard uploaded; V3 PCAPs are raw .pcap and quality-only transport transforms are lossless",
        "pcap_storage": "raw_uncompressed",
        "layer_bytes_original_release": sizes,
        "uploaded_paths": uploaded,
        "transport_transforms": transforms,
    }
    write_status(args.status, payload)
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
