#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path

import zstandard as zstd
from huggingface_hub import HfApi, snapshot_download

from coverlab.capture_tail_guard import check as check_capture_tail
from coverlab.validate_dataset_contract import validate


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_legacy_checksums(source: Path, bronze: Path, checksum_map: dict[str, str], raw_pcap: Path) -> dict:
    """Verify every retained old-release file for which a source hash exists.

    Legacy checksums were calculated before packaging. Persona scratch files are
    intentionally not retained in releases, but aggregate manifests, raw PCAP
    and parser outputs are retained under Bronze/Silver and can be verified
    against their original hashes.
    """
    mapping: dict[str, Path] = {
        "campaigns.jsonl": bronze / "manifests" / "campaigns.jsonl",
        "events.jsonl": bronze / "manifests" / "events.jsonl",
        "manifests/campaigns.jsonl": bronze / "manifests" / "campaigns.jsonl",
        "manifests/events.jsonl": bronze / "manifests" / "events.jsonl",
        "manifests/decrypted_transactions.jsonl": bronze / "manifests" / "decrypted_transactions.jsonl",
        "capture.pcap": raw_pcap,
    }
    for key in checksum_map:
        if key.startswith("parser/suricata/"):
            mapping[key] = source / "silver" / source.name / "suricata-raw" / Path(key).name
        elif key.startswith("parser/zeek/"):
            mapping[key] = source / "silver" / source.name / "zeek-raw" / Path(key).name

    verified: dict[str, str] = {}
    missing: list[str] = []
    mismatches: list[dict] = []
    for key, actual_path in mapping.items():
        expected = checksum_map.get(key)
        if not expected:
            continue
        if not actual_path.exists():
            missing.append(key)
            continue
        actual = _sha256(actual_path)
        verified[key] = actual
        if actual != expected:
            mismatches.append({"key": key, "expected": expected, "actual": actual})

    required = {
        "manifests/campaigns.jsonl",
        "manifests/events.jsonl",
        "manifests/decrypted_transactions.jsonl",
        "capture.pcap",
    }
    required_missing = sorted(k for k in required if k not in verified)
    return {
        "passed": not mismatches and not required_missing,
        "verified_count": len(verified),
        "verified_keys": sorted(verified),
        "missing_retained_files": sorted(missing),
        "required_unverified": required_missing,
        "mismatches": mismatches,
        "legacy_unretained_entries": sorted(
            k for k in checksum_map if k.startswith("persona-")
        ),
    }


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

    # Stage G from pre-contract-revision-2 releases is intentionally invalidated.
    if args.shard.startswith("trusted-bg-") and not args.allow_legacy_trusted_bg:
        print(json.dumps({"reused": False, "reason": "trusted_background_policy_changed", "shard": args.shard}))
        raise SystemExit(3)

    cache = Path(args.cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    pattern = f"releases/{args.source_release}/{args.shard}/**"
    try:
        root = Path(snapshot_download(
            repo_id=args.repo,
            repo_type="dataset",
            token=token,
            allow_patterns=[pattern],
            local_dir=cache,
        ))
    except Exception as exc:
        print(json.dumps({"reused": False, "reason": "download_failed", "error": str(exc), "shard": args.shard}))
        raise SystemExit(3)

    source = root / "releases" / args.source_release / args.shard
    quality = source / "quality" / args.shard / "capture_health.json"
    checksums = source / "quality" / args.shard / "checksums.json"
    bronze = source / "bronze" / args.shard
    pcap_files = list((bronze / "captures").glob("*.pcap.zst")) if bronze.exists() else []

    if not source.exists() or not quality.exists() or not checksums.exists() or len(pcap_files) != 1:
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
    if not checksum_map or pcap_files[0].stat().st_size <= 32:
        print(json.dumps({"reused": False, "reason": "empty_checksum_or_pcap", "shard": args.shard}))
        raise SystemExit(3)

    contract = validate(bronze)
    if not contract["passed"]:
        print(json.dumps({"reused": False, "reason": "contract_failed", "contract": contract, "shard": args.shard}))
        raise SystemExit(3)

    # Reconstruct the original raw PCAP so legacy raw-PCAP SHA256 and the new
    # tail-completeness contract can be verified before reuse.
    raw_pcap = cache / f"{args.shard}.reuse-validation.pcap"
    dctx = zstd.ZstdDecompressor()
    try:
        with pcap_files[0].open("rb") as src, raw_pcap.open("wb") as dst:
            dctx.copy_stream(src, dst)
        checksum_report = _verify_legacy_checksums(source, bronze, checksum_map, raw_pcap)
        tail_report = check_capture_tail(bronze, raw_pcap)
    except Exception as exc:
        print(json.dumps({"reused": False, "reason": "reuse_validation_failed", "error": str(exc), "shard": args.shard}))
        raise SystemExit(3)
    finally:
        # Keep cache pressure bounded for 30 large mixed captures.
        raw_pcap.unlink(missing_ok=True)

    if not checksum_report["passed"]:
        print(json.dumps({"reused": False, "reason": "checksum_verification_failed", "report": checksum_report, "shard": args.shard}))
        raise SystemExit(3)
    if not tail_report["passed"]:
        print(json.dumps({"reused": False, "reason": "capture_tail_guard_failed", "report": tail_report, "shard": args.shard}))
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
        "checksum_verification": checksum_report,
        "capture_tail_guard": tail_report,
        "reuse_policy_revision": 3,
    }
    qdir = dest / "quality" / args.shard
    qdir.mkdir(parents=True, exist_ok=True)
    (qdir / "reuse_provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "reused": True,
        "shard": args.shard,
        "source_release": args.source_release,
        "verified_checksums": checksum_report["verified_count"],
        "capture_tail_passed": True,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
