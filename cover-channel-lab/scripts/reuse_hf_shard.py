#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
from datetime import datetime, timezone
from pathlib import Path

import zstandard as zstd
from huggingface_hub import HfApi, snapshot_download


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(errors="replace").splitlines() if line.strip()]


def _validate_contract(bronze: Path) -> dict:
    campaigns = _read_jsonl(bronze / "manifests" / "campaigns.jsonl")
    events = _read_jsonl(bronze / "manifests" / "events.jsonl")
    errors: list[str] = []
    by_id: dict[str, dict] = {}
    for row in campaigns:
        cid = str(row.get("campaign_id") or "")
        if not cid or cid in by_id:
            errors.append(f"invalid/duplicate campaign_id: {cid!r}")
            continue
        by_id[cid] = row
        stage = str(row.get("experiment_stage") or "")
        role = str(row.get("dataset_role") or "")
        label = int(row.get("label_binary") or 0)
        intent = str(row.get("label_intent") or "")
        mapping = row.get("attack_mapping") or []
        if cid.startswith("g-") or stage == "G_trusted_background" or role == "hard_negative":
            if label != 0 or intent not in {"", "benign"} or mapping:
                errors.append(f"{cid}: trusted background is not benign/no-mapping")
            if stage != "G_trusted_background" or role != "hard_negative":
                errors.append(f"{cid}: trusted background stage/role mismatch")
        if stage == "D_mixed" and label == 1 and str(row.get("scenario_id") or "").startswith("CC_LOTS_"):
            errors.append(f"{cid}: positive mixed sample uses LOTS scenario")
    for event in events:
        cid = str(event.get("campaign_id") or "")
        campaign = by_id.get(cid)
        if campaign is None:
            errors.append(f"event references unknown campaign_id: {cid}")
        elif "label_binary" in event and int(event.get("label_binary") or 0) != int(campaign.get("label_binary") or 0):
            errors.append(f"{cid}: event/campaign label mismatch")
    return {
        "passed": bool(campaigns) and not errors,
        "campaigns": len(campaigns),
        "events": len(events),
        "error_count": len(errors),
        "errors": errors[:200],
        "contract_revision": 2,
    }


def _parse_iso(value: str) -> float:
    text = str(value or "").strip()
    if not text:
        return 0.0
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _last_pcap_timestamp(path: Path) -> tuple[float, int]:
    with path.open("rb") as fh:
        header = fh.read(24)
        if len(header) != 24:
            raise RuntimeError("PCAP global header is truncated")
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
            b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
            b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
            b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
        }
        if header[:4] not in formats:
            raise RuntimeError(f"unsupported capture magic {header[:4].hex()}")
        endian, divisor = formats[header[:4]]
        ph = struct.Struct(endian + "IIII")
        last_ts = 0.0
        count = 0
        while True:
            raw = fh.read(ph.size)
            if not raw:
                break
            if len(raw) != ph.size:
                raise RuntimeError("truncated PCAP packet header")
            sec, frac, incl_len, _ = ph.unpack(raw)
            if incl_len > 64 * 1024 * 1024:
                raise RuntimeError(f"unreasonable PCAP incl_len={incl_len}")
            fh.seek(incl_len, 1)
            last_ts = sec + frac / divisor
            count += 1
        return last_ts, count


def _check_capture_tail(bronze: Path, raw_pcap: Path, tolerance: float = 0.05) -> dict:
    rows = _read_jsonl(bronze / "manifests" / "campaigns.jsonl")
    successful = [r for r in rows if str(r.get("status", "success")) == "success"]
    latest_start = max((_parse_iso(r.get("started_at", "")) for r in successful), default=0.0)
    latest_end = max((_parse_iso(r.get("ended_at", "")) for r in successful), default=0.0)
    last_ts, packet_count = _last_pcap_timestamp(raw_pcap)
    passed = bool(successful) and packet_count > 0 and last_ts + tolerance >= latest_start
    return {
        "passed": passed,
        "packet_count": packet_count,
        "last_pcap_timestamp": last_ts,
        "latest_campaign_started_at": latest_start,
        "latest_campaign_ended_at": latest_end,
        "lag_from_latest_campaign_start_seconds": round(latest_start - last_ts, 6),
        "end_minus_last_packet_seconds": round(latest_end - last_ts, 6),
        "tolerance_seconds": tolerance,
        "guard_revision": 1,
    }


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_legacy_checksums(source: Path, bronze: Path, checksum_map: dict[str, str], raw_pcap: Path) -> dict:
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
        "legacy_unretained_entries": sorted(k for k in checksum_map if k.startswith("persona-")),
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
    if args.shard.startswith("trusted-bg-") and not args.allow_legacy_trusted_bg:
        print(json.dumps({"reused": False, "reason": "trusted_background_policy_changed", "shard": args.shard}))
        raise SystemExit(3)

    cache = Path(args.cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    pattern = f"releases/{args.source_release}/{args.shard}/**"
    try:
        root = Path(snapshot_download(
            repo_id=args.repo, repo_type="dataset", token=token,
            allow_patterns=[pattern], local_dir=cache,
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

    contract = _validate_contract(bronze)
    if not contract["passed"]:
        print(json.dumps({"reused": False, "reason": "contract_failed", "contract": contract, "shard": args.shard}))
        raise SystemExit(3)

    raw_pcap = cache / f"{args.shard}.reuse-validation.pcap"
    try:
        with pcap_files[0].open("rb") as src, raw_pcap.open("wb") as dst:
            zstd.ZstdDecompressor().copy_stream(src, dst)
        checksum_report = _verify_legacy_checksums(source, bronze, checksum_map, raw_pcap)
        tail_report = _check_capture_tail(bronze, raw_pcap)
    except Exception as exc:
        print(json.dumps({"reused": False, "reason": "reuse_validation_failed", "error": str(exc), "shard": args.shard}))
        raise SystemExit(3)
    finally:
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
        "reused": True, "shard": args.shard, "source_release": args.source_release,
        "verified_checksums": checksum_report["verified_count"], "capture_tail_passed": True,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
