from __future__ import annotations

"""Repair Stage M network-profile provenance without regenerating wire traffic.

The source PCAP/parser bytes are copied unchanged. Only metadata fields that were
lost across the sudo/ip-netns environment boundary are corrected.
"""

import argparse
import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd

PROFILES = ("clean", "wan_20ms", "wan_80ms", "lossy_wifi", "constrained")
FIELDS = ("netem_profile", "network_profile_id", "leave_one_network_group")
CORRECTION_ID = "stage_m_network_profile_provenance_v1"


def profile_for_shard(shard: int) -> str:
    if shard < 0:
        raise ValueError("shard must be non-negative")
    return PROFILES[shard % len(PROFILES)]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _patch_obj(obj: Any, profile: str) -> tuple[Any, int]:
    changed = 0
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in FIELDS:
                if v != profile:
                    changed += 1
                out[k] = profile
            else:
                out[k], n = _patch_obj(v, profile)
                changed += n
        return out, changed
    if isinstance(obj, list):
        out = []
        for v in obj:
            nv, n = _patch_obj(v, profile)
            out.append(nv)
            changed += n
        return out, changed
    return obj, 0


def _patch_json(path: Path, profile: str) -> int:
    try:
        obj = json.loads(path.read_text())
    except Exception:
        return 0
    patched, changed = _patch_obj(obj, profile)
    if changed:
        path.write_text(json.dumps(patched, indent=2, sort_keys=True) + "\n")
    return changed


def _patch_jsonl(path: Path, profile: str, source_run_id: int, shard: int) -> tuple[int, int]:
    rows = []
    changed = 0
    count = 0
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        patched, n = _patch_obj(row, profile)
        if path.name == "campaigns.jsonl":
            patched["netem_profile"] = profile
            patched["network_profile_id"] = profile
            patched["leave_one_network_group"] = profile
            patched["metadata_revision"] = 2
            patched["network_profile_provenance"] = "recovered_from_workflow_matrix"
            patched["network_profile_source_run_id"] = int(source_run_id)
            patched["network_profile_source_shard"] = int(shard)
            patched["network_profile_correction_id"] = CORRECTION_ID
        rows.append(json.dumps(patched, separators=(",", ":"), default=str))
        changed += n
        count += 1
    path.write_text("\n".join(rows) + ("\n" if rows else ""))
    return count, changed


def _patch_parquet(path: Path, profile: str) -> int:
    try:
        df = pd.read_parquet(path)
    except Exception:
        return 0
    touched = 0
    for field in FIELDS:
        if field in df.columns:
            touched += int((df[field].astype(str) != profile).sum())
            df[field] = profile
    if touched:
        df.to_parquet(path, index=False)
    return touched


def repair_release(source: Path, output: Path, shard: int, source_run_id: int) -> dict[str, Any]:
    name = f"M-positive-{shard:02d}"
    profile = profile_for_shard(shard)
    bronze = source / "bronze" / name
    if not bronze.exists():
        raise FileNotFoundError(f"missing source bronze shard: {bronze}")
    captures = sorted((bronze / "captures").glob("*.pcap.zst"))
    if len(captures) != 1:
        raise RuntimeError(f"expected exactly one compressed PCAP for {name}, got {len(captures)}")

    if output.exists():
        shutil.rmtree(output)
    shutil.copytree(source, output)

    src_pcap = captures[0]
    dst_pcap = output / src_pcap.relative_to(source)
    before = sha256(src_pcap)
    after_copy = sha256(dst_pcap)
    if before != after_copy:
        raise RuntimeError("PCAP changed during artifact copy")

    json_changes = 0
    jsonl_rows = 0
    parquet_changes = 0
    for path in output.rglob("*.jsonl"):
        rows, changed = _patch_jsonl(path, profile, source_run_id, shard)
        jsonl_rows += rows
        json_changes += changed
    for path in output.rglob("*.json"):
        json_changes += _patch_json(path, profile)
    for path in output.rglob("*.parquet"):
        parquet_changes += _patch_parquet(path, profile)

    campaign_path = output / "bronze" / name / "manifests" / "campaigns.jsonl"
    campaigns = [json.loads(x) for x in campaign_path.read_text().splitlines() if x.strip()]
    if not campaigns:
        raise RuntimeError(f"empty campaigns manifest for {name}")
    for row in campaigns:
        for field in FIELDS:
            if row.get(field) != profile:
                raise RuntimeError(f"{row.get('campaign_id')}: {field} was not corrected")
        if row.get("network_profile_correction_id") != CORRECTION_ID:
            raise RuntimeError(f"{row.get('campaign_id')}: correction marker missing")

    # Keep the root inventory consistent with the corrected manifest.
    inv = output / "stage_m_inventory.json"
    if inv.exists():
        obj = json.loads(inv.read_text())
        obj["netem"] = {profile: len(campaigns)}
        obj["network_profile_correction_id"] = CORRECTION_ID
        obj["source_generation_run_id"] = int(source_run_id)
        obj["source_generation_shard"] = int(shard)
        inv.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")

    repro = output / "bronze" / name / "reproducibility.json"
    if repro.exists():
        obj = json.loads(repro.read_text())
        obj.update({
            "network_profile_correction_id": CORRECTION_ID,
            "network_profile": profile,
            "source_generation_run_id": int(source_run_id),
            "source_generation_shard": int(shard),
            "source_pcap_zst_sha256": before,
            "wire_bytes_regenerated": False,
        })
        repro.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")

    evidence = {
        "passed": True,
        "correction_id": CORRECTION_ID,
        "source_generation_run_id": int(source_run_id),
        "source_generation_shard": int(shard),
        "shard_name": name,
        "network_profile": profile,
        "campaigns": len(campaigns),
        "profile_counts": dict(Counter(r["network_profile_id"] for r in campaigns)),
        "source_pcap_zst_sha256": before,
        "corrected_pcap_zst_sha256": sha256(dst_pcap),
        "pcap_bytes_unchanged": before == sha256(dst_pcap),
        "wire_bytes_regenerated": False,
        "json_metadata_values_changed": json_changes,
        "parquet_metadata_values_changed": parquet_changes,
        "jsonl_rows_scanned": jsonl_rows,
    }
    qdir = output / "quality" / name
    qdir.mkdir(parents=True, exist_ok=True)
    (qdir / "network_profile_correction.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    return evidence


def verify_release(path: Path, shard: int, source_run_id: int) -> dict[str, Any]:
    name = f"M-positive-{shard:02d}"
    profile = profile_for_shard(shard)
    campaign_path = path / "bronze" / name / "manifests" / "campaigns.jsonl"
    rows = [json.loads(x) for x in campaign_path.read_text().splitlines() if x.strip()]
    errors: list[str] = []
    for row in rows:
        for field in FIELDS:
            if row.get(field) != profile:
                errors.append(f"{row.get('campaign_id')}: {field}={row.get(field)!r}, expected {profile!r}")
        if int(row.get("network_profile_source_run_id", -1)) != int(source_run_id):
            errors.append(f"{row.get('campaign_id')}: wrong source run")
        if int(row.get("network_profile_source_shard", -1)) != int(shard):
            errors.append(f"{row.get('campaign_id')}: wrong source shard")
    evidence_path = path / "quality" / name / "network_profile_correction.json"
    evidence = json.loads(evidence_path.read_text()) if evidence_path.exists() else {}
    if evidence.get("pcap_bytes_unchanged") is not True:
        errors.append("PCAP byte-preservation evidence missing")
    return {
        "passed": not errors,
        "shard": shard,
        "profile": profile,
        "campaigns": len(rows),
        "errors": errors[:100],
        "pcap_bytes_unchanged": evidence.get("pcap_bytes_unchanged") is True,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("repair")
    r.add_argument("--source", required=True)
    r.add_argument("--output", required=True)
    r.add_argument("--shard", type=int, required=True)
    r.add_argument("--source-run-id", type=int, required=True)
    v = sub.add_parser("verify")
    v.add_argument("--release", required=True)
    v.add_argument("--shard", type=int, required=True)
    v.add_argument("--source-run-id", type=int, required=True)
    a = ap.parse_args()
    if a.cmd == "repair":
        result = repair_release(Path(a.source), Path(a.output), a.shard, a.source_run_id)
    else:
        result = verify_release(Path(a.release), a.shard, a.source_run_id)
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result.get("passed", False):
        raise SystemExit("Stage M network-profile metadata repair verification failed")


if __name__ == "__main__":
    main()
