from __future__ import annotations

"""Register wire-real external evidence for CoverLab.

This module does not launch C2 software. It records PCAPs captured in an
authorized isolated lab and turns them into strict, challenge-only evidence
consumable by the existing validators/evaluation pipeline.
"""

import argparse
import hashlib
import json
import shutil
from pathlib import Path

from .research_contract_v3 import (
    CLIENT_STACKS,
    ECH_MODES,
    FRAMEWORKS,
    NETWORK_EVIDENCE_TYPES,
    SERVER_STACKS,
    framework_record,
    validate_ech_record,
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy_pcap(source: Path, root: Path, category: str, capture_id: str) -> tuple[Path, str]:
    if not source.is_file() or source.stat().st_size <= 24:
        raise ValueError(f"PCAP is missing or too small: {source}")
    dst_dir = root / category / "pcaps"
    dst_dir.mkdir(parents=True, exist_ok=True)
    suffix = source.suffix if source.suffix else ".pcap"
    safe_id = "".join(c if c.isalnum() or c in "._-" else "_" for c in capture_id)
    dst = dst_dir / f"{safe_id}{suffix}"
    shutil.copy2(source, dst)
    return dst, sha256(dst)


def _upsert_jsonl(path: Path, key: str, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    if path.exists():
        rows = [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
    value = str(record[key])
    rows = [r for r in rows if str(r.get(key, "")) != value]
    rows.append(record)
    path.write_text("\n".join(json.dumps(r, sort_keys=True, separators=(",", ":")) for r in rows) + "\n")


def register_framework(
    root: Path,
    pcap: Path,
    *,
    framework: str,
    campaign_id: str,
    protocol: str,
    lifecycle: list[str],
    tool_version: str,
    adapter_version: str,
    model_score: float | None = None,
    decision_threshold: float = 0.5,
) -> dict:
    framework = framework.lower()
    if framework not in FRAMEWORKS:
        raise ValueError(f"framework must be one of {FRAMEWORKS}")
    rec = framework_record(
        framework,
        campaign_id,
        protocol=protocol,
        pcap_sha256="0" * 64,
        lifecycle=lifecycle,
        isolated=True,
    )
    dst, digest = _copy_pcap(pcap, root, "framework", campaign_id)
    rec.update(
        {
            "pcap_file": str(dst.relative_to(root / "framework")),
            "pcap_sha256": digest,
            "wire_real": True,
            "tool_version": tool_version,
            "adapter_version": adapter_version,
            "capture_provenance": "authorized_isolated_lab",
            "label_binary": 1,
            "label_family": "web_c2_mimicry",
            "label_intent": "c2",
            "decision_threshold": float(decision_threshold),
        }
    )
    if model_score is not None:
        rec["model_score"] = float(model_score)
    _upsert_jsonl(root / "framework" / "framework_holdout.jsonl", "campaign_id", rec)
    return rec


def register_ech(
    root: Path,
    pcap: Path,
    *,
    capture_id: str,
    ech_mode: str,
    pair_id: str,
    label_binary: int,
    protocol: str,
    model_score: float | None,
    decision_threshold: float,
) -> dict:
    if ech_mode not in ECH_MODES:
        raise ValueError(f"ech_mode must be one of {ECH_MODES}")
    if label_binary not in (0, 1):
        raise ValueError("label_binary must be 0 or 1")
    dst, digest = _copy_pcap(pcap, root, "ech", capture_id)
    rec = {
        "capture_id": capture_id,
        "ech_mode": ech_mode,
        "pair_id": pair_id,
        "label_binary": label_binary,
        "protocol": protocol,
        "wire_real": True,
        "isolated_lab": True,
        "pcap_file": str(dst.relative_to(root / "ech")),
        "pcap_sha256": digest,
        "dataset_role": "external_ech_holdout",
        "training_eligible": False,
        "decision_threshold": float(decision_threshold),
    }
    if model_score is not None:
        rec["model_score"] = float(model_score)
    errors = validate_ech_record(rec)
    if errors:
        raise ValueError("; ".join(errors))
    _upsert_jsonl(root / "ech" / "ech_holdout.jsonl", "capture_id", rec)
    return rec


def register_environment(
    root: Path,
    pcap: Path,
    *,
    capture_id: str,
    session_count: int,
    client_stack: str = "",
    server_stack: str = "",
    network_evidence: str = "",
) -> dict:
    if session_count <= 0:
        raise ValueError("session_count must be positive")
    if client_stack and client_stack not in CLIENT_STACKS:
        raise ValueError(f"unknown client stack: {client_stack}")
    if server_stack and server_stack not in SERVER_STACKS:
        raise ValueError(f"unknown server stack: {server_stack}")
    if network_evidence and network_evidence not in NETWORK_EVIDENCE_TYPES:
        raise ValueError(f"unknown network evidence: {network_evidence}")
    if not any((client_stack, server_stack, network_evidence)):
        raise ValueError("at least one environment dimension is required")
    dst, digest = _copy_pcap(pcap, root, "environment", capture_id)
    rec = {
        "capture_id": capture_id,
        "session_count": int(session_count),
        "client_stack": client_stack,
        "server_stack": server_stack,
        "network_evidence": network_evidence,
        "wire_real": True,
        "isolated_lab": True,
        "pcap_file": str(dst.relative_to(root / "environment")),
        "pcap_sha256": digest,
        "dataset_role": "environment_external_holdout",
        "training_eligible": False,
    }
    _upsert_jsonl(root / "environment" / "environment_evidence.jsonl", "capture_id", rec)
    return rec


def register_long_timing(
    root: Path,
    pcap: Path,
    *,
    campaign_id: str,
    interval_seconds: int,
    event_count: int,
    label_binary: int,
) -> dict:
    if interval_seconds not in (1200, 3600):
        raise ValueError("external long timing interval must be 1200 or 3600 seconds")
    required = {1200: 5, 3600: 4}[interval_seconds]
    if event_count < required:
        raise ValueError(f"{interval_seconds}s evidence requires at least {required} events")
    if label_binary not in (0, 1):
        raise ValueError("label_binary must be 0 or 1")
    dst, digest = _copy_pcap(pcap, root, "long-timing", campaign_id)
    rec = {
        "campaign_id": campaign_id,
        "real_interval_seconds": int(interval_seconds),
        "event_count": int(event_count),
        "event_count_target": int(event_count),
        "timing_acceleration": 1,
        "label_binary": int(label_binary),
        "wire_real": True,
        "isolated_lab": True,
        "pcap_file": str(dst.relative_to(root / "long-timing")),
        "pcap_sha256": digest,
        "dataset_role": "external_long_timing_challenge",
        "training_eligible": False,
    }
    _upsert_jsonl(root / "long-timing" / "long_timing_evidence.jsonl", "campaign_id", rec)
    return rec


def register_office(
    root: Path,
    pcap: Path,
    *,
    capture_id: str,
    duration_seconds: float,
    session_count: int,
    privacy_scrubbed: bool,
) -> dict:
    if not privacy_scrubbed:
        raise ValueError("office evidence must be privacy-scrubbed before registration")
    if duration_seconds <= 0 or session_count <= 0:
        raise ValueError("duration_seconds and session_count must be positive")
    dst, digest = _copy_pcap(pcap, root, "office", capture_id)
    rec = {
        "capture_id": capture_id,
        "duration_seconds": float(duration_seconds),
        "session_count": int(session_count),
        "benign_verified": True,
        "privacy_scrubbed": True,
        "pcap_file": str(dst.relative_to(root / "office")),
        "pcap_sha256": digest,
        "dataset_role": "office_external_holdout",
        "training_eligible": False,
    }
    _upsert_jsonl(root / "office" / "office_background.jsonl", "capture_id", rec)
    return rec


def _csv(value: str) -> list[str]:
    return [x.strip() for x in value.split(",") if x.strip()]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="external-evidence")
    sub = ap.add_subparsers(dest="kind", required=True)

    fw = sub.add_parser("framework")
    fw.add_argument("--pcap", required=True)
    fw.add_argument("--framework", required=True, choices=FRAMEWORKS)
    fw.add_argument("--campaign-id", required=True)
    fw.add_argument("--protocol", required=True)
    fw.add_argument("--lifecycle", required=True)
    fw.add_argument("--tool-version", required=True)
    fw.add_argument("--adapter-version", default="coverlab-v4")
    fw.add_argument("--model-score", type=float)
    fw.add_argument("--decision-threshold", type=float, default=0.5)

    ech = sub.add_parser("ech")
    ech.add_argument("--pcap", required=True)
    ech.add_argument("--capture-id", required=True)
    ech.add_argument("--ech-mode", required=True, choices=ECH_MODES)
    ech.add_argument("--pair-id", required=True)
    ech.add_argument("--label-binary", required=True, type=int, choices=(0, 1))
    ech.add_argument("--protocol", required=True, choices=("h2", "h3", "https"))
    ech.add_argument("--model-score", type=float)
    ech.add_argument("--decision-threshold", type=float, default=0.5)

    env = sub.add_parser("environment")
    env.add_argument("--pcap", required=True)
    env.add_argument("--capture-id", required=True)
    env.add_argument("--session-count", required=True, type=int)
    env.add_argument("--client-stack", default="")
    env.add_argument("--server-stack", default="")
    env.add_argument("--network-evidence", default="")

    lt = sub.add_parser("long-timing")
    lt.add_argument("--pcap", required=True)
    lt.add_argument("--campaign-id", required=True)
    lt.add_argument("--interval-seconds", required=True, type=int, choices=(1200, 3600))
    lt.add_argument("--event-count", required=True, type=int)
    lt.add_argument("--label-binary", required=True, type=int, choices=(0, 1))

    office = sub.add_parser("office")
    office.add_argument("--pcap", required=True)
    office.add_argument("--capture-id", required=True)
    office.add_argument("--duration-seconds", required=True, type=float)
    office.add_argument("--session-count", required=True, type=int)
    office.add_argument("--privacy-scrubbed", action="store_true")

    a = ap.parse_args()
    root = Path(a.root)
    if a.kind == "framework":
        rec = register_framework(root, Path(a.pcap), framework=a.framework, campaign_id=a.campaign_id, protocol=a.protocol, lifecycle=_csv(a.lifecycle), tool_version=a.tool_version, adapter_version=a.adapter_version, model_score=a.model_score, decision_threshold=a.decision_threshold)
    elif a.kind == "ech":
        rec = register_ech(root, Path(a.pcap), capture_id=a.capture_id, ech_mode=a.ech_mode, pair_id=a.pair_id, label_binary=a.label_binary, protocol=a.protocol, model_score=a.model_score, decision_threshold=a.decision_threshold)
    elif a.kind == "environment":
        rec = register_environment(root, Path(a.pcap), capture_id=a.capture_id, session_count=a.session_count, client_stack=a.client_stack, server_stack=a.server_stack, network_evidence=a.network_evidence)
    elif a.kind == "long-timing":
        rec = register_long_timing(root, Path(a.pcap), campaign_id=a.campaign_id, interval_seconds=a.interval_seconds, event_count=a.event_count, label_binary=a.label_binary)
    else:
        rec = register_office(root, Path(a.pcap), capture_id=a.capture_id, duration_seconds=a.duration_seconds, session_count=a.session_count, privacy_scrubbed=a.privacy_scrubbed)
    print(json.dumps(rec, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
