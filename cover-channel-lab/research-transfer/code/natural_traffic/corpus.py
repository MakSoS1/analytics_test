from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Iterable

import pandas as pd

from .contracts import CaptureBundle


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()




_CLIENT_PROFILE_MAP = {
    "browser_chromium": "linux-chromium",
    "chromium_websocket": "linux-chromium",
    "curl_linux": "linux-curl",
    "python_httpx": "linux-python-ssl",
    "python_httpx_h2": "linux-python-ssl",
    "python_httpx_reuse": "linux-python-ssl",
    "python_httpx_h2_reuse": "linux-python-ssl",
    "python_stdlib": "linux-python-ssl",
    "go_nethttp": "linux-protocol-native",
    "java_httpclient": "linux-protocol-native",
    "node_fetch": "linux-protocol-native",
    "node_websocket": "linux-protocol-native",
    "rust_reqwest": "linux-protocol-native",
    "python_websockets": "linux-protocol-native",
}


def classify_cover_runtime_profile(profile: dict[str, object]) -> str:
    client = str(profile.get("client", "")).lower()
    try:
        return _CLIENT_PROFILE_MAP[client]
    except KeyError:
        raise ValueError(f"unsupported Cover runtime client for natural profile: {client}") from None


@dataclass(frozen=True)
class CoverCapture:
    bundle: CaptureBundle
    ancestor_id: str
    entry_id: str
    source_profile_id: str
    high_level_profile_id: str
    role: str
    seed: int
    job_dir: Path


def discover_cover_captures(
    run_root: Path,
    *,
    high_level_profile_id: str,
    role: str,
) -> list[CoverCapture]:
    if role not in {"control", "scenario"}:
        raise ValueError(f"invalid role: {role}")
    root = Path(run_root)
    found: list[CoverCapture] = []
    if not root.is_dir():
        raise FileNotFoundError(root)
    for job_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        job_path = job_dir / "job.json"
        result_path = job_dir / "result.json"
        pcap_path = job_dir / "capture.pcap"
        if not (job_path.is_file() and result_path.is_file() and pcap_path.is_file()):
            continue
        job = json.loads(job_path.read_text())
        result = json.loads(result_path.read_text())
        if result.get("status") != "captured":
            continue
        if str(job.get("arm")) != role or str(result.get("arm")) != role:
            continue
        if str(job.get("job_id")) != str(result.get("job_id")):
            raise ValueError(f"job/result identity mismatch: {job_dir}")
        expected = str(result.get("capture_sha256", ""))
        actual = _sha256(pcap_path)
        if not expected or actual != expected:
            raise ValueError(f"capture hash mismatch: {job_dir.name}")
        evidence: list[tuple[str, str]] = []
        for name, digest in sorted(dict(result.get("evidence_sha256", {})).items()):
            path = job_dir / name
            if not path.is_file():
                raise ValueError(f"missing evidence: {path}")
            if _sha256(path) != str(digest):
                raise ValueError(f"evidence hash mismatch: {path}")
            evidence.append((str(path), str(digest)))
        runtime_hash = _sha256(result_path)
        ancestor = str(job["job_id"])
        source_profile = str(job["profile_id"])
        entry_id = str(job["entry_id"])
        bundle = CaptureBundle(
            pair_id=ancestor,
            role=role,
            profile_id=high_level_profile_id,
            fidelity=str(result.get("source_fidelity", "unknown")),
            pcap_path=pcap_path,
            pcap_sha256=actual,
            evidence=tuple(evidence),
            runtime_metadata_path=result_path,
            runtime_metadata_sha256=runtime_hash,
        )
        found.append(
            CoverCapture(
                bundle=bundle,
                ancestor_id=ancestor,
                entry_id=entry_id,
                source_profile_id=source_profile,
                high_level_profile_id=high_level_profile_id,
                role=role,
                seed=int(job["seed"]),
                job_dir=job_dir,
            )
        )
    return found


def aggregate_extracted_tables(
    extracted: Iterable[tuple[CoverCapture, Path]],
    out_path: Path,
    *,
    benign_only: bool = False,
) -> dict[str, object]:
    rows: list[pd.DataFrame] = []
    groups: set[str] = set()
    for capture, path in extracted:
        if benign_only and capture.role != "control":
            raise ValueError("benign aggregate accepts control captures only")
        frame = pd.read_parquet(path).copy()
        frame["profile_id"] = capture.high_level_profile_id
        frame["source_profile_id"] = capture.source_profile_id
        frame["role"] = capture.role
        frame["capture_group"] = capture.ancestor_id
        frame["seed"] = int(capture.seed)
        frame["entry_id"] = capture.entry_id
        rows.append(frame)
        groups.add(capture.ancestor_id)
    if not rows:
        raise ValueError("no extracted captures to aggregate")
    combined = pd.concat(rows, ignore_index=True, sort=False)
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    combined.to_parquet(target, index=False)
    return {
        "version": "natural-cover-corpus-v2",
        "rows": int(len(combined)),
        "capture_groups": len(groups),
        "profiles": sorted(set(combined["profile_id"].astype(str))),
        "roles": sorted(set(combined["role"].astype(str))),
        "sha256": _sha256(target),
        "path": str(target),
    }