"""Remote-only, bounded batch driver. Each batch writes a new retained run."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def ensure_runner_resources(
    path,
    *,
    min_free_gib=15,
    disk_usage_fn=shutil.disk_usage,
    loadavg_fn=os.getloadavg,
):
    usage = disk_usage_fn(Path(path))
    free_gib = float(usage.free) / (1 << 30)
    loadavg = tuple(float(v) for v in loadavg_fn())
    if free_gib < float(min_free_gib):
        raise SystemExit(
            f"resource guard: free disk {free_gib:.2f} GiB below {float(min_free_gib):.2f} GiB"
        )
    return {"free_gib": free_gib, "loadavg": loadavg}


def validate_runtime_results(run_root, jobs):
    root = Path(run_root)
    path = root / "results.json"
    if not path.is_file():
        raise RuntimeError("missing runtime results.json")
    results = json.loads(path.read_text())
    if not isinstance(results, list):
        raise RuntimeError("runtime results.json must contain a list")
    by_id = {}
    for row in results:
        job_id = str(row.get("job_id", ""))
        if not job_id:
            raise RuntimeError("runtime result missing job_id")
        if job_id in by_id:
            raise RuntimeError(f"duplicate runtime result: {job_id}")
        by_id[job_id] = row
    expected = [str(job["job_id"]) for job in jobs]
    missing = [job_id for job_id in expected if job_id not in by_id]
    if missing:
        raise RuntimeError(f"missing runtime result for job {missing[0]}")
    unexpected = sorted(set(by_id) - set(expected))
    if unexpected:
        raise RuntimeError(f"unexpected runtime result: {unexpected[0]}")
    failures = [
        by_id[job_id]
        for job_id in expected
        if str(by_id[job_id].get("status")) != "captured"
    ]
    if failures:
        first = failures[0]
        raise RuntimeError(
            f"runtime job {first.get('job_id')} failed: {first.get('reason') or 'unknown reason'}"
        )
    return {"expected": len(expected), "captured": len(expected), "failed": 0}


def required_runtime_services(jobs):
    services = {"core"}
    for job in jobs:
        entry = dict(job.get("entry") or {})
        namespace = str(entry.get("namespace", "")).lower()
        transport = str(entry.get("transport", "")).lower()
        family = str(entry.get("family", "")).lower()
        carrier = str(entry.get("carrier", "")).lower()
        protocol_hints = " ".join((transport, family, carrier))
        if namespace and namespace != "catalog":
            services.add("stage_m")
        if transport in {"h3", "http3", "quic"} or "quic" in transport:
            services.add("h3")
        if "grpc" in protocol_hints:
            services.add("grpc")
        if "mqtt" in protocol_hints:
            services.add("mqtt")
    return tuple(sorted(services))


def build_jobs(
    registry,
    *,
    requested_entries,
    requested_profiles,
    arm,
    seed,
    timing,
    default_events,
    native_interval,
    mechanics,
    adapter_identity,
):
    if arm not in {"scenario", "control", "both"}:
        raise ValueError("arm must be scenario, control, or both")
    arms = ("scenario", "control") if arm == "both" else (arm,)
    jobs = []
    for e in registry["entries"]:
        if requested_entries is not None and e["entry_id"] not in requested_entries:
            continue
        for p in e["profiles"]:
            if requested_profiles and p["profile_id"] not in requested_profiles:
                continue
            for selected_arm in arms:
                body = {
                    "entry_id": e["entry_id"],
                    "profile_id": p["profile_id"],
                    "arm": selected_arm,
                    "seed": seed,
                    "network": "none",
                    "timing": timing,
                    "registry_sha256": registry["sha256"],
                    "entry": {**e, "dataset_role": p.get("dataset_role", e["dataset_role"])},
                    "profile": p,
                    "events": p.get("runtime_events", default_events),
                    "native_interval": p.get("native_interval", native_interval),
                    "mechanics": mechanics,
                    "runtime_adapters_sha256": adapter_identity,
                    "timeout_seconds": 180 if timing == "accelerated_smoke" else 900,