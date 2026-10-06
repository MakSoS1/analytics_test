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
                    "path_rtt_ms": p.get("path_rtt_ms"),
                    **{
                        k: p[k]
                        for k in ("path_profile", "client_mtu", "client_tcp_timestamps")
                        if p.get(k) is not None
                    },
                }
                jobs.append({
                    **body,
                    "job_id": hashlib.sha256(
                        json.dumps(body, sort_keys=True).encode()
                    ).hexdigest(),
                })
    return jobs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--image", default="cover-complete:20261002")
    parser.add_argument("--entry", action="append", default=[])
    parser.add_argument("--profile", action="append", default=[])
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--events", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261002)
    parser.add_argument("--native-interval", type=float)
    parser.add_argument("--mechanics", action="store_true")
    parser.add_argument(
        "--timing",
        choices=("native", "accelerated_smoke"),
        default="accelerated_smoke",
    )
    parser.add_argument(
        "--arm",
        choices=("scenario", "control", "both"),
        default="both",
        help="generate only scenario, only matched control, or both arms",
    )
    a = parser.parse_args()
    if not a.all and not a.entry:
        parser.error("explicit --all or --entry required")
    resources = ensure_runner_resources(a.out.parent, min_free_gib=15)

    root = Path(__file__).resolve().parent
    registry = json.loads((a.registry or root / "registry.json").read_text())
    adapter_hashes = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.glob("*.py")
    }
    adapter_identity = hashlib.sha256(
        json.dumps(adapter_hashes, sort_keys=True).encode()
    ).hexdigest()

    jobs = build_jobs(
        registry,
        requested_entries=None if a.all else set(a.entry),
        requested_profiles=set(a.profile),
        arm=a.arm,
        seed=a.seed,
        timing=a.timing,
        default_events=a.events,
        native_interval=a.native_interval,
        mechanics=a.mechanics,
        adapter_identity=adapter_identity,
    )
    if not jobs:
        raise SystemExit("no requested entries")

    a.out.mkdir(parents=True, exist_ok=False)
    snapshot = a.out.resolve() / "runtime_code"
    snapshot.mkdir()
    for file in (
        "entrypoint.py",
        "stage_controls.py",
        "browser_guard.py",
        "mechanic_patch.py",
        "browser_client.py",
        "application_patch.py",
        "protocol_patch.py",
        "environment.py",
    ):
        shutil.copyfile(root / file, snapshot / file)
    required_services = required_runtime_services(jobs)
    (a.out / "jobs.json").write_text(
        json.dumps({"jobs": jobs, "required_services": list(required_services)}, indent=2) + "\n"
    )

    image_id = subprocess.check_output(
        ["docker", "image", "inspect", "--format", "{{.Id}}", a.image], text=True
    ).strip()
    manifest = {
        "image_id": image_id,
        "entrypoint_sha256": hashlib.sha256((snapshot / "entrypoint.py").read_bytes()).hexdigest(),
        "control_adapter_sha256": hashlib.sha256((snapshot / "stage_controls.py").read_bytes()).hexdigest(),
        "browser_guard_sha256": hashlib.sha256((snapshot / "browser_guard.py").read_bytes()).hexdigest(),
        "mechanic_patch_sha256": hashlib.sha256((snapshot / "mechanic_patch.py").read_bytes()).hexdigest(),
        "browser_client_sha256": hashlib.sha256((snapshot / "browser_client.py").read_bytes()).hexdigest(),
        "application_patch_sha256": hashlib.sha256((snapshot / "application_patch.py").read_bytes()).hexdigest(),
        "protocol_patch_sha256": hashlib.sha256((snapshot / "protocol_patch.py").read_bytes()).hexdigest(),
        "environment_sha256": hashlib.sha256((snapshot / "environment.py").read_bytes()).hexdigest(),
        "registry_sha256": registry["sha256"],
        "jobs": len(jobs),
        "required_services": list(required_services),
        "arm": a.arm,
        "network": "none",
        "cpus": 2,
        "memory_gib": 4,
        "timing": a.timing,
        "started_at": time.time(),
        "runner_resources": resources,
        "production_ready": False,
    }
    (a.out / "runtime_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    name = "ccfull-" + hashlib.sha256(str(a.out.resolve()).encode()).hexdigest()[:16]
    command = [
        "docker",
        "run",
        "--rm",
        "--init",
        "--name",
        name,
        "--network=none",
        "--cpus=2",
        "--memory=4g",
        "--shm-size=512m",
        "--pids-limit=512",
        "--cap-add=NET_ADMIN",
        "--cap-add=NET_RAW",
        "--cap-add=SYS_ADMIN",
        "--security-opt=apparmor=unconfined",
        "--mount",
        f"type=bind,src={a.out.resolve()},dst=/out",
        "--mount",
        f"type=bind,src={snapshot / 'entrypoint.py'},dst=/entrypoint.py,readonly",
        a.image,
        "/out/jobs.json",
    ]
    for file in (
        "stage_controls.py",
        "browser_guard.py",
        "mechanic_patch.py",
        "browser_client.py",
        "application_patch.py",
        "protocol_patch.py",
        "environment.py",
    ):
        command[-2:-2] = [
            "--mount",
            f"type=bind,src={snapshot / file},dst=/{file},readonly",
        ]
    cp = None
    try:
        with (a.out / "runtime.log").open("w") as log:
            cp = subprocess.run(
                command,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=21600,
            )
    finally:
        subprocess.run(
            ["docker", "stop", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if cp is None:
        raise RuntimeError("container execution did not start")
    manifest.update(exit_code=cp.returncode, ended_at=time.time())
    try:
        result_summary = validate_runtime_results(a.out, jobs)
        manifest["job_results"] = result_summary
        if cp.returncode != 0:
            raise RuntimeError(f"runtime container exited with code {cp.returncode}")
    except Exception as exc:
        manifest["job_validation_error"] = str(exc)
        (a.out / "runtime_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(json.dumps({"jobs": len(jobs), "exit_code": cp.returncode, "out": str(a.out), "error": str(exc)}))
        raise
    (a.out / "runtime_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"jobs": len(jobs), "exit_code": cp.returncode, "out": str(a.out), "job_results": result_summary}))


if __name__ == "__main__":
    main()