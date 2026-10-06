from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import time
from typing import Any, Callable

from office_injection.source import read_pcap

from .contracts import CaptureBundle, GenerationContext, RuntimeProfile


class ResourceBudgetError(RuntimeError):
    pass


class CaptureIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True)
class CapabilityReport:
    profile_id: str
    supported: bool
    capture_type: str
    reason: str
    details: dict[str, Any]


@dataclass(frozen=True)
class CaptureSpec:
    interface: str
    transport: str = "tcp"
    port: int | None = None

    def bpf(self) -> str:
        terms: list[str] = []
        if self.transport:
            terms.append(self.transport.lower())
        if self.port is not None:
            terms.append(f"port {int(self.port)}")
        return " and ".join(terms)


def _sha256_file(path: Path) -> str:
    h = sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _dir_usage_bytes(path: Path) -> int:
    path = Path(path)
    if not path.exists():
        return 0
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def ensure_resource_budget(
    path: Path,
    *,
    min_free_gib: float = 15,
    disk_usage_fn: Callable[[Path], Any] = shutil.disk_usage,
) -> None:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    free = int(disk_usage_fn(target).free)
    required = int(float(min_free_gib) * 2**30)
    if free < required:
        raise ResourceBudgetError(
            f"free disk {free / 2**30:.2f} GiB below required {float(min_free_gib):.2f} GiB"
        )


def ensure_scratch_budget(
    path: Path,
    *,
    cap_gib: float,
    usage_bytes_fn: Callable[[Path], int] = _dir_usage_bytes,
) -> None:
    used = int(usage_bytes_fn(Path(path)))
    cap = int(float(cap_gib) * 2**30)
    if used > cap:
        raise ResourceBudgetError(
            f"scratch usage {used / 2**30:.2f} GiB exceeds cap {float(cap_gib):.2f} GiB"
        )


def probe_capability(
    profile: RuntimeProfile,
    *,
    system_name: str | None = None,
) -> CapabilityReport:
    system = system_name or platform.system()
    if profile.os_family == "windows":
        if system.lower() != "windows":
            return CapabilityReport(
                profile.profile_id, False, profile.capture_type,
                "Windows runtime required; no Linux fallback is allowed",
                {"system": system},
            )
        supported = shutil.which("pktmon") is not None
        return CapabilityReport(
            profile.profile_id, supported, profile.capture_type,
            "pktmon available" if supported else "pktmon is unavailable",
            {"system": system, "pktmon": shutil.which("pktmon")},
        )
    if system.lower() != "linux":
        return CapabilityReport(
            profile.profile_id, False, profile.capture_type,
            "Linux runtime required",
            {"system": system},
        )
    if profile.capture_type != "tcpdump":
        return CapabilityReport(
            profile.profile_id, False, profile.capture_type,
            f"unsupported Linux capture type: {profile.capture_type}",
            {"system": system},
        )
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        return CapabilityReport(
            profile.profile_id, False, profile.capture_type,
            "tcpdump is unavailable",
            {"system": system},
        )
    sudo = shutil.which("sudo")
    usable = os.geteuid() == 0 or sudo is not None
    return CapabilityReport(
        profile.profile_id, usable, profile.capture_type,
        "tcpdump available" if usable else "tcpdump requires root/sudo",
        {"system": system, "tcpdump": tcpdump, "sudo": sudo, "euid": os.geteuid()},
    )


class TcpdumpBackend:
    def capture(self, profile, adapter, context, output_dir):
        spec = adapter.capture_spec(context)
        if not isinstance(spec, CaptureSpec):
            raise TypeError("adapter.capture_spec must return CaptureSpec")
        pcap = Path(output_dir) / "capture.pcap"
        tcpdump = shutil.which("tcpdump")
        if tcpdump is None:
            raise RuntimeError("tcpdump is unavailable")
        cmd: list[str] = []
        if os.geteuid() != 0:
            sudo = shutil.which("sudo")
            if sudo is None:
                raise RuntimeError("tcpdump requires root or sudo")
            cmd.extend([sudo, "-n"])
        cmd.extend([tcpdump, "-i", spec.interface, "--immediate-mode", "-U", "-n", "-s", "0", "-w", str(pcap)])
        bpf = spec.bpf()
        if bpf:
            cmd.extend(bpf.split())
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            time.sleep(0.35)
            if proc.poll() is not None:
                stderr = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(f"tcpdump exited before activity: {stderr.strip()}")
            result = adapter.execute(context)
            time.sleep(0.35)
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait(timeout=5)
        if not pcap.exists() or pcap.stat().st_size <= 24:
            stderr = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"capture is empty: {stderr.strip()}")
        evidence = Path(output_dir) / "execution.json"
        evidence.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        return pcap, (evidence,), {
            "backend": "tcpdump",
            "capture_spec": asdict(spec),
            "command": [Path(x).name if i in (0, 2) else x for i, x in enumerate(cmd)],
        }


def _environment_identity_sha(context: GenerationContext) -> str:
    value = {
        "pair_id": context.pair_id,
        "profile_identity": list(context.profile.identity()),
        "seed": int(context.seed),
    }
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=list)
    return sha256(raw.encode()).hexdigest()


def run_capture(
    profile: RuntimeProfile,
    adapter: Any,
    context: GenerationContext,
    *,
    backend: Any | None = None,
    capability: CapabilityReport | None = None,
    min_free_gib: float = 15,
) -> CaptureBundle:
    output = Path(context.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    run_manifest = output / "run_manifest.json"
    base_manifest = {
        "version": "natural-capture-v2",
        "profile_id": profile.profile_id,
        "pair_id": context.pair_id,
        "role": context.role,
        "adapter_id": getattr(adapter, "adapter_id", type(adapter).__name__),
    }
    try:
        if context.profile.profile_id != profile.profile_id:
            raise ValueError("context/profile mismatch")
        ensure_resource_budget(output, min_free_gib=min_free_gib)
        ensure_scratch_budget(output, cap_gib=profile.resource_budget_gib)
        report = capability or probe_capability(profile)
        if report.profile_id != profile.profile_id:
            raise ValueError("capability/profile mismatch")
        if not report.supported:
            raise RuntimeError(f"capture capability unsupported: {report.reason}")
        selected = backend or TcpdumpBackend()
        pcap, evidence_paths, backend_meta = selected.capture(profile, adapter, context, output)
        pcap = Path(pcap)
        if not pcap.exists() or pcap.stat().st_size <= 24:
            raise RuntimeError("capture backend returned empty PCAP")
        if not list(read_pcap(pcap)):
            raise RuntimeError("capture PCAP contains no packets")
        pcap_hash = _sha256_file(pcap)
        evidence: list[tuple[str, str]] = []
        for path in evidence_paths:
            item = Path(path)
            evidence.append((str(item), _sha256_file(item)))
        runtime = output / "runtime_metadata.json"
        runtime_body = {
            **base_manifest,
            "status": "captured",
            "environment_identity_sha256": _environment_identity_sha(context),
            "capability": asdict(report),
            "backend": backend_meta,
            "pcap_sha256": pcap_hash,
            "evidence": [{"path": p, "sha256": h} for p, h in evidence],
        }
        runtime.write_text(json.dumps(runtime_body, sort_keys=True, indent=2) + "\n")
        runtime_hash = _sha256_file(runtime)
        done = {
            **base_manifest,
            "status": "success",
            "pcap": str(pcap),
            "pcap_sha256": pcap_hash,
            "runtime_metadata": str(runtime),
            "runtime_metadata_sha256": runtime_hash,
        }
        run_manifest.write_text(json.dumps(done, sort_keys=True, indent=2) + "\n")
        return CaptureBundle(
            pair_id=context.pair_id,
            role=context.role,
            profile_id=profile.profile_id,
            fidelity="wire-real",
            pcap_path=pcap,
            pcap_sha256=pcap_hash,
            evidence=tuple(evidence),
            runtime_metadata_path=runtime,
            runtime_metadata_sha256=runtime_hash,
        )
    except Exception as exc:
        failed = {**base_manifest, "status": "failed", "error": str(exc)}
        run_manifest.write_text(json.dumps(failed, sort_keys=True, indent=2) + "\n")
        raise


def verify_capture_bundle(bundle: CaptureBundle) -> bool:
    if _sha256_file(bundle.pcap_path) != bundle.pcap_sha256:
        raise CaptureIntegrityError("capture PCAP hash mismatch")
    if _sha256_file(bundle.runtime_metadata_path) != bundle.runtime_metadata_sha256:
        raise CaptureIntegrityError("runtime metadata hash mismatch")
    for path, expected in bundle.evidence:
        if _sha256_file(Path(path)) != expected:
            raise CaptureIntegrityError(f"evidence hash mismatch: {path}")
    return True


def assert_extraction_input(bundle: CaptureBundle, path: Path) -> bool:
    actual = _sha256_file(Path(path))
    if actual != bundle.pcap_sha256:
        raise CaptureIntegrityError("extraction input does not match pinned capture hash")
    return True