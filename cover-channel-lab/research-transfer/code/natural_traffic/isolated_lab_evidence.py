"""Safe research summaries of strictly isolated Cover/Adaptix capture fixtures.

Only aggregate validation facts leave the ephemeral runner. No capture bytes,
agent artifacts, target addresses, task contents or credentials are exported.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from office_injection.cover_registry import digest

from .corpus import discover_cover_captures
from .pcap_quality import audit_pcap


ADAPTIX_SOURCE_COMMIT = "e99535c9ef4642190f7ea125c2983d1611f1a3f3"
# Deliberately bounded: the repository already implements these fixed cases.
# No arbitrary mechanism names, commands, URLs or targets reach a runtime.
COVER_MATRIX = (
    ("M-HTTPS-BEACON", "m-https-beacon-python_httpx-hypercorn"),
    ("M-TIMING-XCARRIER", "timing-dns-udp"),
    ("M-TIMING-XCARRIER", "timing-wss-python"),
    ("M-TIMING-XCARRIER", "timing-mqtt-paho"),
)


def _sha(path: Path) -> str:
    h = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _verified_registry(base: dict) -> None:
    if not isinstance(base, dict) or base.get("sha256") != digest({
        k: v for k, v in base.items() if k != "sha256"
    }):
        raise ValueError("registry checksum mismatch")


def select_cover_registry(base: dict, *, seed: int = 20261008) -> dict:
    """Freeze a small, distinct native-stack matrix before seeing any outcome."""
    from cover_runtime.environment import profile_config

    _verified_registry(base)
    sources = {(entry["entry_id"], profile["profile_id"]): (entry, profile)
               for entry in base["entries"] for profile in entry["profiles"]}
    if not set(COVER_MATRIX).issubset(sources):
        raise ValueError("registry is missing one or more declared lab profiles")
    body = deepcopy({key: value for key, value in base.items() if key not in ("sha256", "entries")})
    entries = []
    for entry in base["entries"]:
        selected = []
        for profile in entry["profiles"]:
            if (entry["entry_id"], profile["profile_id"]) not in COVER_MATRIX:
                continue
            record = deepcopy(profile)
            record.update(profile_config(entry["entry_id"], profile["profile_id"],
                                         seed, entry.get("family"), "lab_fixed_v1"))
            selected.append(record)
        if selected:
            candidate = deepcopy(entry)
            candidate["profiles"] = selected
            entries.append(candidate)
    body.update({
        "entries": entries,
        "parent_registry_sha256": base["sha256"],
        "path_profile": "lab_fixed_v1",
        "research_policy": "isolated_fixed_lab_matrix; no office equivalence claim; paired native captures",
    })
    body["sha256"] = digest(body)
    return body


def audit_cover(run_root: Path, selected_registry: dict) -> dict:
    """Require the exact preselected role/profile matrix on the native wire."""
    _verified_registry(selected_registry)
    expected = {(entry["entry_id"], profile["profile_id"], arm)
                for entry in selected_registry["entries"]
                for profile in entry["profiles"] for arm in ("scenario", "control")}
    if expected != {(eid, pid, arm) for eid, pid in COVER_MATRIX for arm in ("scenario", "control")}:
        raise ValueError("cover matrix does not match the frozen experimental contract")
    captures = [*discover_cover_captures(run_root, high_level_profile_id="isolated-lab",
                                         role="scenario"),
                *discover_cover_captures(run_root, high_level_profile_id="isolated-lab",
                                         role="control")]
    observed = [(c.entry_id, c.source_profile_id, c.role) for c in captures]
    if len(observed) != len(expected) or set(observed) != expected:
        raise ValueError("missing, duplicated or unexpected cover capture roles/profiles")
    packet_total = 0
    for capture in captures:
        quality = audit_pcap(capture.bundle.pcap_path)
        if not quality.accepted or quality.packet_count < 1:
            raise ValueError("capture failed immutable wire quality audit")
        packet_total += quality.packet_count
        # discover_cover_captures already verified PCAP and evidence SHA256.
        if _sha(capture.bundle.pcap_path) != capture.bundle.pcap_sha256:
            raise ValueError("capture hash changed during quality audit")
    return {
        "version": "isolated-cover-research-evidence-v1",
        "status": "verified", "captures": len(captures),
        "verified_pairs": len(expected) // 2, "physical_frames": packet_total,
        "mechanism_ids": sorted({entry for entry, _ in COVER_MATRIX}),
        "runtime_profiles": sorted(profile for _, profile in COVER_MATRIX),
        "registry_sha256": selected_registry["sha256"],
        "original_pcap_bytes_unchanged": True,
        "public_artifacts_exclude_raw_pcap": True,
        "office_naturalness_proven": False,
        "technique_research_validated": False,
        "production_ready": False,
        "naturalness_status": "not_passed",
    }


def audit_adaptix(run_root: Path) -> dict:
    """Check six TCP/mTLS Gopher pairs without exporting receipt contents."""
    root = Path(run_root)
    packet_total = 0
    for transport in ("tcp", "mtls"):
        for profile in range(3):
            for arm in ("scenario", "control"):
                directory = root / f"{transport}_p{profile}" / arm
                path, receipt_path = directory / "capture.pcap", directory / "receipt.json"
                if not path.is_file() or not receipt_path.is_file():
                    raise ValueError("missing Adaptix paired capture or receipt")
                receipt = json.loads(receipt_path.read_text())
                if (receipt.get("transport"), receipt.get("profile"), receipt.get("arm")) != (
                    transport, profile, arm,
                ) or receipt.get("framework") != "Adaptix" or (
                    receipt.get("source_commit") != ADAPTIX_SOURCE_COMMIT
                ):
                    raise ValueError("Adaptix receipt source/profile/role mismatch")
                if receipt.get("verified") is not True:
                    raise ValueError("unverified Adaptix task and wire capture")
                if receipt.get("capture_sha256") != _sha(path):
                    raise ValueError("Adaptix capture hash mismatch")
                wire = receipt.get("wire_verification") or {}
                if wire.get("packet_count", 0) < 10 or (
                    wire.get("whole_flow_syn") is not True or
                    wire.get("ethernet_mtu_verified") is not True or
                    wire.get("kernel_drops") != 0
                ):
                    raise ValueError("Adaptix wire integrity or drop gate not verified")
                if len(receipt.get("submitted", [])) != 6:
                    raise ValueError("Adaptix fixed task count incomplete")
                quality = audit_pcap(path)
                if not quality.accepted or quality.packet_count < 1:
                    raise ValueError("Adaptix PCAP quality rejected")
                packet_total += quality.packet_count
    return {
        "version": "isolated-adaptix-research-evidence-v1",
        "status": "verified", "source_commit": ADAPTIX_SOURCE_COMMIT,
        "transports": ["tcp", "mtls"], "profiles_per_transport": 3,
        "captures": 12, "verified_pairs": 6,
        "physical_frames": packet_total,
        "fixed_disposable_tasks_only": True,
        "isolated_runtime_network": "none",
        "public_artifacts_exclude_raw_pcap": True,
        "office_naturalness_proven": False,
        "technique_research_validated": False,
        "production_ready": False,
        "naturalness_status": "not_passed",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    cover_select = sub.add_parser("select-cover")
    cover_select.add_argument("--registry", type=Path, required=True)
    cover_select.add_argument("--out", type=Path, required=True)
    cover_audit = sub.add_parser("audit-cover")
    cover_audit.add_argument("--run", type=Path, required=True)
    cover_audit.add_argument("--registry", type=Path, required=True)
    cover_audit.add_argument("--out", type=Path, required=True)
    adaptix = sub.add_parser("audit-adaptix")
    adaptix.add_argument("--run", type=Path, required=True)
    adaptix.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise FileExistsError(args.out)
    if args.action == "select-cover":
        result = select_cover_registry(json.loads(args.registry.read_text()))
    elif args.action == "audit-cover":
        result = audit_cover(args.run, json.loads(args.registry.read_text()))
    else:
        result = audit_adaptix(args.run)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k in (
        "status", "captures", "verified_pairs", "physical_frames", "registry_sha256",
    )}, sort_keys=True))


if __name__ == "__main__":
    main()
