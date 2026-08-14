#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bz2
import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Callable

import pandas as pd
import yaml

from adminlab.lanl_reference import parse_netflow_lines, parse_wls_lines


def stream_bz2_lines(
    url: str,
    *,
    accept: Callable[[str], bool],
    wanted: int,
    max_compressed_bytes: int,
    timeout: int = 60,
) -> tuple[list[str], dict]:
    headers = {"User-Agent": "remote-admin-anomaly-lab-v2/1.0"}
    request = urllib.request.Request(url, headers=headers)
    sha = hashlib.sha256()
    decompressor = bz2.BZ2Decompressor()
    carry = ""
    selected: list[str] = []
    compressed = 0
    decompressed = 0
    status = None
    content_type = ""
    with urllib.request.urlopen(request, timeout=timeout) as response:
        status = getattr(response, "status", None)
        content_type = response.headers.get("Content-Type", "")
        while len(selected) < wanted and compressed < max_compressed_bytes:
            chunk = response.read(min(1024 * 1024, max_compressed_bytes - compressed))
            if not chunk:
                break
            compressed += len(chunk)
            sha.update(chunk)
            data = decompressor.decompress(chunk)
            decompressed += len(data)
            text = carry + data.decode("utf-8", errors="replace")
            parts = text.split("\n")
            carry = parts.pop()
            for line in parts:
                line = line.strip()
                if line and accept(line):
                    selected.append(line)
                    if len(selected) >= wanted:
                        break
    if len(selected) < wanted and carry.strip() and accept(carry.strip()):
        selected.append(carry.strip())
    meta = {
        "url": url,
        "http_status": status,
        "content_type": content_type,
        "compressed_bytes_consumed": compressed,
        "decompressed_bytes_consumed": decompressed,
        "consumed_prefix_sha256": sha.hexdigest(),
        "selected_lines": len(selected),
        "max_compressed_bytes": max_compressed_bytes,
    }
    return selected, meta


def port_token(value: str) -> int | None:
    text = value.strip()
    if text.lower().startswith("port"):
        text = text[4:]
    try:
        return int(text)
    except ValueError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("configs/v2_research.yaml"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--netflow-rows", type=int, default=5000)
    parser.add_argument("--wls-rows", type=int, default=5000)
    parser.add_argument("--max-compressed-mb", type=int, default=512)
    args = parser.parse_args()

    cfg = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    lanl = cfg["lanl"]
    ports = {int(p) for p in lanl["remote_admin_ports"]}
    max_bytes = int(args.max_compressed_mb) * 1024 * 1024
    args.out.mkdir(parents=True, exist_ok=True)

    def netflow_accept(line: str) -> bool:
        parts = line.split(",")
        if len(parts) != 11:
            return False
        src_port = port_token(parts[5])
        dst_port = port_token(parts[6])
        return src_port in ports or dst_port in ports

    def wls_accept(line: str) -> bool:
        if not line.startswith("{"):
            return False
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return False
        description = str(event.get("LogonTypeDescription", "")).lower()
        logon_type = int(event.get("LogonType", 0) or 0)
        return description == "network" or logon_type == 3

    net_lines, net_meta = stream_bz2_lines(
        str(lanl["netflow_url"]),
        accept=netflow_accept,
        wanted=args.netflow_rows,
        max_compressed_bytes=max_bytes,
    )
    wls_lines, wls_meta = stream_bz2_lines(
        str(lanl["host_url"]),
        accept=wls_accept,
        wanted=args.wls_rows,
        max_compressed_bytes=max_bytes,
    )

    net = parse_netflow_lines(net_lines, ports, max_rows=args.netflow_rows)
    wls = parse_wls_lines(wls_lines, max_rows=args.wls_rows)
    if net.empty:
        raise SystemExit("LANL reference gate: no remote-admin network rows were obtained")
    if wls.empty:
        raise SystemExit("LANL reference gate: no Windows network-logon rows were obtained")
    forbidden = {"label_binary", "split", "challenge_reason"}
    if forbidden & set(net.columns) or forbidden & set(wls.columns):
        raise SystemExit("LANL reference gate: supervised label columns leaked into external reference")

    net = net.sort_values(["time", "src_device", "dst_device"], kind="stable").reset_index(drop=True)
    wls = wls.sort_values(["time", "src_device", "dst_device"], kind="stable").reset_index(drop=True)
    net.to_parquet(args.out / "remote_admin_flows.parquet", index=False)
    wls.to_parquet(args.out / "network_logons.parquet", index=False)

    port_counts: dict[str, int] = {}
    for port in sorted(ports):
        count = int(((net["src_port"] == port) | (net["dst_port"] == port)).sum())
        if count:
            port_counts[str(port)] = count
    quality = {
        "schema_version": 2,
        "status": "PASS",
        "environment_id": "lanl_reference",
        "external_only": True,
        "threshold_tuning_allowed": False,
        "netflow_rows": len(net),
        "network_logon_rows": len(wls),
        "remote_admin_port_counts": port_counts,
        "netflow_time_min": int(net["time"].min()),
        "netflow_time_max": int(net["time"].max()),
        "wls_time_min": int(wls["time"].min()),
        "wls_time_max": int(wls["time"].max()),
        "finite_netflow_numeric": bool(net[["time", "duration", "src_packets", "dst_packets", "src_bytes", "dst_bytes"]].notna().all().all()),
        "synthetic_labels_present": False,
    }
    if not quality["finite_netflow_numeric"]:
        raise SystemExit("LANL reference gate: non-finite required network fields")
    (args.out / "reference_quality.json").write_text(json.dumps(quality, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    manifest = {
        "schema_version": 2,
        "dataset": lanl["dataset"],
        "year": int(lanl["year"]),
        "source_page": "https://csr.lanl.gov/data/2017/",
        "citation": "Melissa J. M. Turcotte, Alexander D. Kent, Curtis Hash, Unified Host and Network Data Set, 2018",
        "license_note": "LANL source page states CC0-style waiver to the extent possible under law",
        "remote_admin_ports": sorted(ports),
        "netflow": net_meta,
        "windows_host_events": wls_meta,
        "external_only": True,
        "used_for_training": False,
        "used_for_threshold_tuning": False,
    }
    (args.out / "source_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"quality": quality, "manifest": manifest}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
