#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import urllib.request
from io import StringIO
from pathlib import Path
from typing import Callable

import pandas as pd
import yaml

from adminlab.lanl_reference import parse_netflow_lines, parse_wls_lines


def stream_http_lines(
    url: str,
    *,
    accept: Callable[[str], bool],
    wanted: int,
    max_download_bytes: int,
    timeout: int = 90,
) -> tuple[list[str], dict]:
    """Stream a bounded prefix of a public line-oriented mirror.

    Hash/byte counters describe exactly the consumed HTTP body prefix rather
    than pretending a partially streamed file has the checksum of the complete
    upstream object.
    """
    headers = {"User-Agent": "remote-admin-anomaly-lab-v2/1.0"}
    request = urllib.request.Request(url, headers=headers)
    sha = hashlib.sha256()
    selected: list[str] = []
    downloaded = 0
    status = None
    content_type = ""
    content_length = None
    etag = ""
    last_modified = ""
    with urllib.request.urlopen(request, timeout=timeout) as response:
        status = getattr(response, "status", None)
        content_type = response.headers.get("Content-Type", "")
        content_length = response.headers.get("Content-Length")
        etag = response.headers.get("ETag", "")
        last_modified = response.headers.get("Last-Modified", "")
        for raw in response:
            if downloaded + len(raw) > max_download_bytes:
                break
            downloaded += len(raw)
            sha.update(raw)
            line = raw.decode("utf-8", errors="replace").strip()
            if line and accept(line):
                selected.append(line)
                if len(selected) >= wanted:
                    break
    meta = {
        "url": url,
        "http_status": status,
        "content_type": content_type,
        "content_length_header": content_length,
        "etag": etag,
        "last_modified": last_modified,
        "downloaded_prefix_bytes": downloaded,
        "downloaded_prefix_sha256": sha.hexdigest(),
        "selected_lines": len(selected),
        "max_download_bytes": max_download_bytes,
        "complete_object_downloaded": bool(content_length and downloaded == int(content_length)),
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


def csv_fields(line: str) -> list[str]:
    try:
        return next(csv.reader(StringIO(line)))
    except csv.Error:
        return []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("configs/v2_research.yaml"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--netflow-rows", type=int, default=5000)
    parser.add_argument("--wls-rows", type=int, default=5000)
    parser.add_argument("--max-download-mb", type=int, default=384)
    args = parser.parse_args()

    cfg = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    lanl = cfg["lanl"]
    ports = {int(p) for p in lanl["remote_admin_ports"]}
    max_bytes = int(args.max_download_mb) * 1024 * 1024
    args.out.mkdir(parents=True, exist_ok=True)

    def netflow_accept(line: str) -> bool:
        parts = csv_fields(line)
        if len(parts) != 11:
            return False
        src_port = port_token(parts[5])
        dst_port = port_token(parts[6])
        return src_port in ports or dst_port in ports

    def auth_accept(line: str) -> bool:
        parts = csv_fields(line)
        if len(parts) != 21:
            return False
        try:
            logon_type = int(parts[3])
        except ValueError:
            logon_type = 0
        return parts[4].strip().lower() == "network" or logon_type == 3

    net_lines, net_meta = stream_http_lines(
        str(lanl["netflow_url"]),
        accept=netflow_accept,
        wanted=args.netflow_rows,
        max_download_bytes=max_bytes,
    )
    wls_lines, wls_meta = stream_http_lines(
        str(lanl["auth_url"]),
        accept=auth_accept,
        wanted=args.wls_rows,
        max_download_bytes=max_bytes,
    )

    net = parse_netflow_lines(net_lines, ports, max_rows=args.netflow_rows)
    wls = parse_wls_lines(wls_lines, max_rows=args.wls_rows)
    if net.empty:
        raise SystemExit("LANL reference gate: no remote-admin network rows were obtained from mirror")
    if wls.empty:
        raise SystemExit("LANL reference gate: no Windows network-logon rows were obtained from mirror")
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
        "netflow_rows": int(len(net)),
        "network_logon_rows": int(len(wls)),
        "remote_admin_port_counts": port_counts,
        "netflow_time_min": int(net["time"].min()),
        "netflow_time_max": int(net["time"].max()),
        "wls_time_min": int(wls["time"].min()),
        "wls_time_max": int(wls["time"].max()),
        "finite_netflow_numeric": bool(net[["time", "duration", "src_packets", "dst_packets", "src_bytes", "dst_bytes"]].notna().all().all()),
        "synthetic_labels_present": False,
        "reference_kind": "independent_enterprise_benign_operational_reference",
    }
    if not quality["finite_netflow_numeric"]:
        raise SystemExit("LANL reference gate: non-finite required network fields")
    if not port_counts:
        raise SystemExit("LANL reference gate: no configured remote-admin ports survived filtering")
    (args.out / "reference_quality.json").write_text(json.dumps(quality, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    manifest = {
        "schema_version": 2,
        "dataset": lanl["dataset"],
        "year": int(lanl["year"]),
        "origin": lanl["origin"],
        "origin_page": lanl["origin_page"],
        "transport": lanl["transport"],
        "mirror_page": lanl["mirror_page"],
        "mirror_transforms": list(lanl.get("mirror_transforms", [])),
        "citation": "Melissa J. M. Turcotte, Alexander D. Kent, Curtis Hash, Unified Host and Network Data Set, 2018",
        "remote_admin_ports": sorted(ports),
        "netflow": net_meta,
        "windows_auth_events": wls_meta,
        "external_only": True,
        "used_for_training": False,
        "used_for_threshold_tuning": False,
        "provenance_note": "Rocketgraph is transport/mirror only; dataset lineage remains LANL Unified Host and Network Data Set 2017",
    }
    (args.out / "source_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"quality": quality, "manifest": manifest}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
