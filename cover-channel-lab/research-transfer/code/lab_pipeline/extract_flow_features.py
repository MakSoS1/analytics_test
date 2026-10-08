#!/usr/bin/env python3
"""Per-flow features from lab pcaps, in the tier an NGFW can export.

`extract_lab_features.py` treats one pcap as one row. That is the wrong unit for
measuring FPR: an NGFW decides per flow, and a benign lab session is dozens of
concurrent TLS flows, not one. This splits each capture into flows and labels:

  y=1  the outer tunnel flow of a tunnel session (matched on the recorded
       outer_dst/outer_dst_port), so the positive is the flow a sensor would see
  y=0  every flow of a benign session

Flows of a tunnel session other than the tunnel itself are dropped: they are
side traffic with no trustworthy ground truth. DNS is already filtered by the
shared packet parser.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
from lab_pipeline.extract_lab_features import (  # noqa: E402
    infer_client,
    load_lab_metadata,
    read_pcap_packets,
    source_allowed,
)
from lab_pipeline.flow_tier import FLOW_TIER_FEATURES, flow_features  # noqa: E402

META_COLUMNS = ["session_id", "campaign_id", "label_family", "workload", "netem_profile", "y"]


def flows_from_packets(pkts: list[dict[str, Any]], client: str) -> dict[tuple, dict[str, Any]]:
    flows: dict[tuple, dict[str, Any]] = {}
    for p in pkts:
        a = (p["src"], p["sport"])
        b = (p["dst"], p["dport"])
        key = (a, b, p["proto"]) if a <= b else (b, a, p["proto"])
        f = flows.get(key)
        if f is None:
            f = flows[key] = {
                "up_pkts": 0, "down_pkts": 0, "up_bytes": 0, "down_bytes": 0,
                "t0": p["ts"], "t1": p["ts"], "proto": p["proto"],
                "peer": None,
            }
        upward = p["src"] == client
        if upward:
            f["up_pkts"] += 1
            f["up_bytes"] += p["length"]
            f["peer"] = (p["dst"], p["dport"])
        else:
            f["down_pkts"] += 1
            f["down_bytes"] += p["length"]
            if f["peer"] is None:
                f["peer"] = (p["src"], p["sport"])
        f["t1"] = max(f["t1"], p["ts"])
        f["t0"] = min(f["t0"], p["ts"])
    return flows


def rows_for_session(meta: dict[str, Any], pcap: Path) -> list[dict[str, Any]]:
    pkts = read_pcap_packets(pcap)
    if not pkts:
        return []
    client = infer_client(pkts, meta)
    is_tunnel = meta.get("label_binary") == "tunnel"
    srv_ip = str(meta.get("outer_dst") or "")
    srv_port = int(meta.get("outer_dst_port") or 0)
    out: list[dict[str, Any]] = []
    for _key, f in flows_from_packets(pkts, client).items():
        peer = f["peer"] or ("", 0)
        is_tunnel_flow = bool(srv_ip) and peer[0] == srv_ip and (not srv_port or peer[1] == srv_port)
        if is_tunnel and not is_tunnel_flow:
            continue
        if not is_tunnel and is_tunnel_flow:
            # QC already rejects these; skip rather than mislabel.
            continue
        row = flow_features(
            f["up_pkts"], f["down_pkts"], f["up_bytes"], f["down_bytes"],
            f["t1"] - f["t0"], f["proto"],
        )
        row["session_id"] = meta.get("session_id") or pcap.stem
        row["campaign_id"] = meta.get("campaign_id") or ""
        row["label_family"] = meta.get("label_family") or ""
        row["workload"] = meta.get("workload") or ""
        row["netem_profile"] = meta.get("netem_profile") or ""
        row["y"] = 1 if is_tunnel else 0
        out.append(row)
    return out


def iter_raw_metadata(metadata_dir: Path, source_filter: str) -> list[tuple[dict[str, Any], Path]]:
    """Session metadata as written, paired with its pcap.

    Deliberately NOT `iter_lab_sessions`: that one returns already-extracted
    packet-level feature rows, which drop `outer_dst`/`outer_dst_port` — the
    fields this module needs to tell the tunnel flow from side traffic. Using it
    silently labelled every tunnel session as "no tunnel flow found" and emitted
    a benign-only dataset.
    """
    out: list[tuple[dict[str, Any], Path]] = []
    for fp in sorted(metadata_dir.glob("*.json")):
        try:
            meta = load_lab_metadata(fp)
        except (json.JSONDecodeError, OSError):
            continue
        if not source_allowed(str(meta.get("capture_source") or ""), source_filter):
            continue
        pcap = Path(str(meta.get("pcap") or ""))
        if not pcap.is_file():
            alt = metadata_dir.parent / "pcaps" / (fp.stem + ".pcap")
            pcap = alt if alt.is_file() else pcap
        if not pcap.is_file():
            continue
        out.append((meta, pcap))
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--metadata-dir", default="/opt/tunnel_lab/metadata")
    p.add_argument("--out-csv", default="/opt/tunnel_lab/features/lab_flow_features.csv")
    p.add_argument("--source-filter", default="wsl_tunnel_lab_v3,wsl_tunnel_lab")
    args = p.parse_args()

    rows: list[dict[str, Any]] = []
    for meta, pcap in iter_raw_metadata(Path(args.metadata_dir), args.source_filter):
        rows.extend(rows_for_session(meta, pcap))

    out = Path(args.out_csv)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FLOW_TIER_FEATURES + META_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    print(json.dumps({
        "rows": len(rows),
        "tunnel_flows": sum(1 for r in rows if r["y"] == 1),
        "benign_flows": sum(1 for r in rows if r["y"] == 0),
        "csv": str(out),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
