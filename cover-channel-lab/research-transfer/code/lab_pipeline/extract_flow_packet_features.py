#!/usr/bin/env python3
"""Lab per-FLOW rows at the packet-level tier (112 features).

The unit has to match the office side or the comparison is meaningless.

`extract_lab_features.py` emits one row per session: for a tunnel session that
is effectively the tunnel flow, but for a benign session it aggregates every
flow in the capture into a single row — dozens of concurrent TLS connections
collapsed into one. The office collector, like a real NGFW, emits one row per
flow. Training one against the other compares a session to a connection.

So this splits lab captures into flows the way `extract_flow_features.py` does
(same tunnel-flow matching on the recorded outer_dst, same dropping of a tunnel
session's non-tunnel flows) but computes the full 112-feature vector on each
flow's own packets instead of the 16 flow counters.
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
from lab_pipeline.extract_flow_features import iter_raw_metadata  # noqa: E402
from lab_pipeline.extract_lab_features import (  # noqa: E402
    features_from_packets,
    infer_client,
    read_pcap_packets,
)
from lab_pipeline.schema import MODEL_FEATURE_NAMES  # noqa: E402

DEFAULT_SOURCES = "wsl_tunnel_lab_v3,wsl_tunnel_lab"
CONTEXT_COLUMNS = [
    "session_id", "campaign_id", "label_family", "label_binary",
    "workload", "netem_profile", "stack_variant", "y",
]


def split_flows(pkts: list[dict[str, Any]]) -> dict[tuple, list[dict[str, Any]]]:
    flows: dict[tuple, list[dict[str, Any]]] = {}
    for p in pkts:
        a = (p["src"], p["sport"])
        b = (p["dst"], p["dport"])
        key = (a, b, p["proto"]) if a <= b else (b, a, p["proto"])
        flows.setdefault(key, []).append(p)
    return flows


def rows_for_session(meta: dict[str, Any], pcap: Path, min_packets: int) -> list[dict[str, Any]]:
    pkts = read_pcap_packets(pcap)
    if not pkts:
        return []
    client = infer_client(pkts, meta)
    is_tunnel = meta.get("label_binary") == "tunnel"
    srv_ip = str(meta.get("outer_dst") or "")
    srv_port = int(meta.get("outer_dst_port") or 0)

    out: list[dict[str, Any]] = []
    for _key, fp in split_flows(pkts).items():
        if len(fp) < min_packets:
            continue
        peer = None
        for p in fp:
            if p["src"] == client:
                peer = (p["dst"], p["dport"])
                break
            if p["dst"] == client:
                peer = (p["src"], p["sport"])
                break
        peer = peer or (fp[0]["dst"], fp[0]["dport"])
        is_tunnel_flow = bool(srv_ip) and peer[0] == srv_ip and (not srv_port or peer[1] == srv_port)
        if is_tunnel and not is_tunnel_flow:
            continue  # a tunnel session's side traffic is not a positive
        if not is_tunnel and is_tunnel_flow:
            continue  # QC rejects these; skip rather than mislabel

        row = features_from_packets(fp, {"outer_src": client})
        row = {k: row.get(k, 0.0) for k in MODEL_FEATURE_NAMES}
        row["session_id"] = meta.get("session_id") or pcap.stem
        row["campaign_id"] = meta.get("campaign_id") or ""
        row["label_family"] = meta.get("label_family") or ""
        row["label_binary"] = meta.get("label_binary") or ""
        row["workload"] = meta.get("workload") or ""
        row["netem_profile"] = meta.get("netem_profile") or ""
        row["stack_variant"] = meta.get("stack_variant") or ""
        row["y"] = 1 if is_tunnel else 0
        out.append(row)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--metadata-dir", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--sources", default=DEFAULT_SOURCES)
    ap.add_argument("--min-packets", type=int, default=4)
    args = ap.parse_args()

    pairs = iter_raw_metadata(Path(args.metadata_dir), args.sources)
    cols = list(MODEL_FEATURE_NAMES) + CONTEXT_COLUMNS
    n_tunnel = n_benign = 0
    out = Path(args.out_csv)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        for meta, pcap in pairs:
            for row in rows_for_session(meta, pcap, args.min_packets):
                writer.writerow(row)
                if row["y"] == 1:
                    n_tunnel += 1
                else:
                    n_benign += 1

    print(json.dumps({
        "rows": n_tunnel + n_benign,
        "tunnel_flows": n_tunnel,
        "benign_flows": n_benign,
        "tier": "packet_level_112",
        "csv": str(out),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
