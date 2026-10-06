#!/usr/bin/env python3
"""Turn lab captures into host20 windows — the step that did not exist.

`host_windows.py` is a library and `train_host_detector.py` needs a
`--windows-csv`. Nothing produced that file, so "the host20 code is written" was
true and still left no path from a capture to a trained model. This is that
path.

What it does per capture: replay the packets through the SAME fast-v1 reducer
the sensor runs, turn each flow decision into a `FlowEvent`, feed those to
`HostWindowTable`, and emit the windows it reports as `full`.

Three decisions worth stating, because each could quietly inflate the result.

**Only `full` windows are written.** A window without its twenty bins is
`warmup` or `partial` and is never padded to look complete. A 21-minute capture
yields one full window, which is why the host level needs a collection campaign
rather than a re-extraction.

**Windows do not overlap.** The table can report a sliding window every minute;
twenty of those from one 21-minute capture share nineteen bins and are not
twenty independent observations. Emitting them would repeat, at host scale,
exactly the defect that made 492 961 flow rows look like independent decisions.

**The fast score comes from the model, or not at all.** `--fast-model` feeds
each flow decision through a real bundle so the host features that depend on
fast hits mean something. Without it those features stay at zero and the emitted
rows say so, rather than implying the fast tier saw nothing.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from lab_pipeline.extract_fastv1_features import (  # noqa: E402
    EXCLUDED_SESSIONS,
    CaptureCutShort,
    is_usable_capture,
    span_is_complete,
    SWEEP_INTERVAL_S,
    _flow_key,
    iter_raw_metadata,
)
from lab_pipeline.extract_lab_features import iter_pcap_packets  # noqa: E402
from lab_pipeline.flow_observation import ObservationTable, Packet  # noqa: E402
from lab_pipeline.host_schema import (  # noqa: E402
    HOST_FEATURES,
    HOST_LABEL_COLUMN,
    HOST_WINDOW_CONTEXT,
    WINDOW_SECONDS,
)
from lab_pipeline.host_windows import FlowEvent, HostWindowTable  # noqa: E402
from lab_pipeline.online_schema import FEATURE_NAMES, in_scope  # noqa: E402

# Named in host_schema so the builder and the trainer cannot drift apart: they
# already had, silently, on `y` versus `label`.
CONTEXT_COLUMNS = list(HOST_WINDOW_CONTEXT)


def _pseudonym(salt: str, value: str) -> str:
    return hashlib.sha256(f"{salt}|{value}".encode()).hexdigest()[:16]


def windows_for_session(meta: dict[str, Any], pcap: Path, bundle: Any,
                        salt: str) -> list[dict[str, Any]]:
    is_tunnel = str(meta.get("label_binary") or "") == "tunnel"
    srv_ip = str(meta.get("outer_dst") or "")
    srv_port = int(meta.get("outer_dst_port") or 0)

    table = ObservationTable()
    host_table = HostWindowTable()
    initiators: dict[str, tuple[str, int]] = {}
    peers: dict[str, tuple[str, int]] = {}
    totals: dict[str, list[int]] = {}
    starts: dict[str, float] = {}

    pkts = list(iter_pcap_packets(pcap))
    if not pkts:
        return []
    # Captures taken before the size cap was fixed carry no marker and are still
    # cut short: at this level a missing minute reads as a quiet one.
    if not span_is_complete(pkts[0]["ts"], pkts[-1]["ts"], meta)[0]:
        raise CaptureCutShort("span under the declared duration")

    def emit(rec: dict[str, Any], key: str) -> None:
        peer = peers.get(key, ("", 0))
        if not in_scope(int(initiators.get(key, ("", 0))[1] or 0), int(peer[1] or 0)):
            return
        up, down = totals.get(key, [0, 0])
        score = None
        flagged = False
        if bundle is not None:
            score = bundle.score({n: rec["features"].get(n, 0.0) for n in FEATURE_NAMES})
            flagged = score >= bundle.threshold
        host_table.add(FlowEvent(
            ts=float(rec["decision_ts"]),
            # The client is the host under observation. Pseudonymised per run:
            # an address must not reach the model or the CSV.
            host_key=_pseudonym(salt, initiators.get(key, ("", 0))[0]),
            peer_id=_pseudonym(salt, f"{peer[0]}:{peer[1]}"),
            bytes_up=up, bytes_down=down,
            duration=float(rec["features"].get("observed_duration") or 0.0),
            fast_score=score, fast_flagged=flagged,
            partial=not rec["start_observed"], completed=True,
        ))

    next_sweep = None
    for p in pkts:
        if next_sweep is None:
            next_sweep = p["ts"] + SWEEP_INTERVAL_S
        elif p["ts"] >= next_sweep:
            for rec in table.sweep(p["ts"]):
                emit(rec, rec["flow_instance_id"].rsplit("#", 1)[0])
            next_sweep = p["ts"] + SWEEP_INTERVAL_S
        key = _flow_key(p)
        if key not in initiators:
            initiators[key] = (p["src"], p["sport"])
            peers[key] = (p["dst"], p["dport"])
            totals[key] = [0, 0]
            starts[key] = p["ts"]
        ini = initiators[key]
        up = (p["src"], p["sport"]) == ini
        totals[key][0 if up else 1] += int(p["length"])
        flags = str(p.get("flags") or "")
        rec = table.observe(key, Packet(
            ts=p["ts"], length=p["length"], from_initiator=up,
            syn=("S" in flags and "." not in flags),
            fin=("F" in flags), rst=("R" in flags),
            is_udp=(p["proto"] == "udp"),
        ))
        if rec is not None:
            emit(rec, key)
    for rec in table.sweep(pkts[-1]["ts"] + 3600):
        emit(rec, rec["flow_instance_id"].rsplit("#", 1)[0])

    # One window per host, taken at the end of the capture. Sliding windows from
    # one capture overlap by nineteen of their twenty bins; treating those as
    # independent is the host-scale version of the repeated-observation defect.
    out: list[dict[str, Any]] = []
    end = pkts[-1]["ts"]
    for w in host_table.windows(end):
        # `window_status`, not `status`: the record names it that, and a
        # `.get("status")` that is always None would have written every window.
        if w.get("window_status") != "full":
            continue
        row = {n: w["features"].get(n, 0.0) for n in HOST_FEATURES}
        row["session_id"] = meta.get("session_id") or pcap.stem
        row["campaign_id"] = meta.get("campaign_id") or ""
        row["label_family"] = meta.get("label_family") or ""
        row["label_binary"] = meta.get("label_binary") or ""
        row["workload"] = meta.get("workload") or ""
        row["netem_profile"] = meta.get("netem_profile") or ""
        row["host_key"] = w["host_key"]
        row["window_end"] = round(float(w.get("window_end", end)), 6)
        row["active_bins"] = w.get("active_bins", 0)
        row["scorable"] = 1 if w.get("scorable") else 0
        row["window_status"] = w["window_status"]
        row[HOST_LABEL_COLUMN] = 1 if is_tunnel else 0
        out.append(row)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--metadata-dir", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--sources", default="wsl_tunnel_lab_v3,wsl_tunnel_lab")
    ap.add_argument("--fast-model", default=None,
                    help="score each flow with this bundle; without it the "
                         "fast-hit features stay zero and the report says so")
    ap.add_argument("--salt", default="host20-v1")
    args = ap.parse_args()

    bundle = None
    if args.fast_model:
        from lab_pipeline.model_bundle import ModelBundle

        bundle = ModelBundle.load(args.fast_model)

    cols = list(HOST_FEATURES) + CONTEXT_COLUMNS
    out = Path(args.out_csv)
    out.parent.mkdir(parents=True, exist_ok=True)
    counts = {"sessions": 0, "excluded": 0, "truncated": 0, "windows": 0,
              "tunnel": 0, "benign": 0, "sessions_without_a_full_window": 0}
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        for meta, pcap in iter_raw_metadata(Path(args.metadata_dir), args.sources):
            sid = str(meta.get("session_id") or pcap.stem)
            if sid in EXCLUDED_SESSIONS:
                counts["excluded"] += 1
                continue
            # A capture cut short by the size cap has missing minutes, and this
            # level reads a missing minute as a quiet one.
            if not is_usable_capture(meta)[0]:
                counts["truncated"] += 1
                continue
            counts["sessions"] += 1
            try:
                rows = windows_for_session(meta, pcap, bundle, args.salt)
            except CaptureCutShort:
                counts["truncated"] += 1
                continue
            if not rows:
                counts["sessions_without_a_full_window"] += 1
            for row in rows:
                writer.writerow(row)
                counts["windows"] += 1
                counts["tunnel" if row[HOST_LABEL_COLUMN] == 1 else "benign"] += 1

    print(json.dumps({
        "window_seconds": WINDOW_SECONDS,
        "fast_scores": bool(bundle),
        "note": ("only `full` windows are written, one per host per capture; "
                 "sliding windows from one capture are not independent"),
        **counts,
        "csv": str(out),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
