#!/usr/bin/env python3
"""Offline fast-v1 features from lab pcaps, using the SAME reducer as the sensor.

Closes the training loop for the online contract. Everything trained so far used
the legacy 112-feature session schema, whose aggregates covered whatever the
capture happened to contain; a model built from it cannot be loaded by
`model_bundle` in strict mode, and should not be, because the sensor computes
something else.

This produces rows a fast-v1 model can be trained on: the packets of each lab
capture are fed through `flow_observation.ObservationTable` — the identical
object the live path uses — so an offline row and an online row are the same
computation over the same bounded prefix, not two implementations that happen to
share column names.

Labelling follows `extract_flow_packet_features.py`: for a tunnel session only
the outer tunnel flow is positive, and a benign session contributes every flow.
Rows that the contract marks unscorable (mid-stream join, too few packets) are
written with `scorable=0` and a reason, so training can exclude them explicitly
rather than by accident.
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
from lab_pipeline.extract_flow_features import iter_raw_metadata  # noqa: E402
from lab_pipeline.extract_lab_features import infer_client, read_pcap_packets  # noqa: E402
from lab_pipeline.flow_observation import ObservationTable, Packet  # noqa: E402
from lab_pipeline.online_schema import in_scope, FEATURE_NAMES, SCHEMA_VERSION, contract_hash  # noqa: E402
from lab_pipeline.route_contract import classify_route  # noqa: E402

DEFAULT_SOURCES = "wsl_tunnel_lab_v3,wsl_tunnel_lab"


def pseudonym(flow_instance_id: str) -> str:
    """The flow key is addresses and ports; only a token may leave this function."""
    return hashlib.sha256(flow_instance_id.encode()).hexdigest()[:20]


# Matches sensor/collect_office_fastv1.py: both paths retire flow state on the
# capture clock, at the same interval, or they draw instance boundaries
# differently on a long flow.
SWEEP_INTERVAL_S = 10.0

# Captures whose payload contradicts their label — 22 of them, from the audit of
# 2026-09-11. The exclusion was agreed there and then never applied: a month
# later one of them still contributed 47 rows to the training corpus. Reading
# the manifest here is what makes the decision take effect, and a missing
# manifest is an error rather than an empty set, because an exclusion that
# silently stops happening is the original failure.
EXCLUSIONS_PATH = Path(__file__).resolve().parent / "excluded_sessions.json"


def load_exclusions(path: Path = EXCLUSIONS_PATH) -> frozenset[str]:
    return frozenset(json.loads(path.read_text())["sessions"])


EXCLUDED_SESSIONS = load_exclusions()


class CaptureCutShort(RuntimeError):
    """The capture does not contain the span it declares."""


def is_usable_capture(meta: dict[str, Any]) -> tuple[bool, str]:
    """False for a capture that does not contain the span it claims.

    The lab's per-capture size cap was six megabytes, sized for 45-150 second
    sessions. On 1260-second captures it stopped tcpdump at minute nine of
    twenty-one while the metadata still said 1276 seconds. Those missing minutes
    are not quiet minutes, and nothing downstream can tell the difference —
    least of all the host level, which reads a quiet minute as "this host
    started no flows".
    """
    flag = meta.get("pcap_truncated")
    if isinstance(flag, str):
        flag = flag.strip().lower() in ("true", "1", "yes")
    if flag:
        return False, "pcap_truncated: the capture was cut short by the size cap"
    return True, ""


# A capture is expected to span most of the duration it declares. Below this
# fraction it is treated as cut short even without a marker.
#
# The marker only exists on captures taken after the size cap was fixed. The
# ones taken before it carry no marker and are still truncated: measured, they
# sit at exactly 6.0 MB and 12 minutes against a declared 21. Trusting the
# marker alone would let precisely the damaged captures through, because being
# damaged is what stopped them being marked.
MIN_SPAN_FRACTION = 0.6


def span_is_complete(first_ts: float, last_ts: float, meta: dict[str, Any],
                     min_fraction: float = MIN_SPAN_FRACTION) -> tuple[bool, str]:
    """Does the capture contain most of the time it claims to cover?"""
    planned = float(meta.get("planned_duration_s") or 0)
    if planned <= 0:
        return True, ""
    span = max(0.0, float(last_ts) - float(first_ts))
    if span >= planned * min_fraction:
        return True, ""
    return False, (f"span {span:.0f}s is under {min_fraction:.0%} of the declared "
                   f"{planned:.0f}s; the capture was cut short")

CONTEXT_COLUMNS = [
    "session_id", "campaign_id", "label_family", "label_binary",
    "workload", "netem_profile", "stack_variant", "benign_path",
    # Which client produced a benign twin. `iat_3` measures the gap between the
    # ACK and the first payload, which is the client's turnaround, so a corpus
    # that cannot say whether a row came from curl or from a compiled client
    # cannot be audited for that shortcut at all.
    "benign_client",
    "flow_instance_id", "decision_reason", "start_observed", "scorable", "y",
    # The route the RUNTIME router would choose for this flow, decided here by
    # the very same `classify_route`. Training used to pick a route from the
    # family label, which the sensor does not have: every TCP family declared
    # opaque_outer trained into a model that the router never sends TCP to.
    #
    # The route, not the 5-tuple: the router only needs the transport and
    # whether a port is DNS, and the ports themselves are identity that
    # `test_identity_never_reaches_the_row` rightly keeps out of this table.
    "router_route",
    # Seconds from the first packet of the capture to the moment this flow was
    # decided. Session recall says a tunnel was caught; this says when. A session
    # first flagged on its 400th flow, minutes in, is not the same product as one
    # flagged on its opening handshake, and nothing in the report distinguished
    # them.
    "decision_offset_s",
]


def _flow_key(p: dict[str, Any]) -> str:
    a, b = (p["src"], p["sport"]), (p["dst"], p["dport"])
    lo, hi = (a, b) if a <= b else (b, a)
    return f"{lo[0]}:{lo[1]}-{hi[0]}:{hi[1]}-{p['proto']}"


def rows_for_session(meta: dict[str, Any], pcap: Path) -> list[dict[str, Any]]:
    pkts = read_pcap_packets(pcap)
    if not pkts:
        return []
    pkts.sort(key=lambda p: p["ts"])
    client = infer_client(pkts, meta)
    is_tunnel = meta.get("label_binary") == "tunnel"
    srv_ip = str(meta.get("outer_dst") or "")
    srv_port = int(meta.get("outer_dst_port") or 0)

    table = ObservationTable()
    initiators: dict[str, tuple[str, int]] = {}
    peers: dict[str, tuple[str, int]] = {}
    emitted: list[dict[str, Any]] = []

    # Same clock-driven sweep as the sensor: state is bounded by the flow table,
    # never by how long the capture ran. Lab captures top out at 150 s so this
    # has never been the difference between working and not — but the offline
    # and online paths have to retire flows the same way, or a long session
    # yields different instance boundaries on each side.
    next_sweep = None
    for p in pkts:
        if next_sweep is None:
            next_sweep = p["ts"] + SWEEP_INTERVAL_S
        elif p["ts"] >= next_sweep:
            for rec in table.sweep(p["ts"]):
                rec["_key"] = rec["flow_instance_id"].rsplit("#", 1)[0]
                emitted.append(rec)
            next_sweep = p["ts"] + SWEEP_INTERVAL_S
        key = _flow_key(p)
        if key not in initiators:
            initiators[key] = (p["src"], p["sport"])
            peers[key] = (p["dst"], p["dport"])
        ini = initiators[key]
        flags = str(p.get("flags") or "")
        rec = table.observe(key, Packet(
            ts=p["ts"], length=p["length"],
            from_initiator=(p["src"], p["sport"]) == ini,
            syn=("S" in flags and "." not in flags),
            fin=("F" in flags), rst=("R" in flags),
            is_udp=(p["proto"] == "udp"),
        ))
        if rec is not None:
            rec["_key"] = key
            emitted.append(rec)
    if pkts:
        for rec in table.sweep(pkts[-1]["ts"] + 3600):
            rec["_key"] = rec["flow_instance_id"].rsplit("#", 1)[0]
            emitted.append(rec)

    if pkts:
        complete, why = span_is_complete(pkts[0]["ts"], pkts[-1]["ts"], meta)
        if not complete:
            # Counted by the caller, not swallowed here: a corpus that quietly
            # shrinks is how a rule nobody agreed to becomes permanent.
            raise CaptureCutShort(why)
    capture_t0 = pkts[0]["ts"] if pkts else None
    out: list[dict[str, Any]] = []
    for rec in emitted:
        key = rec.pop("_key")
        peer = peers.get(key, ("", 0))
        is_tunnel_flow = bool(srv_ip) and peer[0] == srv_ip and (not srv_port or peer[1] == srv_port)
        if is_tunnel and not is_tunnel_flow:
            continue                      # side traffic of a tunnel session is not a positive
        if not is_tunnel and is_tunnel_flow:
            # KNOWN DEFECT, measured 2026-09-16: `srv_ip` is this session's own
            # `outer_dst`, and for a benign twin that is the BENIGN server. On
            # the `labserver_*` paths it is a directly visible peer, so this
            # drops the benign session's entire main traffic — one capture
            # contributed 1 row out of 72 flows — and the corpus ends up with
            # almost no lab-server benign traffic, which the model then flags at
            # 86–100%. The pairing key (`capture_cell`) is what should supply
            # the tunnel's address here.
            # See docs/benign_population_blind_spot.md before trusting any FPR.
            continue                      # QC rejects these; skip rather than mislabel

        # One population for training and for scoring: whatever the sensor will
        # not be asked about must not become a negative here either.
        if not in_scope(int(initiators.get(key, ("", 0))[1] or 0), int(peer[1] or 0)):
            continue

        row = {k: rec["features"].get(k, 0.0) for k in FEATURE_NAMES}
        row["session_id"] = meta.get("session_id") or pcap.stem
        row["campaign_id"] = meta.get("campaign_id") or ""
        row["label_family"] = meta.get("label_family") or ""
        row["label_binary"] = meta.get("label_binary") or ""
        row["workload"] = meta.get("workload") or ""
        row["netem_profile"] = meta.get("netem_profile") or ""
        row["stack_variant"] = meta.get("stack_variant") or ""
        row["benign_path"] = meta.get("benign_path") or ""
        row["benign_client"] = meta.get("benign_client") or ""
        row["flow_instance_id"] = pseudonym(rec["flow_instance_id"])
        row["decision_reason"] = rec["decision_reason"]
        row["start_observed"] = 1 if rec["start_observed"] else 0
        row["scorable"] = 1 if rec["scorable"] else 0
        row["y"] = 1 if is_tunnel else 0
        row["decision_offset_s"] = round(max(0.0, float(rec["decision_ts"]) - capture_t0), 6) \
            if capture_t0 is not None and rec.get("decision_ts") is not None else ""
        row["router_route"] = classify_route({
            "proto": key.rsplit("-", 1)[-1],
            "src_port": int(initiators.get(key, ("", 0))[1] or 0),
            "dst_port": int(peer[1] or 0),
        })
        out.append(row)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--metadata-dir", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--sources", default=DEFAULT_SOURCES)
    ap.add_argument("--include-unscorable", action="store_true",
                    help="keep mid-stream and too-short rows (written with scorable=0 either way)")
    args = ap.parse_args()

    pairs = iter_raw_metadata(Path(args.metadata_dir), args.sources)
    cols = list(FEATURE_NAMES) + CONTEXT_COLUMNS
    out = Path(args.out_csv)
    out.parent.mkdir(parents=True, exist_ok=True)

    counts = {"tunnel": 0, "benign": 0, "unscorable_skipped": 0,
              "excluded_sessions": 0, "truncated_captures": 0,
              "truncated_by_span": 0}
    reasons: dict[str, int] = {}
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        for meta, pcap in pairs:
            sid = str(meta.get("session_id") or pcap.stem)
            if sid in EXCLUDED_SESSIONS:
                counts["excluded_sessions"] += 1
                continue
            usable, _why = is_usable_capture(meta)
            if not usable:
                counts["truncated_captures"] += 1
                continue
            try:
                session_rows = rows_for_session(meta, pcap)
            except CaptureCutShort:
                counts["truncated_captures"] += 1
                counts["truncated_by_span"] += 1
                continue
            for row in session_rows:
                reasons[row["decision_reason"]] = reasons.get(row["decision_reason"], 0) + 1
                if not row["scorable"] and not args.include_unscorable:
                    counts["unscorable_skipped"] += 1
                    continue
                writer.writerow(row)
                counts["tunnel" if row["y"] == 1 else "benign"] += 1

    print(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "contract_hash": contract_hash(),
        "rows": counts["tunnel"] + counts["benign"],
        **counts,
        "decision_reasons": reasons,
        "exclusion_manifest": {"path": str(EXCLUSIONS_PATH), "listed": len(EXCLUDED_SESSIONS)},
        "csv": str(out),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
