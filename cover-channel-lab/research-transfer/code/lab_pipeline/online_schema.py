#!/usr/bin/env python3
"""Feature contract for the fast per-flow detector, versioned and hashable.

Why a new schema instead of reusing `schema.py`. The 112-feature vector is 80
sequence features plus 32 aggregates, and the aggregates were computed over
whatever the capture happened to contain: a whole lab session pcap on one side,
the tail of a 15-second office capture on the other. Two different observation
windows, one feature name list. Equal names are not parity.

fast-v1 fixes the window instead of the field list. Every feature — sequence and
aggregate alike — is computed over exactly the same bounded prefix:

    the first MAX_PACKETS packets, or MAX_SECONDS from the first packet,
    or the close of the flow, whichever happens first.

`schema.py` stays untouched as the legacy session-level contract. Anything
trained on it keeps working; nothing new should use it for online decisions.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

SCHEMA_VERSION = "fast-v1"

# Decision horizon. These are a starting proposal to be compared against
# 5/10/20/50/100 packets and 1/5/15/30 seconds on validation, then frozen —
# not an already-demonstrated optimum.
MAX_PACKETS = 20
MAX_SECONDS = 5.0
# Three, not four, and the reason is a measurement rather than a preference.
# Every vanilla WireGuard session in the lab opens with the same three frames —
# 190, 134, 74: handshake initiation, handshake response, first keepalive — and
# then goes quiet for ten to thirty seconds before any workload starts. At a
# floor of four, 203 of 210 sessions were returned as `insufficient_data`: the
# fast tier structurally could not decide on the one family whose opening is
# most distinctive. At three it decides on 206 of 210, and no other tunnel
# family moves at all, because every one of them already had four or more
# packets inside the window. Lab benign gains 2-3%.
#
# Three is also the smallest floor that still carries a direction change, so the
# vector is a real exchange and not one packet plus a reply.
MIN_PACKETS = 3  # below this the flow is reported as insufficient_data, not benign

# A flow INSTANCE ends after this much silence; the next packet on the same
# 4-tuple starts a new one. Without it the offline side grouped a whole capture
# by 5-tuple while Suricata closed and reopened flows on its own timeouts: the
# same pcap gave 44 records offline against 321 through the Lua exporter.
#
# These MUST equal what the sensor runs. A single 30 s value was a guess and it
# split too eagerly (427 offline against 321). Suricata distinguishes a flow that
# has only been seen in one direction ("new") from one carrying traffic both ways
# ("established"), with different timeouts for each and per protocol.
#
# The values below are Suricata's documented defaults. Do not rely on either side
# defaulting to them — pin them explicitly in the sensor's `flow-timeouts` block
# (see detector/sensor/suricata-enp0s4.yaml) so both sides read the same numbers,
# and confirm against the running sensor before quoting parity.
FLOW_TIMEOUTS: dict[str, dict[str, float]] = {
    "tcp": {"new": 60.0, "established": 600.0, "closed": 10.0},
    "udp": {"new": 30.0, "established": 300.0},
    "default": {"new": 30.0, "established": 300.0},
}


def idle_timeout(proto: str, established: bool) -> float:
    """Silence after which this 4-tuple becomes a NEW flow instance."""
    table = FLOW_TIMEOUTS.get(proto.lower(), FLOW_TIMEOUTS["default"])
    return table["established" if established else "new"]

# Unit for packet size. L2 frame length as seen on the wire, excluding FCS —
# the same quantity `tcpdump -e` prints as "length N". An exporter that cannot
# prove it reports this must declare its own unit and be retrained, never
# reconstruct it silently (payload+42/54 was doing exactly that for months).
LENGTH_UNIT = "l2_frame_no_fcs"

# Which flows this detector is asked about at all.
#
# This lived in one private constant inside the office collector, so the three
# components disagreed about what they were looking at: the collector dropped
# DNS from the negatives, the lab extractor kept it, and the Suricata exporter
# scored it. A model that never saw DNS in training was therefore asked about
# DNS in production — out-of-distribution input, and nothing anywhere said so.
#
# No declared family tunnels over DNS, so DNS is out of scope rather than a
# negative. It is part of the contract hash: adding a DNS-based family later
# changes the scope, changes the hash, and forces every corpus and model to be
# re-derived instead of quietly meaning something new.
OUT_OF_SCOPE_PORTS = (53, 5353)


def in_scope(sport: int, dport: int) -> bool:
    """False for traffic the detector is not trained to judge."""
    return not (int(sport) in OUT_OF_SCOPE_PORTS or int(dport) in OUT_OF_SCOPE_PORTS)

AGGREGATE_FEATURES: tuple[str, ...] = (
    "pkt_count", "up_pkt_count", "down_pkt_count",
    "total_bytes", "up_bytes", "down_bytes",
    "observed_duration",
    "up_down_pkt_ratio", "up_down_bytes_ratio",
    "pkt_len_mean", "pkt_len_std", "pkt_len_min", "pkt_len_max",
    "iat_mean", "iat_std", "iat_min", "iat_max",
    "direction_changes", "is_udp", "is_tcp",
    "syn_count", "fin_count", "rst_count",
)

SEQUENCE_PREFIXES: tuple[str, ...] = ("signed_len", "dir", "iat", "mask")

# Never model inputs: they identify the lab or the office, not the tunnel.
FORBIDDEN_FEATURES = frozenset({
    "src_ip", "dst_ip", "src_port", "dst_port", "server_name", "sni",
    "ja3_hash_int", "ja3s_hash_int", "ja4_hash_int", "payload_first_4bytes_int",
    "flow_instance_id", "sensor_epoch", "host_key", "capture_id", "session_id",
})

DECISION_REASONS = ("packet_budget", "time_budget", "flow_closed", "insufficient_data")


def feature_names() -> list[str]:
    names = list(AGGREGATE_FEATURES)
    for i in range(MAX_PACKETS):
        names.extend(f"{p}_{i}" for p in SEQUENCE_PREFIXES)
    return names


FEATURE_NAMES: tuple[str, ...] = tuple(feature_names())


# Bumped whenever the reducer's observable behaviour changes while the constants
# and the feature list stay the same. Parameters alone are not the contract: rev
# 2 fixed a table that re-decided one connection every twenty packets under an
# unchanged flow_instance_id, and a horizon that pulled in the packet which
# revealed the deadline (t = 0, 1, 2, 8 reported observed_duration = 8 against a
# five-second window). Same names, same numbers, different vectors — so without
# this the hash would have let a model trained on the old rows load against the
# fixed sensor. Rev 3 lowered MIN_PACKETS from 4 to 3; that one does move a
# constant, but the revision is what makes the change legible in the hash's
# history.
REDUCER_REVISION = 3


def contract_hash() -> str:
    """Identity of the whole contract, not just the name list.

    Covers the horizon, the minimum, the length unit, the ordered feature names
    and the reducer revision, so a sensor that changes any of them stops matching
    the model.
    """
    payload = json.dumps({
        "schema_version": SCHEMA_VERSION,
        "max_packets": MAX_PACKETS,
        "max_seconds": MAX_SECONDS,
        "min_packets": MIN_PACKETS,
        "flow_timeouts": FLOW_TIMEOUTS,
        "length_unit": LENGTH_UNIT,
        "out_of_scope_ports": list(OUT_OF_SCOPE_PORTS),
        "reducer_revision": REDUCER_REVISION,
        "features": list(FEATURE_NAMES),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def validate_vector(row: dict[str, Any]) -> None:
    """Reject anything the model must not be asked to score.

    A missing field is an error, never a silent zero: padding is only legitimate
    where the mask says the packet slot was never filled.
    """
    leaked = FORBIDDEN_FEATURES & set(row)
    if leaked:
        raise ValueError(f"forbidden identity features in vector: {sorted(leaked)}")
    missing = [n for n in FEATURE_NAMES if n not in row]
    if missing:
        raise ValueError(f"missing {len(missing)} features, first few: {missing[:5]}")
    for name in FEATURE_NAMES:
        v = row[name]
        if not isinstance(v, (int, float)) or v != v or v in (float("inf"), float("-inf")):
            raise ValueError(f"feature {name} is not a finite number: {v!r}")


def describe() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "contract_hash": contract_hash(),
        "max_packets": MAX_PACKETS,
        "max_seconds": MAX_SECONDS,
        "min_packets": MIN_PACKETS,
        "flow_timeouts": FLOW_TIMEOUTS,
        "length_unit": LENGTH_UNIT,
        "n_features": len(FEATURE_NAMES),
        "decision_reasons": list(DECISION_REASONS),
    }


if __name__ == "__main__":
    print(json.dumps(describe(), indent=2))
