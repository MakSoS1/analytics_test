#!/usr/bin/env python3
"""Contract for the second detector level: host behaviour over 20 minutes.

Separate from fast-v1 on purpose. The fast model answers "is this connection a
tunnel" from its first packets; this one answers "does this host behave like it
is running a tunnel" from twenty minutes of activity. Different unit, different
denominator, different alert budget — a flow FPR of 1e-4 cannot be carried over
to overlapping host windows.

Window semantics:

    trailing 20 minutes, recomputed once a minute, held as 20 one-minute bins
    per host key. Memory is hosts x 20 bins and nothing else.

A window that does not yet have 20 bins is `warmup` or `partial`; it is never
padded to look like a full one. The 20-minute length comes from the user's
operational experience, and its usefulness for VPN detection is still to be
demonstrated — it is a starting point, not a validated constant.

Input must include flows the fast model did NOT flag. Feeding this level only
fast hits makes it blind to exactly the misses it exists to catch.

The host key is a local pseudonym used for grouping. It never enters the model
vector, and neither does any address.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

HOST_SCHEMA_VERSION = "host20-v1"

WINDOW_SECONDS = 20 * 60
BIN_SECONDS = 60
N_BINS = WINDOW_SECONDS // BIN_SECONDS
# Kept, and no longer the completeness rule.
#
# It used to be: a window is `full` when at least this many of its bins contain
# a flow. Measured over 21-minute lab captures, that was unmeetable by the
# traffic this level targets — httptunnel started 371 flows inside 10 minutes,
# and 18 sessions yielded one full window, benign. A tunnel comes up in a burst
# and then lives inside long flows that start nothing new, so its quiet minutes
# are the signal. Completeness now asks whether the host was already being
# observed at the window's oldest minute; see HostWindowTable.window.
#
# The constant remains as the floor for calling a window's activity dense enough
# to describe, and because it is part of the published host20 contract.
MIN_BINS_FOR_FULL = N_BINS

WINDOW_STATUS = ("warmup", "partial", "full")

HOST_FEATURES: tuple[str, ...] = (
    # volume and shape
    "flows_started", "flows_completed", "bytes_up", "bytes_down",
    "up_down_bytes_ratio", "mean_flow_bytes", "max_flow_bytes",
    # persistence: what a tunnel looks like over time
    "active_flow_max", "active_flow_mean", "long_flow_count",
    "flow_duration_mean", "flow_duration_max",
    # churn and reconnection
    "distinct_peers", "reconnect_count", "flow_start_rate_std",
    # idleness and keepalive
    "idle_bins", "keepalive_like_flows", "small_flow_ratio",
    # what the fast level thought, including the flows it did not flag
    "fast_scored_flows", "fast_flagged_flows", "fast_score_mean",
    "fast_score_max", "fast_score_p90",
    # honesty about the window itself
    "bins_present", "missing_bin_ratio", "partial_flow_ratio",
)

FORBIDDEN_HOST_FEATURES = frozenset({
    "host_key", "src_ip", "dst_ip", "peer_ip", "hostname", "sensor_id",
})


def contract_hash() -> str:
    payload = json.dumps({
        "schema_version": HOST_SCHEMA_VERSION,
        "window_seconds": WINDOW_SECONDS,
        "bin_seconds": BIN_SECONDS,
        "features": list(HOST_FEATURES),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def validate_host_vector(row: dict[str, Any]) -> None:
    leaked = FORBIDDEN_HOST_FEATURES & set(row)
    if leaked:
        raise ValueError(f"identity fields must not reach the host model: {sorted(leaked)}")
    missing = [n for n in HOST_FEATURES if n not in row]
    if missing:
        raise ValueError(f"missing {len(missing)} host features, first few: {missing[:5]}")
    for name in HOST_FEATURES:
        v = row[name]
        if not isinstance(v, (int, float)) or v != v or v in (float("inf"), float("-inf")):
            raise ValueError(f"host feature {name} is not finite: {v!r}")


def describe() -> dict[str, Any]:
    return {
        "schema_version": HOST_SCHEMA_VERSION,
        "contract_hash": contract_hash(),
        "window_seconds": WINDOW_SECONDS,
        "bin_seconds": BIN_SECONDS,
        "n_bins": N_BINS,
        "n_features": len(HOST_FEATURES),
        "window_status": list(WINDOW_STATUS),
        "note": "flow-level FPR budgets do not transfer to overlapping host windows",
    }


if __name__ == "__main__":
    print(json.dumps(describe(), indent=2))


# The columns a host-window CSV carries, named once.
#
# The builder wrote `y` and `window_end_ts`; the trainer read `label` and
# `window_end`. Both were internally consistent and they never met, so the
# trainer reported 13 windows and `labelled: 0` — a refusal that looked like
# "not enough data" and was really "we do not speak the same names". Naming the
# contract here is what stops the two drifting apart again.
HOST_WINDOW_CONTEXT = (
    "session_id", "campaign_id", "label_family", "label_binary",
    "workload", "netem_profile", "host_key", "window_end",
    "active_bins", "scorable", "window_status", "label",
)
HOST_LABEL_COLUMN = "label"
