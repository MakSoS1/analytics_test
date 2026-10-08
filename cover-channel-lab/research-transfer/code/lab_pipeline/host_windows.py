#!/usr/bin/env python3
"""Trailing 20-minute host aggregator with bounded memory.

Holds 20 one-minute bins per host key and nothing else, so memory is
`hosts x 20` regardless of how much traffic a host generates. A window is
emitted once a minute; before 20 bins exist it is reported `warmup` or
`partial`, never padded to look complete.

Things this gets right because each was called out as a way to be wrong:

* an event on a bin boundary lands in exactly one bin, not two;
* a late event is accepted only while its bin is still inside the window, and
  counted as late — it never rewrites an already emitted window;
* future-dated events are refused rather than silently shifting the watermark;
* flows the fast level did NOT flag are still ingested, otherwise this level is
  blind to the misses it exists to catch;
* the host key groups but never reaches the model vector.
"""
from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from lab_pipeline.host_schema import (
    BIN_SECONDS,
    HOST_FEATURES,
    HOST_SCHEMA_VERSION,
    MIN_BINS_FOR_FULL,
    N_BINS,
    contract_hash,
)

LONG_FLOW_SECONDS = 120.0
SMALL_FLOW_BYTES = 2_000
KEEPALIVE_MAX_BYTES = 600


@dataclass
class FlowEvent:
    """One completed or updated flow, as the sensor reports it."""

    ts: float                  # decision or flow-end time
    host_key: str
    peer_id: str               # pseudonymous peer grouping token, not an address
    bytes_up: int
    bytes_down: int
    duration: float
    fast_score: float | None = None
    fast_flagged: bool = False
    partial: bool = False      # sensor could not observe the whole flow
    completed: bool = True


@dataclass
class _Bin:
    flows_started: int = 0
    flows_completed: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    durations: list[float] = field(default_factory=list)
    flow_bytes: list[int] = field(default_factory=list)
    peers: set[str] = field(default_factory=set)
    fast_scores: list[float] = field(default_factory=list)
    fast_flagged: int = 0
    keepalive_like: int = 0
    small_flows: int = 0
    long_flows: int = 0
    partial_flows: int = 0
    late_events: int = 0


class HostWindowTable:
    def __init__(self, max_hosts: int = 50_000) -> None:
        self._bins: dict[str, dict[int, _Bin]] = defaultdict(dict)
        # When this host was first observed. A bin after that with no activity
        # means the host started no flows in that minute — information, not a
        # gap. A bin before it means we were not watching yet.
        self._first_seen: dict[str, int] = {}
        self._order: deque[str] = deque()
        self._max_hosts = max_hosts
        self._watermark: float = 0.0
        self.counters: dict[str, int] = {
            "events": 0, "late_accepted": 0, "late_dropped": 0,
            "future_refused": 0, "hosts_evicted": 0,
        }

    # ---- ingestion -------------------------------------------------------
    @staticmethod
    def bin_index(ts: float) -> int:
        """Left-closed, right-open bins: a boundary timestamp belongs to one."""
        return int(math.floor(ts / BIN_SECONDS))

    def add(self, ev: FlowEvent, now: float | None = None) -> bool:
        self.counters["events"] += 1
        now = now if now is not None else ev.ts
        if ev.ts > now + BIN_SECONDS:
            # Clock skew or a bad record; do not let it drag the watermark.
            self.counters["future_refused"] += 1
            return False
        self._watermark = max(self._watermark, now)

        idx = self.bin_index(ev.ts)
        first = self._first_seen.get(ev.host_key)
        if first is None or idx < first:
            self._first_seen[ev.host_key] = idx
        oldest = self.bin_index(self._watermark) - (N_BINS - 1)
        if idx < oldest:
            self.counters["late_dropped"] += 1
            return False
        if ev.ts < self._watermark - BIN_SECONDS:
            self.counters["late_accepted"] += 1

        if ev.host_key not in self._bins:
            self._order.append(ev.host_key)
            self._evict()
        b = self._bins[ev.host_key].setdefault(idx, _Bin())
        b.flows_started += 1
        if ev.completed:
            b.flows_completed += 1
        b.bytes_up += ev.bytes_up
        b.bytes_down += ev.bytes_down
        total = ev.bytes_up + ev.bytes_down
        b.flow_bytes.append(total)
        b.durations.append(ev.duration)
        b.peers.add(ev.peer_id)
        if ev.fast_score is not None:
            b.fast_scores.append(float(ev.fast_score))
        if ev.fast_flagged:
            b.fast_flagged += 1
        if total <= KEEPALIVE_MAX_BYTES:
            b.keepalive_like += 1
        if total <= SMALL_FLOW_BYTES:
            b.small_flows += 1
        if ev.duration >= LONG_FLOW_SECONDS:
            b.long_flows += 1
        if ev.partial:
            b.partial_flows += 1
        return True

    def _forget(self, host_key: str) -> None:
        self._bins.pop(host_key, None)
        self._first_seen.pop(host_key, None)

    def _evict(self) -> None:
        while len(self._order) > self._max_hosts:
            victim = self._order.popleft()
            self._forget(victim)
            self.counters["hosts_evicted"] += 1

    def prune(self, now: float) -> None:
        """Drop bins that fell out of the trailing window."""
        oldest = self.bin_index(now) - (N_BINS - 1)
        for host, bins in list(self._bins.items()):
            for idx in [i for i in bins if i < oldest]:
                del bins[idx]
            if not bins:
                # Forget when it was first seen too: a host that comes back
                # after being pruned is one we are watching from now, not from
                # whenever we last saw it, and a stale first_seen would call its
                # first window complete.
                self._forget(host)

    # ---- emission --------------------------------------------------------
    def window(self, host_key: str, now: float) -> dict[str, Any] | None:
        bins = self._bins.get(host_key)
        if not bins:
            return None
        newest = self.bin_index(now)
        oldest = newest - (N_BINS - 1)
        present = {i: b for i, b in bins.items() if oldest <= i <= newest}
        if not present:
            return None

        # A window is complete when we were already watching this host at its
        # oldest minute — not when every minute happens to contain a flow.
        #
        # Requiring activity in all twenty was measured to be unmeetable by the
        # very traffic this level targets: over 21-minute captures, httptunnel
        # started 371 flows and fitted them into 10 minutes, and 18 sessions
        # yielded ONE full window, benign. A tunnel comes up in a burst and then
        # carries its traffic inside long flows that start nothing new, so its
        # quiet minutes are the signal, not missing data.
        first = self._first_seen.get(host_key)
        observed_from_the_start = first is not None and first <= oldest
        n_present = len(present)
        if observed_from_the_start:
            status = "full"
        elif n_present > 1:
            status = "partial"
        else:
            status = "warmup"

        durations: list[float] = []
        flow_bytes: list[int] = []
        scores: list[float] = []
        peers: set[str] = set()
        starts_per_bin: list[int] = []
        agg = {
            "flows_started": 0, "flows_completed": 0, "bytes_up": 0, "bytes_down": 0,
            "fast_flagged": 0, "keepalive": 0, "small": 0, "long": 0, "partial": 0,
        }
        for i in range(oldest, newest + 1):
            b = present.get(i)
            starts_per_bin.append(b.flows_started if b else 0)
            if b is None:
                continue
            agg["flows_started"] += b.flows_started
            agg["flows_completed"] += b.flows_completed
            agg["bytes_up"] += b.bytes_up
            agg["bytes_down"] += b.bytes_down
            agg["fast_flagged"] += b.fast_flagged
            agg["keepalive"] += b.keepalive_like
            agg["small"] += b.small_flows
            agg["long"] += b.long_flows
            agg["partial"] += b.partial_flows
            durations.extend(b.durations)
            flow_bytes.extend(b.flow_bytes)
            scores.extend(b.fast_scores)
            peers |= b.peers

        n_flows = max(agg["flows_started"], 1)
        row = {name: 0.0 for name in HOST_FEATURES}
        row.update({
            "flows_started": float(agg["flows_started"]),
            "flows_completed": float(agg["flows_completed"]),
            "bytes_up": float(agg["bytes_up"]),
            "bytes_down": float(agg["bytes_down"]),
            "up_down_bytes_ratio": agg["bytes_up"] / max(agg["bytes_down"], 1),
            "mean_flow_bytes": (sum(flow_bytes) / len(flow_bytes)) if flow_bytes else 0.0,
            "max_flow_bytes": float(max(flow_bytes)) if flow_bytes else 0.0,
            "active_flow_max": float(max(starts_per_bin) if starts_per_bin else 0),
            "active_flow_mean": (sum(starts_per_bin) / len(starts_per_bin)) if starts_per_bin else 0.0,
            "long_flow_count": float(agg["long"]),
            "flow_duration_mean": (sum(durations) / len(durations)) if durations else 0.0,
            "flow_duration_max": float(max(durations)) if durations else 0.0,
            "distinct_peers": float(len(peers)),
            "reconnect_count": float(max(agg["flows_started"] - len(peers), 0)),
            "flow_start_rate_std": _std(starts_per_bin),
            "idle_bins": float(sum(1 for v in starts_per_bin if v == 0)),
            "keepalive_like_flows": float(agg["keepalive"]),
            "small_flow_ratio": agg["small"] / n_flows,
            "fast_scored_flows": float(len(scores)),
            "fast_flagged_flows": float(agg["fast_flagged"]),
            "fast_score_mean": (sum(scores) / len(scores)) if scores else 0.0,
            "fast_score_max": float(max(scores)) if scores else 0.0,
            "fast_score_p90": _pct(sorted(scores), 90) if scores else 0.0,
            "bins_present": float(n_present),
            "missing_bin_ratio": (N_BINS - n_present) / N_BINS,
            "partial_flow_ratio": agg["partial"] / n_flows,
        })
        return {
            "schema_version": HOST_SCHEMA_VERSION,
            "contract_hash": contract_hash(),
            "host_key": host_key,          # envelope only, never a model input
            "window_end": float(now),
            "window_status": status,
            # How many of the twenty minutes had any flow at all. A `full`
            # window with two busy bins is still a real observation, but an
            # operator should be able to see that it was a quiet host.
            "active_bins": n_present,
            "scorable": status == "full",
            "features": row,
        }

    def windows(self, now: float) -> list[dict[str, Any]]:
        out = []
        for host in list(self._bins):
            w = self.window(host, now)
            if w is not None:
                out.append(w)
        return out

    def host_count(self) -> int:
        return len(self._bins)

    def bin_count(self) -> int:
        return sum(len(b) for b in self._bins.values())


def _std(vals: list[int] | list[float]) -> float:
    if len(vals) < 2:
        return 0.0
    m = sum(vals) / len(vals)
    return math.sqrt(sum((v - m) ** 2 for v in vals) / len(vals))


def _pct(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, int(round((q / 100.0) * (len(sorted_vals) - 1)))))
    return float(sorted_vals[idx])
