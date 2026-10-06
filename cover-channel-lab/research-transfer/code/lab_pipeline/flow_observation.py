#!/usr/bin/env python3
"""Bounded per-flow observation: the same reducer offline and on the sensor.

One object consumes packets and emits exactly one feature vector when the
fast-v1 horizon is reached. It holds a fixed amount of state — the first
MAX_PACKETS packets and a handful of counters — so a long session never
accumulates in memory just to answer an early question.

The properties the tests pin down, because each one was a real defect:

* packets after the decision cannot change the vector already emitted;
* the time budget fires even if no further packet ever arrives;
* a flow closing before the budget emits once, not twice;
* a reused 4-tuple is a new flow instance, not a continuation;
* a flow joined mid-stream is marked `start_observed=false` and gets its own
  handling rather than being quietly treated as a clean negative;
* aggregates cover the SAME prefix as the sequence features.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from lab_pipeline.online_schema import (
    AGGREGATE_FEATURES,
    FEATURE_NAMES,
    MAX_PACKETS,
    MAX_SECONDS,
    MIN_PACKETS,
    SCHEMA_VERSION,
    contract_hash,
    idle_timeout,
)


@dataclass(frozen=True)
class Packet:
    ts: float
    length: int            # L2 frame bytes, no FCS
    from_initiator: bool
    syn: bool = False
    fin: bool = False
    rst: bool = False
    is_udp: bool = False


@dataclass
class Observation:
    """One flow, observed until the fast-v1 horizon."""

    flow_instance_id: str
    start_observed: bool = True
    _pkts: list[Packet] = field(default_factory=list)
    _t0: float | None = None
    _closed: bool = False
    _emitted: bool = False
    _syn = 0
    _fin = 0
    _rst = 0
    _seen_total: int = 0
    _expired_at: float | None = None

    # ---- ingestion -------------------------------------------------------
    def add(self, pkt: Packet) -> bool:
        """Feed one packet. True when the flow is ready to emit.

        Packets arriving after the decision are counted for telemetry but never
        alter the vector: an online decision must not be retroactively rewritten.

        The horizon is a half-open window `[t0, t0 + MAX_SECONDS)`. A packet at
        or past its far edge is what *reveals* that the budget expired; it is not
        part of what the budget covered. Appending it first and checking after
        made a run at t = 0, 1, 2, 8 report `observed_duration = 8` against a
        five-second contract — a window the sensor, driven by a real timer, can
        never reproduce.
        """
        self._seen_total += 1
        if self._emitted:
            return False
        if self._t0 is None:
            self._t0 = pkt.ts
        elif (pkt.ts - self._t0) >= MAX_SECONDS:
            self._expired_at = pkt.ts
            return True
        if len(self._pkts) < MAX_PACKETS:
            self._pkts.append(pkt)
        self._syn += int(pkt.syn)
        self._fin += int(pkt.fin)
        self._rst += int(pkt.rst)
        if pkt.fin or pkt.rst:
            self._closed = True
        return self.ready(pkt.ts)

    def ready(self, now: float | None = None) -> bool:
        if self._emitted or self._t0 is None:
            return False
        if self._expired_at is not None:
            return True
        if self._closed:
            return True
        if len(self._pkts) >= MAX_PACKETS:
            return True
        if now is not None and (now - self._t0) >= MAX_SECONDS:
            return True
        return False

    def decision_reason(self, now: float | None = None) -> str:
        if len(self._pkts) < MIN_PACKETS:
            return "insufficient_data"
        if self._expired_at is not None:
            return "time_budget"
        if len(self._pkts) >= MAX_PACKETS:
            return "packet_budget"
        if self._closed:
            return "flow_closed"
        if now is not None and self._t0 is not None and (now - self._t0) >= MAX_SECONDS:
            return "time_budget"
        return "flow_closed"

    # ---- emission --------------------------------------------------------
    def emit(self, now: float | None = None) -> dict[str, Any]:
        """Produce the record exactly once. Idempotent afterwards."""
        reason = self.decision_reason(now)
        self._emitted = True
        pkts = self._pkts
        # When the decision was taken, in capture time. Needed to answer "how
        # soon after the flow started did the detector speak", which session
        # recall alone cannot: a session counted as detected on its 400th flow
        # is not the same product as one detected on its first.
        decided_at = now if now is not None else (pkts[-1].ts if pkts else self._t0)
        vector = self._vector(pkts)
        return {
            "schema_version": SCHEMA_VERSION,
            "contract_hash": contract_hash(),
            "flow_instance_id": self.flow_instance_id,
            "decision_reason": reason,
            "decision_ts": decided_at,
            "first_packet_ts": self._t0,
            "start_observed": self.start_observed,
            "observed_packets": len(pkts),
            # Packets this observation saw that the vector does not cover: the
            # one that revealed the deadline, at most. It cannot describe what
            # arrives later — the record is emitted the instant the decision is
            # made. The table counts the rest of the connection separately.
            "packets_outside_prefix": max(0, self._seen_total - len(pkts)),
            "scorable": reason != "insufficient_data" and self.start_observed,
            "features": vector,
        }

    def _vector(self, pkts: list[Packet]) -> dict[str, float]:
        row = {name: 0.0 for name in FEATURE_NAMES}
        if not pkts:
            return row
        t0 = pkts[0].ts
        lens = [p.length for p in pkts]
        iats: list[float] = []
        prev = t0
        up = down = 0
        up_b = down_b = 0
        changes = 0
        last_dir: bool | None = None
        for i, p in enumerate(pkts):
            gap = max(0.0, p.ts - prev)
            prev = p.ts
            if i:
                iats.append(gap)
            if p.from_initiator:
                up += 1
                up_b += p.length
            else:
                down += 1
                down_b += p.length
            if last_dir is not None and p.from_initiator != last_dir:
                changes += 1
            last_dir = p.from_initiator
            row[f"signed_len_{i}"] = float(p.length if p.from_initiator else -p.length)
            row[f"dir_{i}"] = 1.0 if p.from_initiator else -1.0
            row[f"iat_{i}"] = float(gap)
            row[f"mask_{i}"] = 1.0

        # Aggregates span exactly the packets above — the same prefix, never the
        # whole capture. This is the parity the old 112-feature vector lacked.
        n = len(pkts)
        duration = max(pkts[-1].ts - t0, 0.0)
        row["pkt_count"] = float(n)
        row["up_pkt_count"] = float(up)
        row["down_pkt_count"] = float(down)
        row["total_bytes"] = float(sum(lens))
        row["up_bytes"] = float(up_b)
        row["down_bytes"] = float(down_b)
        row["observed_duration"] = float(duration)
        row["up_down_pkt_ratio"] = up / max(down, 1)
        row["up_down_bytes_ratio"] = up_b / max(down_b, 1)
        row["pkt_len_mean"] = sum(lens) / n
        row["pkt_len_std"] = _std(lens)
        row["pkt_len_min"] = float(min(lens))
        row["pkt_len_max"] = float(max(lens))
        row["iat_mean"] = (sum(iats) / len(iats)) if iats else 0.0
        row["iat_std"] = _std(iats) if iats else 0.0
        row["iat_min"] = float(min(iats)) if iats else 0.0
        row["iat_max"] = float(max(iats)) if iats else 0.0
        row["direction_changes"] = float(changes)
        row["is_udp"] = 1.0 if pkts[0].is_udp else 0.0
        row["is_tcp"] = 0.0 if pkts[0].is_udp else 1.0
        row["syn_count"] = float(self._syn)
        row["fin_count"] = float(self._fin)
        row["rst_count"] = float(self._rst)
        for name in AGGREGATE_FEATURES:
            row[name] = float(row[name])
        return row


def _std(vals: list[float] | list[int]) -> float:
    if len(vals) < 2:
        return 0.0
    m = sum(vals) / len(vals)
    return math.sqrt(sum((v - m) ** 2 for v in vals) / len(vals))


@dataclass
class _Slot:
    """What the table remembers about one 4-tuple, alive or already decided."""

    instance: str
    obs: Observation | None      # dropped on decision: the prefix is spent
    last_seen: float
    first_dir: bool
    is_udp: bool
    decided: bool = False
    packets_after: int = 0


class ObservationTable:
    """Flow table with explicit instance identity and a time-driven sweep.

    One flow instance yields exactly ONE decision. That sounds obvious and was
    not true: the table deleted the observation on emit but kept the key's
    sequence number, so the very next packet of the same connection rebuilt a
    fresh `Observation` carrying the *same* `flow_instance_id`. A 61-packet
    connection produced three records; a re-extracted corpus held 492 961 rows
    across 50 834 distinct (session, flow instance) pairs, one id appearing 1 050
    times.

    That is not a cosmetic duplicate. Consecutive slices of one connection are
    not independent samples, so an office FPR denominator built from them claims
    far more evidence than exists; and session recall stops meaning "detected
    from the opening prefix" when the model gets a fresh attempt every twenty
    packets for the whole session.

    A decided slot therefore stays, absorbing the rest of the connection without
    scoring it, until the flow times out. That also gives state a place to die:
    the previous version kept a `_seq`, `_last_seen`, `_bidirectional` and
    `_first_dir` entry for every 4-tuple it had ever seen, and nothing ever
    removed them — unbounded growth on a sensor that sees millions of tuples a
    day. Instance numbers come from one table-wide counter, so evicting a key
    can never resurrect a retired id.
    """

    def __init__(self) -> None:
        self._slots: dict[str, _Slot] = {}
        self._next_instance = 0

    def _idle_for(self, slot: _Slot, bidirectional: bool) -> float:
        return idle_timeout("udp" if slot.is_udp else "tcp", bidirectional)

    def _open(self, key: str, pkt: Packet, start_observed: bool) -> _Slot:
        self._next_instance += 1
        inst = f"{key}#{self._next_instance}"
        slot = _Slot(
            instance=inst,
            obs=Observation(flow_instance_id=inst, start_observed=start_observed),
            last_seen=pkt.ts,
            first_dir=pkt.from_initiator,
            is_udp=pkt.is_udp,
        )
        self._slots[key] = slot
        return slot

    def observe(self, key: str, pkt: Packet, start_observed: bool = True) -> dict[str, Any] | None:
        slot = self._slots.get(key)
        if slot is not None:
            bidirectional = slot.first_dir != pkt.from_initiator
            if bidirectional:
                slot.first_dir = pkt.from_initiator  # keep flipping: stays bidirectional
                slot.bidirectional = True
            timed_out = (pkt.ts - slot.last_seen) > self._idle_for(
                slot, getattr(slot, "bidirectional", False)
            )
            # A bare SYN reopens the 4-tuple only once the current instance is
            # finished. While the instance is still undecided the same SYN is a
            # retransmitted handshake, and treating it as a new connection threw
            # away the prefix we were in the middle of observing.
            bare_syn = pkt.syn and not pkt.is_udp and pkt.from_initiator
            if timed_out or (bare_syn and slot.decided):
                slot = None
        if slot is None:
            slot = self._open(key, pkt, start_observed)
        slot.last_seen = pkt.ts
        if slot.decided:
            slot.packets_after += 1
            return None
        assert slot.obs is not None
        if slot.obs.add(pkt):
            rec = slot.obs.emit(pkt.ts)
            slot.decided = True
            slot.obs = None
            return rec
        return None

    def sweep(self, now: float) -> list[dict[str, Any]]:
        """Emit expired flows, then retire state for flows past their timeout."""
        out = []
        for key, slot in list(self._slots.items()):
            if slot.obs is not None and slot.obs.ready(now):
                out.append(slot.obs.emit(now))
                slot.decided = True
                slot.obs = None
            if (now - slot.last_seen) > self._idle_for(slot, getattr(slot, "bidirectional", False)):
                del self._slots[key]
        return out

    def live_count(self) -> int:
        """Flows still gathering a prefix — not counting decided ones."""
        return sum(1 for s in self._slots.values() if s.obs is not None)

    def absorbed_after_decision(self) -> int:
        """Packets belonging to already-decided flows. Telemetry, never scored."""
        return sum(s.packets_after for s in self._slots.values())

    def tracked_keys(self) -> int:
        """Every 4-tuple holding state, decided or not. Must not grow forever."""
        return len(self._slots)
