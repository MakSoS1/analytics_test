from __future__ import annotations

import math
import random
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from .manifest import SessionRecord
from .v2_scenarios import build_v2_semantic_plan


def _dt(value: str) -> datetime:
    out = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return out if out.tzinfo is not None else out.replace(tzinfo=timezone.utc)


def _duration(row: SessionRecord) -> timedelta:
    return max(timedelta(0), _dt(row.end_ts) - _dt(row.start_ts))


def _weekend(row: SessionRecord) -> int:
    return int(_dt(row.start_ts).weekday() >= 5)


def _slot(row: SessionRecord) -> tuple[int, int, int]:
    value = _dt(row.start_ts)
    return value.hour, value.minute, value.second


def _with_slot(row: SessionRecord, slot: tuple[int, int, int], duration: timedelta | None = None) -> SessionRecord:
    start = _dt(row.start_ts)
    start = start.replace(hour=slot[0], minute=slot[1], second=slot[2], microsecond=0)
    span = _duration(row) if duration is None else duration
    return replace(row, start_ts=start.isoformat(), end_ts=(start + span).isoformat())


def _stable_shuffle(rows: list[SessionRecord], seed: int, salt: str) -> list[SessionRecord]:
    out = sorted(rows, key=lambda row: row.session_id)
    rng = random.Random(f"{seed}|{salt}")
    rng.shuffle(out)
    return out


def _redistribute_time_of_day(records: list[SessionRecord], *, seed: int) -> list[SessionRecord]:
    """Give both labels the same deterministic time-of-day distribution."""
    buckets: dict[tuple[str, int], list[SessionRecord]] = defaultdict(list)
    for row in records:
        buckets[(row.protocol, _weekend(row))].append(row)

    replacements: dict[str, SessionRecord] = {}
    for key, bucket in sorted(buckets.items()):
        slots = sorted({_slot(row) for row in bucket})
        if not slots:
            continue
        slot_cycle = list(slots)
        random.Random(f"{seed}|slot-cycle|{key}").shuffle(slot_cycle)
        for label in (0, 1):
            side = [row for row in bucket if int(row.label_binary) == label]
            side = _stable_shuffle(side, seed, f"time|{key}|{label}")
            for index, row in enumerate(side):
                replacements[row.session_id] = _with_slot(row, slot_cycle[index % len(slot_cycle)])
    return [replacements.get(row.session_id, row) for row in records]


def v3_current_signature(row: SessionRecord) -> tuple[object, ...]:
    """Network/current-session controls that matched twins must share."""
    start = _dt(row.start_ts)
    return (
        row.protocol,
        int(row.dst_port),
        row.action,
        row.netem_profile,
        row.task_id,
        row.calendar_id,
        row.behavior_profile,
        row.auth_outcome,
        row.client_stack,
        row.server_stack,
        row.implementation_id,
        start.hour,
        start.minute,
        int(round(_duration(row).total_seconds())),
        int(row.wire_attempts),
        int(row.wire_transfer_bytes),
    )


def _copy_current_controls(template: SessionRecord, target: SessionRecord, pair_id: str) -> SessionRecord:
    template_start = _dt(template.start_ts)
    target_start = _dt(target.start_ts).replace(
        hour=template_start.hour,
        minute=template_start.minute,
        second=template_start.second,
        microsecond=0,
    )
    span = _duration(template)
    return replace(
        target,
        pair_id=pair_id,
        action=template.action,
        task_id=template.task_id,
        calendar_id=template.calendar_id,
        behavior_profile=template.behavior_profile,
        netem_profile=template.netem_profile,
        auth_outcome=template.auth_outcome,
        client_stack=template.client_stack,
        server_stack=template.server_stack,
        implementation_id=template.implementation_id,
        start_ts=target_start.isoformat(),
        end_ts=(target_start + span).isoformat(),
        wire_attempts=template.wire_attempts,
        wire_transfer_bytes=template.wire_transfer_bytes,
    )


def _assign_exact_time_pairs(records: list[SessionRecord], *, seed: int, matched_fraction: float) -> list[SessionRecord]:
    if not 0.0 <= matched_fraction <= 1.0:
        raise ValueError("matched_fraction must be in [0,1]")
    target_pairs = math.ceil(len(records) * matched_fraction / 2.0)
    if target_pairs == 0:
        return list(records)

    groups: dict[tuple[str, int, int, int], dict[int, list[SessionRecord]]] = defaultdict(lambda: {0: [], 1: []})
    for row in records:
        start = _dt(row.start_ts)
        groups[(row.protocol, _weekend(row), start.hour, start.minute)][int(row.label_binary)].append(row)
    for key, sides in groups.items():
        for label in (0, 1):
            sides[label] = _stable_shuffle(sides[label], seed, f"pair|{key}|{label}")

    selected: set[str] = set()
    pairs: list[tuple[SessionRecord, SessionRecord]] = []
    keys = sorted(groups)
    while len(pairs) < target_pairs:
        progress = False
        for key in keys:
            benign = next((row for row in groups[key][0] if row.session_id not in selected), None)
            if benign is None:
                continue
            suspicious_candidates = [row for row in groups[key][1] if row.session_id not in selected]
            if not suspicious_candidates:
                continue
            suspicious = next(
                (
                    row
                    for row in suspicious_candidates
                    if (row.src_host_id, row.dst_host_id) != (benign.src_host_id, benign.dst_host_id)
                ),
                suspicious_candidates[0],
            )
            pairs.append((benign, suspicious))
            selected.update({benign.session_id, suspicious.session_id})
            progress = True
            if len(pairs) >= target_pairs:
                break
        if not progress:
            break

    if len(pairs) < target_pairs:
        raise ValueError(
            "cannot build required V3 exact-time counterfactual coverage without a time fallback: "
            f"pairs={len(pairs)} target={target_pairs}"
        )

    replacements: dict[str, SessionRecord] = {}
    for index, (benign, suspicious) in enumerate(pairs):
        pair_id = f"v3cf-{seed:08x}-{index:05d}"
        replacements[benign.session_id] = replace(benign, pair_id=pair_id)
        replacements[suspicious.session_id] = _copy_current_controls(benign, suspicious, pair_id)
    return [replacements.get(row.session_id, row) for row in records]


def build_v3_signal_plan(
    records: list[SessionRecord], *, seed: int, matched_fraction: float = 0.40
) -> list[SessionRecord]:
    """Compatibility V3 preparation: balance time and current-session controls.

    The causal Stage-H planner builds observable histories before calling this
    compatibility layer. This function intentionally does not invent a malicious
    signal from the label; it only removes nuisance/time shortcuts and constructs
    matched current-session pairs.
    """
    if not records:
        return []
    labels_before = {row.session_id: int(row.label_binary) for row in records}
    redistributed = _redistribute_time_of_day(records, seed=seed)
    paired = _assign_exact_time_pairs(redistributed, seed=seed, matched_fraction=matched_fraction)
    enriched = build_v2_semantic_plan(paired, seed=seed, min_counterfactual_fraction=0.0)
    if {row.session_id: int(row.label_binary) for row in enriched} != labels_before:
        raise AssertionError("V3 signal preparation changed ground-truth labels")
    return sorted(enriched, key=lambda row: (_dt(row.start_ts), row.session_id))


def _strict_prior_for_source(current: SessionRecord, history: list[SessionRecord]) -> list[SessionRecord]:
    start = _dt(current.start_ts)
    return sorted(
        [row for row in history if row.src_host_id == current.src_host_id and _dt(row.start_ts) < start],
        key=lambda row: (_dt(row.start_ts), row.session_id),
    )


def causal_history_signature(current: SessionRecord, history: list[SessionRecord]) -> dict[str, int | float]:
    """Return only production-observable relational history statistics.

    Host identities are used as ephemeral state keys, but never returned. The
    signature deliberately contains no label, persona, scenario, campaign or
    semantic fields.
    """
    prior = _strict_prior_for_source(current, history)
    pair_rows = [row for row in prior if row.dst_host_id == current.dst_host_id]
    protocol_rows = [row for row in prior if row.protocol == current.protocol]
    distinct_dst = {row.dst_host_id for row in prior}
    distinct_protocols = {row.protocol for row in prior}
    recent_1h = [row for row in prior if _dt(current.start_ts) - _dt(row.start_ts) <= timedelta(hours=1)]
    recent_24h = [row for row in prior if _dt(current.start_ts) - _dt(row.start_ts) <= timedelta(hours=24)]
    pair_recency = -1.0
    if pair_rows:
        pair_recency = float((_dt(current.start_ts) - max(_dt(row.start_ts) for row in pair_rows)).total_seconds())
    switches = 0
    ordered = sorted(prior, key=lambda row: (_dt(row.start_ts), row.session_id))
    for left, right in zip(ordered, ordered[1:]):
        switches += int(left.protocol != right.protocol)
    return {
        "source_sessions_prior": len(prior),
        "pair_seen_count_prior": len(pair_rows),
        "pair_recency_s_prior": pair_recency,
        "distinct_dst_prior": len(distinct_dst),
        "protocol_seen_count_prior": len(protocol_rows),
        "protocol_diversity_prior": len(distinct_protocols),
        "new_destination_for_source": int(current.dst_host_id not in distinct_dst),
        "new_protocol_for_source": int(current.protocol not in distinct_protocols),
        "recent_sessions_1h_prior": len(recent_1h),
        "recent_sessions_24h_prior": len(recent_24h),
        "recent_new_target_count_1h_prior": len({row.dst_host_id for row in recent_1h}),
        "recent_protocol_switch_count_prior": switches,
    }


def build_history_by_session(records: list[SessionRecord]) -> dict[str, list[SessionRecord]]:
    """Build strictly-prior source-local histories for planner/evaluation audits."""
    history: dict[str, list[SessionRecord]] = defaultdict(list)
    out: dict[str, list[SessionRecord]] = {}
    for row in sorted(records, key=lambda item: (_dt(item.start_ts), item.session_id)):
        out[row.session_id] = list(history[row.src_host_id])
        history[row.src_host_id].append(row)
    return out


def _history_vector(signature: dict[str, int | float]) -> tuple[int | float, ...]:
    return tuple(signature[key] for key in sorted(signature))


def audit_causal_observability(
    records: list[SessionRecord], *, history_by_session: dict[str, list[SessionRecord]] | None = None
) -> dict:
    """Fail closed when opposite labels differ only in semantic metadata.

    For every matched counterfactual pair the current-session signature must be
    equal and the prior production-observable history signature must differ.
    """
    histories = history_by_session if history_by_session is not None else build_history_by_session(records)
    by_pair: dict[str, list[SessionRecord]] = defaultdict(list)
    for row in records:
        if row.pair_id:
            by_pair[row.pair_id].append(row)

    semantic_only: list[str] = []
    invalid_current: list[str] = []
    separated = 0
    for pair_id, pair in sorted(by_pair.items()):
        if len(pair) != 2 or {int(row.label_binary) for row in pair} != {0, 1}:
            invalid_current.append(pair_id)
            continue
        if len({v3_current_signature(row) for row in pair}) != 1:
            invalid_current.append(pair_id)
            continue
        vectors = {
            _history_vector(causal_history_signature(row, histories.get(row.session_id, [])))
            for row in pair
        }
        if len(vectors) == 1:
            semantic_only.append(pair_id)
        else:
            separated += 1

    return {
        "valid": not semantic_only and not invalid_current,
        "counterfactual_pairs": len(by_pair),
        "causally_separated_counterfactual_pairs": separated,
        "semantic_only_counterfactual_pairs": semantic_only[:50],
        "invalid_current_session_pairs": invalid_current[:50],
        "history_fields": sorted(causal_history_signature(records[0], histories.get(records[0].session_id, [])).keys()) if records else [],
    }


def audit_v3_signal_plan(records: list[SessionRecord]) -> dict:
    by_pair: dict[str, list[SessionRecord]] = defaultdict(list)
    label_totals = Counter(int(row.label_binary) for row in records)
    hour_counts: dict[int, Counter[int]] = defaultdict(Counter)
    protocol_hour_counts: dict[str, dict[int, Counter[int]]] = defaultdict(lambda: defaultdict(Counter))
    for row in records:
        if row.pair_id:
            by_pair[row.pair_id].append(row)
        hour = _dt(row.start_ts).hour
        hour_counts[hour][int(row.label_binary)] += 1
        protocol_hour_counts[row.protocol][hour][int(row.label_binary)] += 1

    valid_pairs = 0
    exact_hour_pairs = 0
    invalid_pairs: list[str] = []
    for pair_id, rows in sorted(by_pair.items()):
        labels = {int(row.label_binary) for row in rows}
        signatures = {v3_current_signature(row) for row in rows}
        slots = {(_dt(row.start_ts).hour, _dt(row.start_ts).minute) for row in rows}
        if len(rows) == 2 and labels == {0, 1} and len(signatures) == 1:
            valid_pairs += 1
            if len(slots) == 1:
                exact_hour_pairs += 1
        else:
            invalid_pairs.append(pair_id)

    gaps: list[float] = []
    for hour, counts in hour_counts.items():
        benign_fraction = counts[0] / max(1, label_totals[0])
        suspicious_fraction = counts[1] / max(1, label_totals[1])
        gaps.append(abs(benign_fraction - suspicious_fraction))

    return {
        "rows": len(records),
        "label_counts": {str(k): int(v) for k, v in sorted(label_totals.items())},
        "counterfactual_pairs": valid_pairs,
        "counterfactual_row_fraction": (2 * valid_pairs / len(records)) if records else 0.0,
        "matched_hour_pair_fraction": (exact_hour_pairs / valid_pairs) if valid_pairs else 0.0,
        "invalid_counterfactual_pairs": invalid_pairs[:20],
        "max_hour_label_fraction_gap": max(gaps, default=0.0),
        "hour_label_counts": {
            str(hour): {str(label): int(count) for label, count in sorted(counts.items())}
            for hour, counts in sorted(hour_counts.items())
        },
        "protocol_hour_label_counts": {
            protocol: {
                str(hour): {str(label): int(count) for label, count in sorted(counts.items())}
                for hour, counts in sorted(hours.items())
            }
            for protocol, hours in sorted(protocol_hour_counts.items())
        },
        "causal_observability": audit_causal_observability(records),
        "time_matching_fallback_allowed": False,
        "wire_controls_label_dependent": False,
    }
