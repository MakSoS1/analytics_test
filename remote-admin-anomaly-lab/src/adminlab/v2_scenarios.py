from __future__ import annotations

import math
import random
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from .manifest import SessionRecord

V2_BENIGN_FAMILIES = {
    "routine_admin",
    "scheduled_patch_fanout",
    "backup_burst",
    "helpdesk",
    "incident_response",
    "new_server",
    "new_admin",
    "service_automation",
    "jump_host",
    "offhours_emergency",
    "mass_diagnostics",
    "benign_first_seen",
}

V2_SUSPICIOUS_FAMILIES = {
    "low_slow_lateral",
    "sudden_fanout",
    "rare_pair",
    "new_protocol",
    "protocol_switch",
    "failed_then_success",
    "target_chain",
    "credential_hop_like",
    "small_copy_then_admin",
    "offhours_lateral",
}


def _dt(value: str) -> datetime:
    out = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return out if out.tzinfo is not None else out.replace(tzinfo=timezone.utc)


def _duration_seconds(row: SessionRecord) -> int:
    return max(0, int(round((_dt(row.end_ts) - _dt(row.start_ts)).total_seconds())))


def _hour_bucket(row: SessionRecord) -> int:
    return _dt(row.start_ts).hour // 4


def counterfactual_signature(row: SessionRecord) -> tuple[object, ...]:
    """Current-session nuisance controls that a matched twin should share.

    Host/pair identity, simulated day and all semantic ground-truth fields are
    deliberately excluded: V2 wants the current session to overlap while prior
    source/destination history remains informative and independently varying.
    """
    return (
        row.protocol,
        row.dst_port,
        row.action,
        row.netem_profile,
        row.task_id,
        row.behavior_profile,
        row.client_stack,
        row.server_stack,
        row.implementation_id,
        row.auth_outcome,
        _hour_bucket(row),
        _duration_seconds(row),
        int(row.wire_attempts),
        int(row.wire_transfer_bytes),
    )


def _semantic_context(records: list[SessionRecord]) -> list[SessionRecord]:
    """Assign V2 families from selected-corpus causal history only."""
    history: dict[str, list[SessionRecord]] = defaultdict(list)
    seen_dsts: dict[str, set[str]] = defaultdict(set)
    seen_protocols: dict[str, set[str]] = defaultdict(set)
    output: list[SessionRecord] = []

    for row in sorted(records, key=lambda r: (_dt(r.start_ts), r.session_id)):
        start = _dt(row.start_ts)
        src = row.src_host_id
        dst = row.dst_host_id
        prior = history[src]
        recent_1h = [p for p in prior if timedelta(0) <= start - _dt(p.start_ts) <= timedelta(hours=1)]
        recent_24h = [p for p in prior if timedelta(0) <= start - _dt(p.start_ts) <= timedelta(hours=24)]
        new_dst = dst not in seen_dsts[src]
        new_protocol = row.protocol not in seen_protocols[src]
        prior_targets = {p.dst_host_id for p in recent_1h}
        prior_protocols = [p.protocol for p in recent_1h]
        offhours = start.hour < 7 or start.hour >= 20
        previous = prior[-1] if prior else None
        gap_seconds = (start - _dt(previous.start_ts)).total_seconds() if previous else math.inf

        if int(row.label_binary) == 0:
            task = row.task_id.lower()
            behavior = row.behavior_profile.lower()
            if not prior:
                family = "new_admin"
                relation = "first_observed_source_session"
            elif behavior == "maintenance_fanout" or "patch" in task or "deploy" in task:
                family = "scheduled_patch_fanout"
                relation = "approved_multi_target_change"
            elif behavior == "bulk_transfer" or "backup" in task:
                family = "backup_burst"
                relation = "known_bulk_transfer"
            elif row.protocol in {"rdp", "vnc"} and behavior in {"interactive", "reconnect"}:
                family = "helpdesk"
                relation = "interactive_support_path"
            elif offhours and ("incident" in task or len(recent_1h) >= 2):
                family = "incident_response"
                relation = "approved_offhours_response"
            elif offhours:
                family = "offhours_emergency"
                relation = "approved_offhours_exception"
            elif new_dst and len(prior) >= 2:
                family = "benign_first_seen"
                relation = "approved_new_pair"
            elif new_dst:
                family = "new_server"
                relation = "approved_new_target"
            elif "service" in row.persona_id.lower() or "automation" in task:
                family = "service_automation"
                relation = "scheduled_service_identity"
            elif len(prior_targets) >= 3:
                family = "mass_diagnostics"
                relation = "approved_fanout"
            elif len(prior_targets) >= 1 and len(prior_protocols) >= 2:
                family = "jump_host"
                relation = "approved_multi_protocol_admin"
            else:
                family = "routine_admin"
                relation = "known_pair"
            intent = "approved_administration"
            label_family = family
        else:
            if previous is not None and previous.auth_outcome != "success" and row.auth_outcome == "success":
                family = "failed_then_success"
                relation = "auth_transition"
            elif new_protocol and prior:
                family = "new_protocol"
                relation = "source_protocol_novelty"
            elif len(prior_targets) >= 3 and new_dst:
                family = "sudden_fanout"
                relation = "rapid_new_target_fanout"
            elif previous is not None and previous.protocol != row.protocol and len(recent_1h) >= 1:
                family = "protocol_switch"
                relation = "rapid_protocol_transition"
            elif previous is not None and previous.behavior_profile in {"small_transfer", "bulk_transfer"} and row.behavior_profile not in {"small_transfer", "bulk_transfer"}:
                family = "small_copy_then_admin"
                relation = "transfer_then_remote_admin"
            elif offhours:
                family = "offhours_lateral"
                relation = "offhours_new_admin_path"
            elif new_dst and gap_seconds >= 15 * 60:
                family = "low_slow_lateral"
                relation = "sparse_new_pair"
            elif new_dst:
                family = "rare_pair"
                relation = "new_or_rare_pair"
            elif len(prior_targets) >= 2:
                family = "target_chain"
                relation = "multi_target_chain"
            elif len(recent_24h) >= 2:
                family = "credential_hop_like"
                relation = "reused_source_across_targets"
            else:
                family = "low_slow_lateral"
                relation = "sparse_admin_activity"
            intent = "unauthorized_lateral_movement"
            label_family = family

        enriched = replace(
            row,
            campaign_type=family,
            label_family=label_family,
            intent_profile=intent,
            historical_relation=relation,
        )
        output.append(enriched)
        history[src].append(enriched)
        seen_dsts[src].add(dst)
        seen_protocols[src].add(row.protocol)

    return sorted(output, key=lambda r: (_dt(r.start_ts), r.session_id))


def _copy_current_controls(template: SessionRecord, target: SessionRecord, pair_id: str) -> SessionRecord:
    """Match current-session controls while preserving target identity/history."""
    duration = _duration_seconds(template)
    target_start = _dt(target.start_ts)
    target_end = target_start + timedelta(seconds=duration)
    return replace(
        target,
        pair_id=pair_id,
        task_id=template.task_id,
        action=template.action,
        behavior_profile=template.behavior_profile,
        netem_profile=template.netem_profile,
        auth_outcome=template.auth_outcome,
        client_stack=template.client_stack,
        server_stack=template.server_stack,
        implementation_id=template.implementation_id,
        end_ts=target_end.isoformat(),
        wire_attempts=template.wire_attempts,
        wire_transfer_bytes=template.wire_transfer_bytes,
    )


def _assign_counterfactual_pairs(
    records: list[SessionRecord], *, seed: int, min_fraction: float
) -> list[SessionRecord]:
    if not 0.0 <= min_fraction <= 1.0:
        raise ValueError("counterfactual fraction must be in [0,1]")
    target_pairs = math.ceil(len(records) * min_fraction / 2.0)
    if target_pairs == 0:
        return list(records)

    rng = random.Random(seed)
    groups: dict[tuple[str, int], dict[int, list[SessionRecord]]] = defaultdict(lambda: {0: [], 1: []})
    for row in records:
        groups[(row.protocol, _hour_bucket(row))][int(row.label_binary)].append(row)
    for bucket in groups.values():
        for label in (0, 1):
            bucket[label].sort(key=lambda r: (r.simulated_day, r.start_ts, r.session_id))
            rng.shuffle(bucket[label])

    selected_ids: set[str] = set()
    pairs: list[tuple[SessionRecord, SessionRecord]] = []
    keys = sorted(groups)
    progress = True
    while len(pairs) < target_pairs and progress:
        progress = False
        for key in keys:
            benign = [r for r in groups[key][0] if r.session_id not in selected_ids]
            suspicious = [r for r in groups[key][1] if r.session_id not in selected_ids]
            if not benign or not suspicious:
                continue
            # Prefer different identity/history so the current-session twin does
            # not erase the very relational signal V2 is designed to test.
            b = benign[0]
            s = next(
                (candidate for candidate in suspicious if (candidate.src_host_id, candidate.dst_host_id) != (b.src_host_id, b.dst_host_id)),
                suspicious[0],
            )
            pairs.append((b, s))
            selected_ids.update({b.session_id, s.session_id})
            progress = True
            if len(pairs) >= target_pairs:
                break

    # If hour-bucket matching was too restrictive, fill within protocol while
    # preserving label balance. This affects only pair coverage; start time is
    # not copied and remains available to the time-only shortcut audit.
    if len(pairs) < target_pairs:
        by_protocol: dict[str, dict[int, list[SessionRecord]]] = defaultdict(lambda: {0: [], 1: []})
        for row in records:
            if row.session_id not in selected_ids:
                by_protocol[row.protocol][int(row.label_binary)].append(row)
        for protocol in sorted(by_protocol):
            benign = sorted(by_protocol[protocol][0], key=lambda r: (r.start_ts, r.session_id))
            suspicious = sorted(by_protocol[protocol][1], key=lambda r: (r.start_ts, r.session_id))
            for b, s in zip(benign, suspicious):
                if len(pairs) >= target_pairs:
                    break
                pairs.append((b, s))
                selected_ids.update({b.session_id, s.session_id})
            if len(pairs) >= target_pairs:
                break

    if len(pairs) < target_pairs:
        raise ValueError(
            f"cannot build required V2 counterfactual coverage: pairs={len(pairs)} target={target_pairs}"
        )

    replacements: dict[str, SessionRecord] = {}
    for index, (benign, suspicious) in enumerate(pairs):
        pair_id = f"v2cf-{seed:08x}-{index:05d}"
        replacements[benign.session_id] = replace(benign, pair_id=pair_id)
        replacements[suspicious.session_id] = _copy_current_controls(benign, suspicious, pair_id)

    return [replacements.get(row.session_id, row) for row in records]


def build_v2_semantic_plan(
    records: list[SessionRecord], *, seed: int, min_counterfactual_fraction: float = 0.30
) -> list[SessionRecord]:
    """Enrich a selected V2 corpus and enforce captured counterfactual overlap.

    Labels are never changed. Semantics are assigned from strictly earlier rows
    in the selected corpus; then a bounded subset receives matched current-session
    controls. Implementation/wire-control materializers should run afterwards so
    their existing pair-aware logic produces identical client/control cohorts.
    """
    if not records:
        return []
    original_labels = {row.session_id: int(row.label_binary) for row in records}
    enriched = _semantic_context(records)
    paired = _assign_counterfactual_pairs(
        enriched, seed=seed, min_fraction=min_counterfactual_fraction
    )
    if {row.session_id: int(row.label_binary) for row in paired} != original_labels:
        raise AssertionError("V2 semantic preparation changed ground-truth labels")
    return sorted(paired, key=lambda r: (_dt(r.start_ts), r.session_id))


def summarize_v2_plan(records: list[SessionRecord]) -> dict:
    per_protocol_labels: dict[str, Counter[int]] = defaultdict(Counter)
    timeline: dict[str, set[int]] = defaultdict(set)
    by_pair: dict[str, list[SessionRecord]] = defaultdict(list)
    family_counts: Counter[str] = Counter()

    for row in records:
        per_protocol_labels[row.protocol][int(row.label_binary)] += 1
        timeline[row.protocol].add(int(row.simulated_day))
        family_counts[row.campaign_type or row.label_family] += 1
        if row.pair_id:
            by_pair[row.pair_id].append(row)

    counterfactual_rows = 0
    valid_pairs = 0
    invalid_pairs: list[str] = []
    for pair_id, pair_rows in by_pair.items():
        labels = {int(row.label_binary) for row in pair_rows}
        signatures = {counterfactual_signature(row) for row in pair_rows}
        if labels == {0, 1} and len(pair_rows) == 2 and len(signatures) == 1:
            valid_pairs += 1
            counterfactual_rows += len(pair_rows)
        else:
            invalid_pairs.append(pair_id)

    total = len(records)
    return {
        "rows": total,
        "label_counts": dict(sorted(Counter(int(r.label_binary) for r in records).items())),
        "v2_family_counts": dict(sorted(family_counts.items())),
        "counterfactual_pairs": valid_pairs,
        "invalid_counterfactual_pairs": invalid_pairs[:20],
        "counterfactual_pair_fraction": (counterfactual_rows / total) if total else 0.0,
        "per_protocol_label_counts": {
            protocol: {str(label): count for label, count in sorted(counts.items())}
            for protocol, counts in sorted(per_protocol_labels.items())
        },
        "timeline_days_by_protocol": {
            protocol: len(days) for protocol, days in sorted(timeline.items())
        },
    }
