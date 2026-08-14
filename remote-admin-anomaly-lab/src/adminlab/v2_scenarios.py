from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

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


def _duration_seconds(row: SessionRecord) -> int:
    start = datetime.fromisoformat(row.start_ts)
    end = datetime.fromisoformat(row.end_ts)
    return max(0, int(round((end - start).total_seconds())))


def counterfactual_signature(row: SessionRecord) -> tuple[object, ...]:
    """Return wire/nuisance controls shared by a counterfactual pair.

    Deliberately excluded: label, intent, campaign family, historical relation,
    scenario/session identifiers and all other semantic ground-truth fields.
    """
    return (
        row.pair_id,
        row.protocol,
        row.src_host_id,
        row.dst_host_id,
        row.dst_port,
        row.action,
        row.netem_profile,
        row.task_id,
        row.client_stack,
        row.server_stack,
        row.implementation_id,
        row.auth_outcome,
        int(row.simulated_day),
        _duration_seconds(row),
    )


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
    for pair_rows in by_pair.values():
        labels = {int(row.label_binary) for row in pair_rows}
        signatures = {counterfactual_signature(row) for row in pair_rows}
        if labels == {0, 1} and len(signatures) == 1:
            valid_pairs += 1
            counterfactual_rows += len(pair_rows)

    total = len(records)
    return {
        "rows": total,
        "label_counts": dict(sorted(Counter(int(r.label_binary) for r in records).items())),
        "v2_family_counts": dict(sorted(family_counts.items())),
        "counterfactual_pairs": valid_pairs,
        "counterfactual_pair_fraction": (counterfactual_rows / total) if total else 0.0,
        "per_protocol_label_counts": {
            protocol: {str(label): count for label, count in sorted(counts.items())}
            for protocol, counts in sorted(per_protocol_labels.items())
        },
        "timeline_days_by_protocol": {
            protocol: len(days) for protocol, days in sorted(timeline.items())
        },
    }
