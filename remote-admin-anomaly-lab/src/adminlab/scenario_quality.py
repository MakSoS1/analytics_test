from __future__ import annotations

from collections import Counter
from typing import Iterable

from .manifest import SessionRecord

DEFAULT_THRESHOLDS = {
    "semantic_families": 25,
    "personas": 40,
    "host_relations": 12,
    "campaign_types": 8,
    "simulated_days": 30,
    "protocols": 4,
}


def evaluate_scenario_quality(
    records: Iterable[SessionRecord],
    *,
    thresholds: dict[str, int] | None = None,
) -> dict:
    rows = list(records)
    limits = dict(DEFAULT_THRESHOLDS)
    if thresholds:
        limits.update({str(k): int(v) for k, v in thresholds.items()})
    semantic = {
        (r.task_id, r.protocol, r.behavior_profile)
        for r in rows
        if r.task_id and r.protocol and r.behavior_profile
    }
    personas = {r.persona_id for r in rows if r.persona_id}
    relations = {(r.src_host_id, r.dst_host_id, r.protocol) for r in rows}
    campaigns = {r.campaign_type for r in rows if r.campaign_type}
    days = {int(r.simulated_day) for r in rows}
    protocols = {r.protocol for r in rows if r.protocol}
    hard_benign = [
        r for r in rows
        if r.label_binary == 0 and (
            r.historical_relation in {"novel_but_ticketed", "recently_added_pair"}
            or r.task_id in {"emergency_admin", "approved_forwarding", "backup"}
            or r.behavior_profile in {"bulk_transfer", "maintenance_fanout", "forwarding_session"}
        )
    ]
    hard_suspicious = [
        r for r in rows
        if r.label_binary == 1 and (
            r.historical_relation in {"novel_pair", "rare_pair"}
            or r.campaign_type in {
                "valid_credentials_low_slow", "compromised_workstation_fanout",
                "trusted_jump_host_abuse", "cross_protocol_chain", "single_normal_session",
            }
        )
    ]
    metrics = {
        "rows": len(rows),
        "semantic_families": len(semantic),
        "personas": len(personas),
        "host_relations": len(relations),
        "campaign_types": len(campaigns),
        "simulated_days": len(days),
        "protocols": len(protocols),
        "hard_benign_sessions": len(hard_benign),
        "hard_suspicious_sessions": len(hard_suspicious),
        "label_counts": dict(Counter("suspicious" if r.label_binary else "benign" for r in rows)),
        "protocol_counts": dict(Counter(r.protocol for r in rows)),
    }
    failed = [name for name, minimum in limits.items() if int(metrics[name]) < minimum]
    if not hard_benign:
        failed.append("hard_benign_sessions")
    if not hard_suspicious:
        failed.append("hard_suspicious_sessions")
    metrics["thresholds"] = limits
    metrics["failed_gates"] = sorted(set(failed))
    metrics["ok"] = not metrics["failed_gates"]
    metrics["policy"] = "semantic diversity gate; row count alone never passes corpus promotion"
    return metrics
