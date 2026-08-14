from __future__ import annotations

import random
from collections import Counter, defaultdict, deque
from dataclasses import replace

from .manifest import SessionRecord


def _chunk_source_sequence(rows: list[SessionRecord], *, seed: int, key: str, min_size: int = 3, max_size: int = 5) -> list[list[SessionRecord]]:
    """Build small source-local sequence units with protocol diversity where possible."""
    by_protocol: dict[str, deque[SessionRecord]] = defaultdict(deque)
    for row in sorted(rows, key=lambda item: (item.start_ts, item.session_id)):
        by_protocol[row.protocol].append(row)
    groups: list[list[SessionRecord]] = []
    rng = random.Random(f"{seed}|{key}")
    while any(by_protocol.values()):
        group: list[SessionRecord] = []
        available = [protocol for protocol, queue in by_protocol.items() if queue]
        available.sort(key=lambda protocol: (-len(by_protocol[protocol]), protocol))
        if len(available) > 1 and rng.random() < 0.5:
            available = available[1:] + available[:1]
        for protocol in available:
            if len(group) >= max_size:
                break
            if by_protocol[protocol]:
                group.append(by_protocol[protocol].popleft())
        while len(group) < max_size:
            remaining = [protocol for protocol, queue in by_protocol.items() if queue]
            if not remaining:
                break
            protocol = max(remaining, key=lambda value: (len(by_protocol[value]), value))
            group.append(by_protocol[protocol].popleft())
        groups.append(sorted(group, key=lambda item: (item.start_ts, item.session_id)))

    # Keep units bounded. A tiny tail can join the preceding group only if the
    # result remains <= 8; otherwise it remains a legitimate small campaign.
    if len(groups) >= 2 and len(groups[-1]) < min_size and len(groups[-2]) + len(groups[-1]) <= 8:
        tail = groups.pop()
        groups[-1].extend(tail)
        groups[-1].sort(key=lambda item: (item.start_ts, item.session_id))
    return groups


def organize_v3_campaigns(records: list[SessionRecord], *, seed: int) -> list[SessionRecord]:
    """Assign many small independent campaign units without changing labels/pairs.

    V2 grouped all activity by day+label, which made campaign components too
    coarse. V3 adds source identity to the campaign boundary so the benchmark has
    many independent behavioral units while still modeling multi-session activity
    from one administrative source on one simulated day.
    """
    if not records:
        return []

    buckets: dict[tuple[int, int, str], list[SessionRecord]] = defaultdict(list)
    for row in records:
        buckets[(int(row.simulated_day), int(row.label_binary), str(row.src_host_id))].append(row)

    output: list[SessionRecord] = []
    campaign_index = 0
    for (day, label, src_host), rows in sorted(buckets.items()):
        groups = _chunk_source_sequence(rows, seed=seed, key=f"{day}|{label}|{src_host}")
        for group in groups:
            campaign_id = f"v3c-d{day:02d}-l{label}-{src_host}-{seed:08x}-{campaign_index:05d}"
            protocols = {row.protocol for row in group}
            size = len(group)
            sequence_profile = "multi_protocol" if len(protocols) >= 2 else "single_protocol"
            for position, row in enumerate(group):
                output.append(
                    replace(
                        row,
                        campaign_id=campaign_id,
                        campaign_position=position,
                        campaign_size=size,
                        sequence_profile=sequence_profile,
                    )
                )
            campaign_index += 1

    return sorted(output, key=lambda row: (row.start_ts, row.session_id))


def audit_v3_campaigns(records: list[SessionRecord]) -> dict:
    campaigns: dict[str, list[SessionRecord]] = defaultdict(list)
    for row in records:
        campaigns[str(row.campaign_id)].append(row)

    labels = Counter()
    multi_protocol = 0
    sizes: list[int] = []
    hard_benign = 0
    hard_benign_families = {
        "incident_response",
        "offhours_emergency",
        "mass_diagnostics",
        "scheduled_patch_fanout",
        "backup_burst",
        "benign_first_seen",
        "new_server",
    }
    for rows in campaigns.values():
        label_set = {int(row.label_binary) for row in rows}
        if len(label_set) == 1:
            label = next(iter(label_set))
            labels[label] += 1
            if label == 0 and any((row.campaign_type or row.label_family) in hard_benign_families for row in rows):
                hard_benign += 1
        if len({row.protocol for row in rows}) >= 2:
            multi_protocol += 1
        sizes.append(len(rows))

    total = len(records)
    return {
        "rows": total,
        "campaign_count": len(campaigns),
        "benign_campaign_count": int(labels[0]),
        "suspicious_campaign_count": int(labels[1]),
        "hard_benign_campaign_count": int(hard_benign),
        "multi_protocol_campaign_count": int(multi_protocol),
        "max_campaign_size": max(sizes, default=0),
        "median_campaign_size": sorted(sizes)[len(sizes) // 2] if sizes else 0,
        "max_campaign_fraction": (max(sizes, default=0) / total) if total else 0.0,
    }
