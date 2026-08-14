from __future__ import annotations

import random
from collections import defaultdict, deque
from dataclasses import replace

from .manifest import SessionRecord


def _catalog_entry(campaign_config: dict, label: int, campaign_index: int) -> tuple[str, str, str]:
    side = "suspicious" if label else "benign"
    catalog = campaign_config["campaigns"][side]
    names = sorted(catalog)
    name = names[campaign_index % len(names)]
    cfg = catalog[name]
    intents = list(map(str, cfg.get("intents", []))) or ["unknown_intent"]
    relations = list(map(str, cfg.get("historical_relations", []))) or ["unknown_relation"]
    intent = intents[campaign_index % len(intents)]
    relation = relations[(campaign_index // max(1, len(names))) % len(relations)]
    return name, intent, relation


def _diverse_groups(rows: list[SessionRecord], *, min_size: int = 3, max_size: int = 5) -> list[list[SessionRecord]]:
    """Greedily build same-day groups with protocol diversity where possible."""
    by_protocol: dict[str, deque[SessionRecord]] = defaultdict(deque)
    for row in sorted(rows, key=lambda r: (r.start_ts, r.session_id)):
        by_protocol[row.protocol].append(row)
    groups: list[list[SessionRecord]] = []
    while sum(len(q) for q in by_protocol.values()) > 0:
        group: list[SessionRecord] = []
        protocols = sorted(by_protocol, key=lambda p: (-len(by_protocol[p]), p))
        # First pass: one from each available protocol.
        for protocol in protocols:
            if len(group) >= max_size:
                break
            if by_protocol[protocol]:
                group.append(by_protocol[protocol].popleft())
        # Fill the rest by largest remaining buckets.
        while len(group) < max_size:
            available = [p for p, q in by_protocol.items() if q]
            if not available:
                break
            protocol = max(available, key=lambda p: (len(by_protocol[p]), p))
            group.append(by_protocol[protocol].popleft())
        groups.append(sorted(group, key=lambda r: (r.start_ts, r.session_id)))
    # Merge tiny trailing groups into the previous group for useful campaign units.
    if len(groups) >= 2 and len(groups[-1]) < min_size:
        tail = groups.pop()
        groups[-1].extend(tail)
        groups[-1].sort(key=lambda r: (r.start_ts, r.session_id))
    return groups


def organize_campaign_sequences(
    records: list[SessionRecord],
    campaign_config: dict,
    *,
    seed: int,
) -> list[SessionRecord]:
    """Assign same-day multi-session campaign identity without changing wire controls.

    Counterfactual Stage-F rows are intentionally left untouched because their
    pair-level campaign identity is part of the counterfactual invariant.
    """
    if not records:
        return []
    if any(r.pair_id for r in records):
        return list(records)
    rng = random.Random(seed)
    buckets: dict[tuple[int, int], list[SessionRecord]] = defaultdict(list)
    for row in records:
        buckets[(int(row.simulated_day), int(row.label_binary))].append(row)
    output: list[SessionRecord] = []
    campaign_index = 0
    for (day, label) in sorted(buckets):
        groups = _diverse_groups(buckets[(day, label)])
        # Deterministically vary group order among days without moving events to
        # a different day or altering the session timestamp/wire profile.
        if len(groups) > 1 and rng.random() < 0.5:
            groups = list(reversed(groups))
        for group in groups:
            campaign_type, intent, relation = _catalog_entry(campaign_config, label, campaign_index)
            campaign_id = f"seq-d{day:02d}-l{label}-{seed:08x}-{campaign_index:06d}"
            protocol_count = len({r.protocol for r in group})
            sequence_profile = "multi_protocol" if protocol_count >= 2 else "single_protocol"
            size = len(group)
            for position, row in enumerate(sorted(group, key=lambda r: (r.start_ts, r.session_id))):
                output.append(
                    replace(
                        row,
                        campaign_id=campaign_id,
                        campaign_type=campaign_type,
                        label_family="benign" if label == 0 else campaign_type,
                        intent_profile=intent,
                        historical_relation=relation,
                        campaign_position=position,
                        campaign_size=size,
                        sequence_profile=sequence_profile,
                    )
                )
            campaign_index += 1
    return sorted(output, key=lambda r: (r.start_ts, r.session_id))
