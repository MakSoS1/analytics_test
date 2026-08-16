from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import replace
from typing import Any

from .manifest import SessionRecord
from .v3_causal import (
    _balanced_source_subset,
    _benign_assignment,
    _label_schedule,
    _materialize,
    _stable_int,
    _suspicious_assignment,
)
from .v3_signal import (
    _copy_current_controls,
    _dt,
    audit_causal_observability,
    build_history_by_session,
    causal_history_signature,
)


_STRONG_HISTORY_FIELDS = (
    "pair_seen_count_prior",
    "new_destination_for_source",
    "new_protocol_for_source",
    "protocol_seen_count_prior",
    "distinct_dst_prior",
    "source_sessions_prior",
)


def _history_separation_score(left: dict[str, int | float], right: dict[str, int | float]) -> tuple[int, int]:
    strong = sum(int(left.get(name) != right.get(name)) for name in _STRONG_HISTORY_FIELDS)
    total = sum(int(left.get(name) != right.get(name)) for name in sorted(set(left) | set(right)))
    return strong, total


def _provisional_output(
    rows: list[SessionRecord],
    accepted: list[tuple[SessionRecord, SessionRecord]],
    *,
    seed: int,
) -> list[SessionRecord]:
    replacements: dict[str, SessionRecord] = {}
    for index, (benign, attack) in enumerate(accepted):
        pair_id = f"v3cf-causal-{seed:08x}-{index:05d}"
        replacements[benign.session_id] = replace(benign, pair_id=pair_id)
        replacements[attack.session_id] = _copy_current_controls(benign, attack, pair_id)
    return sorted(
        [replacements.get(row.session_id, row) for row in rows],
        key=lambda row: (_dt(row.start_ts), row.session_id),
    )


def _candidate_score(
    benign: SessionRecord,
    attack: SessionRecord,
    histories: dict[str, list[SessionRecord]],
) -> tuple[int, int]:
    left = causal_history_signature(benign, histories.get(benign.session_id, []))
    trial_attack = _copy_current_controls(benign, attack, "__trial__")
    right = causal_history_signature(trial_attack, histories.get(attack.session_id, []))
    return _history_separation_score(left, right)


def _pair_causally_separated_stable(
    rows: list[SessionRecord],
    *,
    seed: int,
    matched_fraction: float,
) -> list[SessionRecord]:
    """Choose matched twins that remain causally distinct after final replay.

    Matching current-session time can reorder one row relative to other events on
    the same simulated day. Therefore a pair is not accepted solely from its
    pre-copy history. Each candidate is inserted into a provisional corpus and
    the complete counterfactual audit is replayed. A candidate that makes *any*
    accepted pair semantic-only is rejected.
    """
    if not 0.0 <= matched_fraction <= 1.0:
        raise ValueError("matched_fraction must be in [0,1]")
    target_pairs = math.ceil(len(rows) * matched_fraction / 2.0)
    if target_pairs == 0:
        return sorted(rows, key=lambda row: (_dt(row.start_ts), row.session_id))

    base_histories = build_history_by_session(rows)
    by_protocol: dict[str, dict[int, list[SessionRecord]]] = defaultdict(lambda: {0: [], 1: []})
    for row in rows:
        by_protocol[row.protocol][int(row.label_binary)].append(row)
    for protocol in by_protocol:
        for label in (0, 1):
            by_protocol[protocol][label].sort(
                key=lambda row: (_stable_int(f"pair|{row.session_id}", seed), row.session_id)
            )

    used: set[str] = set()
    accepted: list[tuple[SessionRecord, SessionRecord]] = []
    protocols = sorted(by_protocol)
    stalled_rounds = 0
    while len(accepted) < target_pairs:
        progress = False
        for protocol in protocols:
            benign_rows = [row for row in by_protocol[protocol][0] if row.session_id not in used]
            attack_rows = [row for row in by_protocol[protocol][1] if row.session_id not in used]
            if not benign_rows or not attack_rows:
                continue

            # Prefer candidates with multiple strong causal differences so their
            # separation is robust to a small same-day timestamp adjustment.
            ranked: list[tuple[int, int, int, str, SessionRecord, SessionRecord]] = []
            for benign in benign_rows[:20]:
                for attack in attack_rows[:40]:
                    strong, total = _candidate_score(benign, attack, base_histories)
                    if strong <= 0 or total <= 0:
                        continue
                    ranked.append(
                        (
                            -strong,
                            -total,
                            _stable_int(f"candidate|{benign.session_id}|{attack.session_id}", seed),
                            benign.session_id + "|" + attack.session_id,
                            benign,
                            attack,
                        )
                    )
            ranked.sort(key=lambda item: item[:4])

            for _, _, _, _, benign, attack in ranked:
                trial_pairs = accepted + [(benign, attack)]
                trial_output = _provisional_output(rows, trial_pairs, seed=seed)
                report = audit_causal_observability(trial_output)
                if report["valid"] and report["causally_separated_counterfactual_pairs"] == len(trial_pairs):
                    accepted.append((benign, attack))
                    used.update({benign.session_id, attack.session_id})
                    progress = True
                    break
            if len(accepted) >= target_pairs:
                break

        if not progress:
            stalled_rounds += 1
            # Expand deterministic candidate ordering once before failing. In
            # normal 1k V3 data the first round has ample candidates.
            if stalled_rounds > 1:
                break
            for protocol in protocols:
                for label in (0, 1):
                    by_protocol[protocol][label].sort(
                        key=lambda row: (_stable_int(f"retry|{row.session_id}", seed), row.session_id)
                    )
        else:
            stalled_rounds = 0

    if len(accepted) < target_pairs:
        raise ValueError(
            f"cannot build replay-stable causal counterfactual coverage: pairs={len(accepted)} target={target_pairs}"
        )

    output = _provisional_output(rows, accepted, seed=seed)
    final_report = audit_causal_observability(output)
    if not final_report["valid"]:
        raise ValueError(f"final replay-stable causal counterfactual audit failed: {final_report}")
    if final_report["causally_separated_counterfactual_pairs"] != target_pairs:
        raise ValueError(f"final causal pair count mismatch: {final_report}")
    return output


def build_v3_causal_plan(
    records: list[SessionRecord],
    *,
    topology: dict[str, Any],
    seed: int,
    matched_fraction: float = 0.40,
) -> list[SessionRecord]:
    """Corrected in-place V3 causal planner used by NGFW training/release."""
    if not records:
        return []
    if not 0.0 <= matched_fraction <= 1.0:
        raise ValueError("matched_fraction must be in [0,1]")

    labels = _label_schedule(records)
    sources = _balanced_source_subset(topology, len(records), seed=seed)
    if len(sources) < min(20, len(records)):
        raise ValueError(f"insufficient causal source diversity: {len(sources)}")

    history: dict[str, list[SessionRecord]] = defaultdict(list)
    usage: Counter[str] = Counter()
    output: list[SessionRecord] = []
    benign_index = 0
    suspicious_index = 0
    for index, base in enumerate(sorted(records, key=lambda row: (_dt(row.start_ts), row.session_id))):
        label = labels[base.session_id]
        if label == 0:
            source, destination, family, relation = _benign_assignment(
                base, sources, history, usage, topology, benign_index, seed=seed
            )
            benign_index += 1
        else:
            source, destination, family, relation = _suspicious_assignment(
                base, sources, history, usage, topology, suspicious_index, seed=seed
            )
            suspicious_index += 1
        row = _materialize(
            base,
            source,
            destination,
            label=label,
            family=family,
            relation=relation,
            seed=seed,
            index=index,
        )
        output.append(row)
        history[row.src_host_id].append(row)
        usage[row.src_host_id] += 1

    paired = _pair_causally_separated_stable(
        output,
        seed=seed,
        matched_fraction=matched_fraction,
    )
    per_protocol: dict[str, Counter[int]] = defaultdict(Counter)
    for row in paired:
        per_protocol[row.protocol][int(row.label_binary)] += 1
    for protocol, counts in per_protocol.items():
        if counts[0] != counts[1]:
            raise AssertionError(f"V3 causal protocol label imbalance {protocol}: {dict(counts)}")

    final = audit_causal_observability(paired)
    if not final["valid"]:
        raise ValueError(f"V3 causal observability failed after stable pairing: {final}")
    return paired
