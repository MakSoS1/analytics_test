from __future__ import annotations

import hashlib
import math
from collections import Counter, defaultdict
from dataclasses import replace
from ipaddress import ip_interface
from typing import Any, Callable

from .manifest import SessionRecord
from .v3_signal import (
    _copy_current_controls,
    _dt,
    audit_causal_observability,
    build_history_by_session,
    causal_history_signature,
)

SERVICE_ROLES = {
    "LinuxServer", "FileServer", "RDPServer", "VNCServer", "RPCServer", "ManagementServer",
}
DESTINATION_ROLE = {"ssh": "LinuxServer", "smb": "FileServer", "rdp": "RDPServer", "vnc": "VNCServer"}
SUSPICIOUS_FAMILIES = (
    "rare_pair", "new_protocol", "protocol_switch", "source_drift",
    "target_chain", "sudden_fanout", "low_slow_lateral",
)
BENIGN_FAMILIES = (
    "routine_admin", "scheduled_patch_fanout", "helpdesk", "backup_burst",
    "benign_first_seen", "offhours_emergency", "service_automation",
)
LOW_PRIVILEGE_ROLES = {"CompromisedWorkstation", "RegularUser", "RemoteWorker"}


def _stable_int(value: str, seed: int) -> int:
    return int.from_bytes(hashlib.sha256(f"{seed}|{value}".encode()).digest()[:8], "big")


def _bare_ip(value: str) -> str:
    return str(ip_interface(str(value)).ip)


def _source_hosts(topology: dict[str, Any]) -> list[dict[str, Any]]:
    return [host for host in topology["hosts"] if str(host["role"]) not in SERVICE_ROLES]


def _destination_hosts(topology: dict[str, Any], protocol: str) -> list[dict[str, Any]]:
    role = DESTINATION_ROLE[protocol]
    rows = sorted(
        [host for host in topology["hosts"] if str(host["role"]) == role],
        key=lambda host: str(host["id"]),
    )
    if not rows:
        raise ValueError(f"no destination hosts for {protocol}/{role}")
    return rows


def _balanced_source_subset(topology: dict[str, Any], row_count: int, *, seed: int) -> list[dict[str, Any]]:
    sources = _source_hosts(topology)
    if not sources:
        raise ValueError("V3 causal planner requires source endpoints")
    target = min(len(sources), max(20, min(len(sources), max(1, row_count // 20))))
    by_role: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for host in sources:
        by_role[str(host["role"])].append(host)
    for role, rows in by_role.items():
        rows.sort(key=lambda host: (_stable_int(f"source|{role}|{host['id']}", seed), str(host["id"])))
    selected: list[dict[str, Any]] = []
    while len(selected) < target:
        progressed = False
        for role in sorted(by_role):
            if by_role[role]:
                selected.append(by_role[role].pop(0))
                progressed = True
                if len(selected) >= target:
                    break
        if not progressed:
            break
    return selected


def _label_schedule(rows: list[SessionRecord]) -> dict[str, int]:
    """Ignore incoming labels and create warm-up-first exact 50/50 labels per protocol."""
    out: dict[str, int] = {}
    for protocol in sorted({row.protocol for row in rows}):
        part = sorted(
            [row for row in rows if row.protocol == protocol],
            key=lambda row: (_dt(row.start_ts), row.session_id),
        )
        if len(part) % 2:
            raise ValueError(f"causal V3 requires even per-protocol rows: {protocol}={len(part)}")
        half = len(part) // 2
        warm = min(half, max(1, len(part) // 5))
        schedule = [0] * warm
        benign_left = half - warm
        suspicious_left = half
        while benign_left or suspicious_left:
            if suspicious_left:
                schedule.append(1)
                suspicious_left -= 1
            if benign_left:
                schedule.append(0)
                benign_left -= 1
        for row, label in zip(part, schedule):
            out[row.session_id] = label
    return out


def _prior(source: dict[str, Any], history: dict[str, list[SessionRecord]]) -> list[SessionRecord]:
    return history.get(str(source["id"]), [])


def _has_pair(rows: list[SessionRecord], dst_id: str) -> bool:
    return any(row.dst_host_id == dst_id for row in rows)


def _has_protocol(rows: list[SessionRecord], protocol: str) -> bool:
    return any(row.protocol == protocol for row in rows)


def _choose(
    sources: list[dict[str, Any]], usage: Counter[str], predicate: Callable[[dict[str, Any]], bool],
    *, seed: int, salt: str,
) -> dict[str, Any] | None:
    candidates = [host for host in sources if predicate(host)]
    if not candidates:
        return None
    return min(
        candidates,
        key=lambda host: (usage[str(host["id"])], _stable_int(f"{salt}|{host['id']}", seed), str(host["id"])),
    )


def _known_destination(rows: list[SessionRecord], protocol: str, destinations: list[dict[str, Any]]) -> dict[str, Any]:
    lookup = {str(host["id"]): host for host in destinations}
    for previous in reversed(rows):
        if previous.protocol == protocol and previous.dst_host_id in lookup:
            return lookup[previous.dst_host_id]
    return destinations[0]


def _new_destination(rows: list[SessionRecord], destinations: list[dict[str, Any]], *, seed: int, salt: str) -> dict[str, Any]:
    unseen = [host for host in destinations if not _has_pair(rows, str(host["id"]))]
    candidates = unseen or destinations
    return min(candidates, key=lambda host: (_stable_int(f"{salt}|{host['id']}", seed), str(host["id"])))


def _seed_unused_normal_source(
    sources: list[dict[str, Any]], usage: Counter[str], *, seed: int, salt: str,
) -> dict[str, Any] | None:
    unused = [
        host for host in sources
        if usage[str(host["id"])] == 0 and str(host["role"]) != "CompromisedWorkstation"
    ]
    if not unused:
        return None
    return min(unused, key=lambda host: (_stable_int(f"warmup|{salt}|{host['id']}", seed), str(host["id"])))


def _benign_assignment(
    base: SessionRecord, sources: list[dict[str, Any]], history: dict[str, list[SessionRecord]],
    usage: Counter[str], topology: dict[str, Any], index: int, *, seed: int,
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    protocol = base.protocol
    destinations = _destination_hosts(topology, protocol)

    # First establish independent endpoint baselines. This is deliberate warm-up,
    # not random spreading: each endpoint needs its own production-observable state.
    seed_source = _seed_unused_normal_source(sources, usage, seed=seed, salt=base.session_id)
    if seed_source is not None:
        return seed_source, destinations[index % len(destinations)], "routine_admin", "baseline_warmup"

    family = BENIGN_FAMILIES[index % len(BENIGN_FAMILIES)]
    if family in {"routine_admin", "backup_burst", "scheduled_patch_fanout", "offhours_emergency"}:
        source = _choose(
            sources, usage,
            lambda host: _has_protocol(_prior(host, history), protocol),
            seed=seed, salt=f"benign-known|{base.session_id}",
        )
    elif family == "helpdesk":
        source = _choose(
            sources, usage,
            lambda host: str(host["role"]) == "Helpdesk" and bool(_prior(host, history)),
            seed=seed, salt=f"helpdesk|{base.session_id}",
        )
    elif family == "service_automation":
        source = _choose(
            sources, usage,
            lambda host: str(host["role"]) == "ServiceAccount" and bool(_prior(host, history)),
            seed=seed, salt=f"service|{base.session_id}",
        )
    else:
        source = _choose(
            sources, usage, lambda host: bool(_prior(host, history)),
            seed=seed, salt=f"benign-first-seen|{base.session_id}",
        )
    if source is None:
        source = _choose(
            sources, usage, lambda host: str(host["role"]) != "CompromisedWorkstation",
            seed=seed, salt=f"benign-fallback|{base.session_id}",
        ) or sources[0]

    prior = _prior(source, history)
    if family == "benign_first_seen":
        return source, _new_destination(prior, destinations, seed=seed, salt=base.session_id), family, "approved_new_pair"
    return source, _known_destination(prior, protocol, destinations), family, "known_or_expected_pair"


def _suspicious_assignment(
    base: SessionRecord, sources: list[dict[str, Any]], history: dict[str, list[SessionRecord]],
    usage: Counter[str], topology: dict[str, Any], index: int, *, seed: int,
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    protocol = base.protocol
    destinations = _destination_hosts(topology, protocol)
    requested = SUSPICIOUS_FAMILIES[index % len(SUSPICIOUS_FAMILIES)]

    def candidate(family: str) -> dict[str, Any] | None:
        if family == "source_drift":
            return _choose(
                sources, usage,
                lambda host: str(host["role"]) in LOW_PRIVILEGE_ROLES and len(_prior(host, history)) <= 1,
                seed=seed, salt=f"source-drift|{base.session_id}",
            )
        if family == "new_protocol":
            return _choose(
                sources, usage,
                lambda host: bool(_prior(host, history)) and not _has_protocol(_prior(host, history), protocol),
                seed=seed, salt=f"new-protocol|{base.session_id}",
            )
        if family == "protocol_switch":
            return _choose(
                sources, usage,
                lambda host: bool(_prior(host, history)) and _prior(host, history)[-1].protocol != protocol,
                seed=seed, salt=f"protocol-switch|{base.session_id}",
            )
        if family in {"target_chain", "sudden_fanout"}:
            return _choose(
                sources, usage,
                lambda host: len({row.dst_host_id for row in _prior(host, history)[-5:]}) >= 2,
                seed=seed, salt=f"fanout|{base.session_id}",
            )
        if family in {"rare_pair", "low_slow_lateral"}:
            return _choose(
                sources, usage,
                lambda host: bool(_prior(host, history)) and any(
                    not _has_pair(_prior(host, history), str(dst["id"])) for dst in destinations
                ),
                seed=seed, salt=f"rare-pair|{base.session_id}",
            )
        return None

    source = None
    family = requested
    for possible in (requested,) + tuple(name for name in SUSPICIOUS_FAMILIES if name != requested):
        source = candidate(possible)
        if source is not None:
            family = possible
            break

    if source is None:
        source = _choose(
            sources, usage, lambda host: bool(_prior(host, history)),
            seed=seed, salt=f"attack-fallback|{base.session_id}",
        )
        if source is not None:
            family = "new_protocol" if not _has_protocol(_prior(source, history), protocol) else "rare_pair"
        else:
            source = _choose(
                sources, usage, lambda host: str(host["role"]) in LOW_PRIVILEGE_ROLES,
                seed=seed, salt=f"drift-fallback|{base.session_id}",
            ) or sources[0]
            family = "source_drift"

    prior = _prior(source, history)
    destination = _new_destination(prior, destinations, seed=seed, salt=f"attack|{base.session_id}")
    relation = {
        "rare_pair": "new_or_rare_pair",
        "new_protocol": "source_protocol_novelty",
        "protocol_switch": "rapid_protocol_transition",
        "source_drift": "non_admin_source_admin_activity",
        "target_chain": "multi_target_chain",
        "sudden_fanout": "rapid_new_target_fanout",
        "low_slow_lateral": "sparse_new_pair",
    }[family]
    return source, destination, family, relation


def _materialize(
    base: SessionRecord, source: dict[str, Any], destination: dict[str, Any], *,
    label: int, family: str, relation: str, seed: int, index: int,
) -> SessionRecord:
    return replace(
        base,
        label_binary=label,
        label_family=family,
        campaign_type=family,
        scenario_id=f"v3_causal_{family}_{base.protocol}",
        campaign_id=f"v3causal-{seed:08x}-{index:05d}",
        pair_id="",
        src_role=str(source["role"]),
        src_host_id=str(source["id"]),
        src_ip=_bare_ip(str(source["ip"])),
        dst_role=str(destination["role"]),
        dst_host_id=str(destination["id"]),
        dst_ip=_bare_ip(str(destination["ip"])),
        intent_profile="approved_administration" if label == 0 else "unauthorized_lateral_movement",
        historical_relation=relation,
    )


def _pair_causally_separated(rows: list[SessionRecord], *, seed: int, matched_fraction: float) -> list[SessionRecord]:
    target_pairs = math.ceil(len(rows) * matched_fraction / 2.0)
    if target_pairs == 0:
        return rows
    histories = build_history_by_session(rows)
    by_protocol: dict[str, dict[int, list[SessionRecord]]] = defaultdict(lambda: {0: [], 1: []})
    for row in rows:
        by_protocol[row.protocol][int(row.label_binary)].append(row)
    for protocol in by_protocol:
        for label in (0, 1):
            by_protocol[protocol][label].sort(key=lambda row: (_stable_int(row.session_id, seed), row.session_id))

    used: set[str] = set()
    chosen: list[tuple[SessionRecord, SessionRecord]] = []
    while len(chosen) < target_pairs:
        progress = False
        for protocol in sorted(by_protocol):
            benign_rows = [row for row in by_protocol[protocol][0] if row.session_id not in used]
            attack_rows = [row for row in by_protocol[protocol][1] if row.session_id not in used]
            for benign in benign_rows:
                left = causal_history_signature(benign, histories.get(benign.session_id, []))
                attack = next(
                    (
                        row for row in attack_rows
                        if causal_history_signature(row, histories.get(row.session_id, [])) != left
                    ),
                    None,
                )
                if attack is None:
                    continue
                chosen.append((benign, attack))
                used.update({benign.session_id, attack.session_id})
                progress = True
                break
            if len(chosen) >= target_pairs:
                break
        if not progress:
            break
    if len(chosen) < target_pairs:
        raise ValueError(f"cannot build causal counterfactual coverage: pairs={len(chosen)} target={target_pairs}")

    replacements: dict[str, SessionRecord] = {}
    for index, (benign, attack) in enumerate(chosen):
        pair_id = f"v3cf-causal-{seed:08x}-{index:05d}"
        replacements[benign.session_id] = replace(benign, pair_id=pair_id)
        replacements[attack.session_id] = _copy_current_controls(benign, attack, pair_id)
    output = sorted(
        [replacements.get(row.session_id, row) for row in rows],
        key=lambda row: (_dt(row.start_ts), row.session_id),
    )
    report = audit_causal_observability(output)
    if not report["valid"] or report["causally_separated_counterfactual_pairs"] < target_pairs:
        raise ValueError(f"causal counterfactual audit failed: {report}")
    return output


def build_v3_causal_plan(
    records: list[SessionRecord], *, topology: dict[str, Any], seed: int, matched_fraction: float = 0.40,
) -> list[SessionRecord]:
    """Corrected V3: observable baseline/mutation first, binary label second."""
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
                base, sources, history, usage, topology, benign_index, seed=seed,
            )
            benign_index += 1
        else:
            source, destination, family, relation = _suspicious_assignment(
                base, sources, history, usage, topology, suspicious_index, seed=seed,
            )
            suspicious_index += 1
        row = _materialize(
            base, source, destination, label=label, family=family, relation=relation, seed=seed, index=index,
        )
        output.append(row)
        history[row.src_host_id].append(row)
        usage[row.src_host_id] += 1

    paired = _pair_causally_separated(output, seed=seed, matched_fraction=matched_fraction)
    per_protocol: dict[str, Counter[int]] = defaultdict(Counter)
    for row in paired:
        per_protocol[row.protocol][int(row.label_binary)] += 1
    for protocol, counts in per_protocol.items():
        if counts[0] != counts[1]:
            raise AssertionError(f"V3 causal protocol label imbalance {protocol}: {dict(counts)}")
    if not audit_causal_observability(paired)["valid"]:
        raise ValueError("V3 causal observability failed")
    return paired
