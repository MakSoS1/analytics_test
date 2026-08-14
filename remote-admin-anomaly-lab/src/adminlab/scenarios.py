from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from ipaddress import ip_interface
from typing import Any

from .config import validate_scenarios, validate_topology
from .manifest import SessionRecord

PORTS = {
    "ssh": 22,
    "smb": 445,
    "rdp": 3389,
    "vnc": 5900,
    "dcerpc": 135,
    "winrm": 5985,
}

MITRE = {
    "ssh": "T1021.004",
    "smb": "T1021.002",
    "rdp": "T1021.001",
    "vnc": "T1021.005",
    "dcerpc": "T1021.003",
    "winrm": "T1021.006",
}


def _bare_ip(value: str) -> str:
    return str(ip_interface(value).ip)


def _hosts_by_role(topology: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for host in topology["hosts"]:
        result.setdefault(str(host["role"]), []).append(host)
    return result


def _eligible_families(
    topology: dict[str, Any], scenarios: dict[str, Any], stage: str, label: str | None = None
) -> list[tuple[str, dict[str, Any]]]:
    by_role = _hosts_by_role(topology)
    out: list[tuple[str, dict[str, Any]]] = []
    for name, family in sorted(scenarios["scenario_families"].items()):
        if stage not in family["stages"]:
            continue
        if label is not None and label not in family["labels"]:
            continue
        if not any(role in by_role for role in family["src_roles"]):
            continue
        if not any(role in by_role for role in family["dst_roles"]):
            continue
        out.append((name, family))
    if not out:
        raise ValueError(f"no eligible scenario family for stage={stage} label={label}")
    return out


def _choose_host(rng: random.Random, by_role: dict[str, list[dict]], allowed_roles: list[str]) -> dict:
    roles = [role for role in allowed_roles if by_role.get(role)]
    role = roles[rng.randrange(len(roles))]
    hosts = by_role[role]
    return hosts[rng.randrange(len(hosts))]


def _make_record(
    *,
    rng: random.Random,
    topology: dict[str, Any],
    family_name: str,
    family: dict[str, Any],
    label_binary: int,
    stage: str,
    index: int,
    seed: int,
    netem_profile: str,
    pair_id: str = "",
    forced_dst: dict[str, Any] | None = None,
) -> SessionRecord:
    by_role = _hosts_by_role(topology)
    src = _choose_host(rng, by_role, list(family["src_roles"]))
    dst = forced_dst or _choose_host(rng, by_role, list(family["dst_roles"]))
    protocol = str(family["protocol"])
    start = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc) + timedelta(
        seconds=index * 7 + rng.randrange(0, 5)
    )
    duration = 2 + rng.randrange(0, 180)
    end = start + timedelta(seconds=duration)
    campaign_index = index // 8
    campaign_id = f"cmp-{stage.lower()}-{seed:08x}-{campaign_index:06d}"
    session_id = f"ses-{stage.lower()}-{seed:08x}-{index:07d}"
    return SessionRecord(
        campaign_id=campaign_id,
        scenario_id=family_name,
        session_id=session_id,
        pair_id=pair_id,
        label_binary=label_binary,
        label_family="benign" if label_binary == 0 else family_name,
        mitre_technique=MITRE[protocol],
        src_role=str(src["role"]),
        dst_role=str(dst["role"]),
        src_host_id=str(src["id"]),
        dst_host_id=str(dst["id"]),
        src_ip=_bare_ip(str(src["ip"])),
        dst_ip=_bare_ip(str(dst["ip"])),
        src_port=49152 + rng.randrange(0, 16384),
        dst_port=PORTS[protocol],
        protocol=protocol,
        action=str(family["action"]),
        wire_fidelity=str(family["wire_fidelity"]),
        semantic_fidelity=str(family["semantic_fidelity"]),
        ground_truth_source="scenario_orchestrator",
        netem_profile=netem_profile,
        generator_seed=seed,
        start_ts=start.isoformat(),
        end_ts=end.isoformat(),
        status="planned",
    )


def plan_sessions(
    topology: dict[str, Any],
    scenarios: dict[str, Any],
    netem: dict[str, Any],
    *,
    seed: int,
    count: int,
    stage: str,
) -> list[SessionRecord]:
    validate_topology(topology)
    validate_scenarios(scenarios, topology)
    if stage not in set("ABCDEFGH"):
        raise ValueError("stage must be A-H")
    if count <= 0:
        raise ValueError("count must be positive")
    profiles = sorted(netem.get("profiles", {}))
    if not profiles:
        raise ValueError("at least one netem profile is required")

    rng = random.Random(seed)
    defaults = scenarios["stage_defaults"][stage]
    suspicious_fraction = float(defaults["suspicious_fraction"])
    records: list[SessionRecord] = []

    if stage == "F":
        pair_families = [
            item
            for item in _eligible_families(topology, scenarios, stage)
            if set(item[1]["labels"]) == {"benign", "suspicious"}
        ]
        pair_count = count // 2
        by_role = _hosts_by_role(topology)
        for pair_index in range(pair_count):
            family_name, family = pair_families[pair_index % len(pair_families)]
            profile = profiles[pair_index % len(profiles)]
            forced_dst = _choose_host(rng, by_role, list(family["dst_roles"]))
            pair_id = f"pair-{seed:08x}-{pair_index:06d}"
            base_index = pair_index * 2
            records.append(
                _make_record(
                    rng=rng,
                    topology=topology,
                    family_name=family_name,
                    family=family,
                    label_binary=0,
                    stage=stage,
                    index=base_index,
                    seed=seed,
                    netem_profile=profile,
                    pair_id=pair_id,
                    forced_dst=forced_dst,
                )
            )
            records.append(
                _make_record(
                    rng=rng,
                    topology=topology,
                    family_name=family_name,
                    family=family,
                    label_binary=1,
                    stage=stage,
                    index=base_index + 1,
                    seed=seed,
                    netem_profile=profile,
                    pair_id=pair_id,
                    forced_dst=forced_dst,
                )
            )
        if len(records) < count:
            family_name, family = pair_families[0]
            records.append(
                _make_record(
                    rng=rng,
                    topology=topology,
                    family_name=family_name,
                    family=family,
                    label_binary=0,
                    stage=stage,
                    index=len(records),
                    seed=seed,
                    netem_profile=profiles[len(records) % len(profiles)],
                )
            )
        return records

    suspicious_target = round(count * suspicious_fraction)
    benign_target = count - suspicious_target
    labels = [1] * suspicious_target + [0] * benign_target
    rng.shuffle(labels)
    family_cache = {
        0: _eligible_families(topology, scenarios, stage, "benign"),
        1: _eligible_families(topology, scenarios, stage, "suspicious"),
    }
    for index, label_binary in enumerate(labels):
        candidates = family_cache[label_binary]
        family_name, family = candidates[index % len(candidates)]
        profile = profiles[index % len(profiles)]
        records.append(
            _make_record(
                rng=rng,
                topology=topology,
                family_name=family_name,
                family=family,
                label_binary=label_binary,
                stage=stage,
                index=index,
                seed=seed,
                netem_profile=profile,
            )
        )
    return records
