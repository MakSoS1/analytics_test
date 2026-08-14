from __future__ import annotations

import random
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from ipaddress import ip_interface
from pathlib import Path
from typing import Any

from .config import load_yaml, validate_scenarios, validate_topology
from .manifest import SessionRecord

PORTS = {"ssh": 22, "smb": 445, "rdp": 3389, "vnc": 5900, "dcerpc": 135, "winrm": 5985}
MITRE = {
    "ssh": "T1021.004",
    "smb": "T1021.002",
    "rdp": "T1021.001",
    "vnc": "T1021.005",
    "dcerpc": "T1021.003",
    "winrm": "T1021.006",
}
DST_ROLE_BY_PROTOCOL = {
    "ssh": "LinuxServer",
    "smb": "FileServer",
    "rdp": "RDPServer",
    "vnc": "VNCServer",
    "dcerpc": "RPCServer",
    "winrm": "ManagementServer",
}
CLIENT_STACKS = {
    "ssh": {"openssh"},
    "smb": {"smbclient"},
    "rdp": {"freerdp"},
    "vnc": {"rfb-python"},
    "winrm": {"curl-wsman"},
}


def _bare_ip(value: str) -> str:
    return str(ip_interface(value).ip)


def load_digital_twin_bundle(config_dir: Path | str) -> dict[str, Any]:
    root = Path(config_dir)
    return {
        "personas": load_yaml(root / "personas.yaml"),
        "tasks": load_yaml(root / "tasks.yaml"),
        "calendars": load_yaml(root / "calendars.yaml"),
        "behavior": load_yaml(root / "behavior_distributions.yaml"),
        "campaigns": load_yaml(root / "campaigns.yaml"),
    }


def expand_personas(config: dict[str, Any]) -> list[dict[str, Any]]:
    templates = config.get("persona_templates", [])
    out: list[dict[str, Any]] = []
    for template in templates:
        count = int(template.get("count", 0))
        if count <= 0:
            raise ValueError(f"persona template {template.get('template_id')} has invalid count")
        for idx in range(count):
            row = dict(template)
            row["persona_id"] = f"{template['template_id']}-{idx + 1:02d}"
            row.pop("count", None)
            out.append(row)
    return out


def validate_digital_twin(bundle: dict[str, Any], topology: dict[str, Any]) -> None:
    validate_topology(topology)
    personas = expand_personas(bundle["personas"])
    if len(personas) != 58:
        raise ValueError(f"digital twin must expand to 58 personas, got {len(personas)}")
    calendars = bundle["calendars"].get("calendars", {})
    tasks = bundle["tasks"].get("tasks", {})
    profiles = bundle["behavior"].get("behavior_profiles", {})
    campaigns = bundle["campaigns"].get("campaigns", {})
    actual_source_roles = {str(h["role"]) for h in topology["hosts"]}
    for persona in personas:
        if persona.get("calendar_id") not in calendars:
            raise ValueError(f"unknown persona calendar: {persona.get('calendar_id')}")
        weights = persona.get("task_weights", {})
        if not weights:
            raise ValueError(f"persona without tasks: {persona['persona_id']}")
        if not set(weights) <= set(tasks):
            raise ValueError(f"persona references unknown task: {persona['persona_id']}")
        endpoint_roles = set(map(str, persona.get("source_endpoint_roles", [])))
        if not endpoint_roles or not endpoint_roles <= actual_source_roles:
            raise ValueError(f"persona source endpoint role unavailable: {persona['persona_id']}")
    if not profiles:
        raise ValueError("behavior profiles are required")
    if not campaigns.get("benign") or not campaigns.get("suspicious"):
        raise ValueError("both benign and suspicious campaign catalogs are required")
    simulation = bundle["calendars"].get("simulation", {})
    if int(simulation.get("days", 0)) < 30:
        raise ValueError("digital twin history must span at least 30 simulated days")


def _weighted_choice(rng: random.Random, weights: dict[str, Any]) -> str:
    names = sorted(weights)
    values = [max(0.0, float(weights[name])) for name in names]
    if sum(values) <= 0:
        raise ValueError("all task weights are zero")
    return rng.choices(names, weights=values, k=1)[0]


def _hosts_for_roles(topology: dict[str, Any], roles: list[str]) -> list[dict[str, Any]]:
    allowed = set(map(str, roles))
    return [h for h in topology["hosts"] if str(h["role"]) in allowed]


def _compatible_task_protocols(persona: dict[str, Any], tasks: dict[str, Any]) -> list[tuple[str, str]]:
    stacks = set(map(str, persona.get("client_stacks", [])))
    pairs: list[tuple[str, str]] = []
    for task_id in sorted(persona["task_weights"]):
        for protocol in tasks[task_id].get("protocols", []):
            needed = CLIENT_STACKS.get(str(protocol), set())
            if not needed or stacks & needed:
                pairs.append((task_id, str(protocol)))
    if not pairs:
        raise ValueError(f"persona {persona['persona_id']} has no compatible task/protocol")
    return pairs


def _client_stack(persona: dict[str, Any], protocol: str) -> str:
    available = sorted(set(map(str, persona.get("client_stacks", []))) & CLIENT_STACKS.get(protocol, set()))
    if available:
        return available[0]
    fallback = {"ssh": "openssh", "smb": "smbclient", "rdp": "freerdp", "vnc": "rfb-python", "winrm": "curl-wsman"}
    return fallback.get(protocol, "native-client")


def _action(protocol: str, behavior_profile: str) -> str:
    if protocol == "ssh":
        if behavior_profile in {"small_transfer", "bulk_transfer"}:
            return "inert_sftp_transfer"
        if behavior_profile in {"reconnect", "maintenance_fanout"}:
            return "repeated_login"
        return "harmless_exec"
    if protocol == "smb":
        return "inert_marker_put" if behavior_profile in {"small_transfer", "bulk_transfer", "maintenance_fanout"} else "list_and_fetch"
    if protocol in {"rdp", "vnc"}:
        return "bounded_session"
    if protocol == "winrm":
        return "wsman_probe"
    if protocol == "dcerpc":
        return "rpc_query"
    raise ValueError(protocol)


def _fidelity(protocol: str) -> tuple[str, str]:
    return {
        "ssh": ("real_ssh", "high"),
        "smb": ("real_smb", "partial_admin_share"),
        "rdp": ("real_rdp_linux", "partial_windows"),
        "vnc": ("real_rfb", "partial_client_interaction"),
        "dcerpc": ("real_dcerpc_samba", "partial_dcom"),
        "winrm": ("wsman_http", "partial_winrm"),
    }[protocol]


def _timeline_timestamp(
    rng: random.Random, calendar: dict[str, Any], simulation: dict[str, Any], index: int, count: int
) -> tuple[datetime, int]:
    start = datetime.fromisoformat(str(simulation["start"])).astimezone(timezone.utc)
    days = int(simulation["days"])
    if count <= 1:
        day = 0
    else:
        day = min(days - 1, round(index * (days - 1) / (count - 1)))
    date = start + timedelta(days=day)
    ranges = calendar.get("hour_ranges", [[8, 18]])
    hour_range = ranges[(index + day) % len(ranges)]
    low, high = int(hour_range[0]), int(hour_range[1])
    hour = low if high <= low else rng.randrange(low, high)
    minute = rng.randrange(0, 60)
    second = rng.randrange(0, 60)
    return date.replace(hour=hour % 24, minute=minute, second=second), day


def _campaign_context(bundle: dict[str, Any], label: int, index: int) -> tuple[str, str, str]:
    side = "suspicious" if label else "benign"
    catalog = bundle["campaigns"]["campaigns"][side]
    names = sorted(catalog)
    name = names[index % len(names)]
    cfg = catalog[name]
    intents = list(cfg.get("intents", []))
    relations = list(cfg.get("historical_relations", []))
    intent = str(intents[index % len(intents)])
    relation = str(relations[(index // max(1, len(names))) % len(relations)])
    return name, intent, relation


def _make_one(
    *,
    topology: dict[str, Any],
    bundle: dict[str, Any],
    netem_profiles: list[str],
    rng: random.Random,
    persona: dict[str, Any],
    task_id: str,
    protocol: str,
    behavior_profile: str,
    label: int,
    stage: str,
    index: int,
    count: int,
    seed: int,
    pair_id: str = "",
    forced_src: dict[str, Any] | None = None,
    forced_dst: dict[str, Any] | None = None,
    forced_start: datetime | None = None,
    forced_duration: int | None = None,
    forced_netem: str | None = None,
    forced_client: str | None = None,
    forced_auth: str | None = None,
) -> SessionRecord:
    tasks = bundle["tasks"]["tasks"]
    calendar_cfg = bundle["calendars"]["calendars"][persona["calendar_id"]]
    simulation = bundle["calendars"]["simulation"]
    src_candidates = _hosts_for_roles(topology, list(persona["source_endpoint_roles"]))
    dst_candidates = _hosts_for_roles(topology, [DST_ROLE_BY_PROTOCOL[protocol]])
    if not src_candidates or not dst_candidates:
        raise ValueError(f"no endpoints for {persona['persona_id']} {protocol}")
    src = forced_src or src_candidates[(index + seed) % len(src_candidates)]
    dst = forced_dst or dst_candidates[(index * 3 + seed) % len(dst_candidates)]
    if forced_start is None:
        start, simulated_day = _timeline_timestamp(rng, calendar_cfg, simulation, index, count)
    else:
        start = forced_start
        sim_start = datetime.fromisoformat(str(simulation["start"])).astimezone(timezone.utc)
        simulated_day = max(0, (start.date() - sim_start.date()).days)
    profile_cfg = bundle["behavior"]["behavior_profiles"][behavior_profile]
    duration_range = list(profile_cfg.get("duration_seconds", [60, 300]))
    duration = forced_duration if forced_duration is not None else rng.randint(int(duration_range[0]), int(duration_range[1]))
    end = start + timedelta(seconds=duration)
    auths = list(map(str, profile_cfg.get("auth_outcomes", ["success"])))
    auth = forced_auth or auths[(index + seed) % len(auths)]
    campaign_type, intent, relation = _campaign_context(bundle, label, index)
    wire, semantic = _fidelity(protocol)
    client = forced_client or _client_stack(persona, protocol)
    netem_profile = forced_netem or netem_profiles[(index + seed) % len(netem_profiles)]
    campaign_slot = max(1, 3 + ((index + seed) % 11))
    campaign_id = f"dt-{stage.lower()}-{seed:08x}-{campaign_type}-{index // campaign_slot:06d}"
    return SessionRecord(
        campaign_id=campaign_id,
        scenario_id=f"dt_{task_id}_{protocol}",
        session_id=f"dt-ses-{stage.lower()}-{seed:08x}-{index:07d}",
        pair_id=pair_id,
        label_binary=label,
        label_family="benign" if label == 0 else campaign_type,
        mitre_technique=MITRE[protocol],
        src_role=str(persona["role"]),
        dst_role=str(dst["role"]),
        src_host_id=str(src["id"]),
        dst_host_id=str(dst["id"]),
        src_ip=_bare_ip(str(src["ip"])),
        dst_ip=_bare_ip(str(dst["ip"])),
        src_port=0,
        dst_port=PORTS[protocol],
        protocol=protocol,
        action=_action(protocol, behavior_profile),
        wire_fidelity=wire,
        semantic_fidelity=semantic,
        ground_truth_source="scenario_orchestrator",
        netem_profile=netem_profile,
        generator_seed=seed,
        start_ts=start.isoformat(),
        end_ts=end.isoformat(),
        status="planned",
        persona_id=str(persona["persona_id"]),
        task_id=task_id,
        calendar_id=str(persona["calendar_id"]),
        intent_profile=intent,
        behavior_profile=behavior_profile,
        campaign_type=campaign_type,
        historical_relation=relation,
        auth_outcome=auth,
        client_stack=client,
        simulated_day=simulated_day,
    )


def plan_digital_twin_sessions(
    topology: dict[str, Any],
    scenarios: dict[str, Any],
    netem: dict[str, Any],
    bundle: dict[str, Any],
    *,
    seed: int,
    count: int,
    stage: str,
) -> list[SessionRecord]:
    validate_topology(topology)
    validate_scenarios(scenarios, topology)
    validate_digital_twin(bundle, topology)
    if stage not in set("ABCDEFGH"):
        raise ValueError("stage must be A-H")
    if count <= 0:
        raise ValueError("count must be positive")
    profiles = sorted(netem.get("profiles", {}))
    if not profiles:
        raise ValueError("at least one netem profile required")
    personas = expand_personas(bundle["personas"])
    tasks = bundle["tasks"]["tasks"]
    protocol_pools = bundle["behavior"]["protocol_profile_pool"]
    rng = random.Random(seed)

    if stage == "F":
        records: list[SessionRecord] = []
        pair_total = count // 2
        for pair_index in range(pair_total):
            persona = personas[pair_index % len(personas)]
            compatible = _compatible_task_protocols(persona, tasks)
            task_id, protocol = compatible[(pair_index + seed) % len(compatible)]
            behavior_profile = list(protocol_pools[protocol])[(pair_index * 5 + seed) % len(protocol_pools[protocol])]
            src_candidates = _hosts_for_roles(topology, list(persona["source_endpoint_roles"]))
            dst_candidates = _hosts_for_roles(topology, [DST_ROLE_BY_PROTOCOL[protocol]])
            src = src_candidates[(pair_index + seed) % len(src_candidates)]
            dst = dst_candidates[(pair_index + seed) % len(dst_candidates)]
            calendar = bundle["calendars"]["calendars"][persona["calendar_id"]]
            start, _ = _timeline_timestamp(rng, calendar, bundle["calendars"]["simulation"], pair_index, max(1, pair_total))
            profile_cfg = bundle["behavior"]["behavior_profiles"][behavior_profile]
            dr = profile_cfg["duration_seconds"]
            duration = rng.randint(int(dr[0]), int(dr[1]))
            auths = list(map(str, profile_cfg.get("auth_outcomes", ["success"])))
            auth = auths[(pair_index + seed) % len(auths)]
            client = _client_stack(persona, protocol)
            netem_profile = profiles[(pair_index + seed) % len(profiles)]
            pair_id = f"dt-pair-{seed:08x}-{pair_index:06d}"
            base = _make_one(
                topology=topology, bundle=bundle, netem_profiles=profiles, rng=rng, persona=persona,
                task_id=task_id, protocol=protocol, behavior_profile=behavior_profile, label=0,
                stage=stage, index=pair_index * 2, count=count, seed=seed, pair_id=pair_id,
                forced_src=src, forced_dst=dst, forced_start=start, forced_duration=duration,
                forced_netem=netem_profile, forced_client=client, forced_auth=auth,
            )
            attack = _make_one(
                topology=topology, bundle=bundle, netem_profiles=profiles, rng=rng, persona=persona,
                task_id=task_id, protocol=protocol, behavior_profile=behavior_profile, label=1,
                stage=stage, index=pair_index * 2 + 1, count=count, seed=seed, pair_id=pair_id,
                forced_src=src, forced_dst=dst, forced_start=start, forced_duration=duration,
                forced_netem=netem_profile, forced_client=client, forced_auth=auth,
            )
            # Pair identity and wire controls are identical; only intent/history
            # context differs. Keep campaign grouping common as well.
            attack = replace(attack, campaign_id=base.campaign_id)
            records.extend([base, attack])
        if count % 2:
            records.append(records[-2])
        return records[:count]

    policy = bundle["campaigns"].get("stage_policy", {}).get(stage, {})
    suspicious_fraction = float(policy.get("suspicious_fraction", scenarios["stage_defaults"][stage]["suspicious_fraction"]))
    suspicious_target = round(count * suspicious_fraction)
    labels = [1] * suspicious_target + [0] * (count - suspicious_target)
    rng.shuffle(labels)
    records = []
    for index, label in enumerate(labels):
        persona = personas[(index * 7 + seed) % len(personas)]
        compatible = _compatible_task_protocols(persona, tasks)
        task_id, protocol = compatible[(index * 3 + seed) % len(compatible)]
        task_profiles = [p for p in tasks[task_id].get("behavior_profiles", []) if p in protocol_pools[protocol]]
        candidates = task_profiles or list(protocol_pools[protocol])
        behavior_profile = candidates[(index * 5 + seed) % len(candidates)]
        records.append(
            _make_one(
                topology=topology, bundle=bundle, netem_profiles=profiles, rng=rng, persona=persona,
                task_id=task_id, protocol=protocol, behavior_profile=behavior_profile, label=label,
                stage=stage, index=index, count=count, seed=seed,
            )
        )
    records.sort(key=lambda row: (row.start_ts, row.session_id))
    return records
