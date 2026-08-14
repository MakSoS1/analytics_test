from __future__ import annotations
from ipaddress import ip_interface,ip_network
from pathlib import Path
from typing import Any
import yaml
FORBIDDEN_FEATURE_COLUMNS:set[str]={
 'scenario_id','campaign_id','session_id','pair_id','generator_seed','expected_sid','attack_marker','capture_filename','ground_truth_source','wire_fidelity','semantic_fidelity',
 'persona_id','task_id','calendar_id','intent_profile','behavior_profile','campaign_type','historical_relation','client_stack','simulated_day','wire_attempts','wire_transfer_bytes','execution_start_ts','execution_end_ts',
}
def load_yaml(path:Path|str)->dict[str,Any]:
    with Path(path).open('r',encoding='utf-8') as fh:data=yaml.safe_load(fh)
    if not isinstance(data,dict):raise ValueError(f'expected mapping in {path}')
    return data
def _require_unique(values:list[str],what:str)->None:
    if len(values)!=len(set(values)):raise ValueError(f'duplicate {what}')
def validate_topology(data:dict[str,Any])->None:
    lab=data.get('lab');hosts=data.get('hosts')
    if not isinstance(lab,dict) or not isinstance(hosts,list) or not hosts:raise ValueError('topology requires lab mapping and non-empty hosts list')
    if lab.get('external_routing') is not False:raise ValueError('external routing must be disabled')
    network=ip_network(str(lab['cidr']),strict=True);bridge=ip_interface(str(lab['bridge_ip']))
    if bridge.ip not in network:raise ValueError('bridge ip outside lab cidr')
    ids=[str(h['id']) for h in hosts];namespaces=[str(h['namespace']) for h in hosts];ips=[str(h['ip']) for h in hosts];_require_unique(ids,'host id');_require_unique(namespaces,'host namespace');_require_unique(ips,'host ip')
    known_roles=set(map(str,data.get('known_roles',[])));known_protocols=set(map(str,data.get('known_protocols',[])))
    if not known_roles or not known_protocols:raise ValueError('known_roles and known_protocols must be non-empty')
    for host in hosts:
        iface=ip_interface(str(host['ip']))
        if iface.ip not in network:raise ValueError(f"host ip outside lab cidr: {host['id']}")
        if str(host['role']) not in known_roles:raise ValueError(f"unknown role: {host['role']}")
        for service in host.get('services',[]):
            if str(service) not in known_protocols:raise ValueError(f'unknown protocol: {service}')
def validate_scenarios(data:dict[str,Any],topology:dict[str,Any])->None:
    validate_topology(topology);families=data.get('scenario_families')
    if not isinstance(families,dict) or not families:raise ValueError('scenario_families must be non-empty')
    known_roles=set(map(str,topology['known_roles']));known_protocols=set(map(str,topology['known_protocols']));valid_stages=set('ABCDEFGH');valid_labels={'benign','suspicious'}
    for name,family in families.items():
        if family.get('protocol') not in known_protocols:raise ValueError(f"unknown protocol in {name}: {family.get('protocol')}")
        if not set(map(str,family.get('stages',[])))<=valid_stages:raise ValueError(f'unknown stage in {name}')
        if not set(map(str,family.get('labels',[])))<=valid_labels:raise ValueError(f'unknown label in {name}')
        for role in family.get('src_roles',[])+family.get('dst_roles',[]):
            if str(role) not in known_roles:raise ValueError(f'unknown role in {name}: {role}')
    safety=data.get('safety',{})
    if safety.get('allow_external_targets') is not False:raise ValueError('external targets must be disabled')
    if safety.get('allow_proxy_forwarding') is not False:raise ValueError('proxy forwarding must be disabled')
    if safety.get('allow_payload_execution') is not False:raise ValueError('payload execution must be disabled')
    lab_network=ip_network(str(topology['lab']['cidr']),strict=True);allowed_network=ip_network(str(safety['allowed_destination_cidr']),strict=True)
    if not allowed_network.subnet_of(lab_network):raise ValueError('scenario destination cidr must stay inside lab cidr')
def validate_feature_contract(data:dict[str,Any])->None:
    allowlist=set(map(str,data.get('production_allowlist',[])));forbidden=set(map(str,data.get('forbidden',[])))|FORBIDDEN_FEATURE_COLUMNS;training_only=set(map(str,data.get('training_only',[])))
    if not allowlist:raise ValueError('production allowlist must be non-empty')
    overlap=allowlist&forbidden
    if overlap:raise ValueError(f'forbidden production feature: {sorted(overlap)[0]}')
    if allowlist&training_only:raise ValueError('training-only column present in production allowlist')
    required={'connections_1m','connections_5m','connections_15m','connections_1h','connections_24h','connections_7d','connections_30d'}
    if not required<=allowlist:raise ValueError('required stateful windows missing from production allowlist')
