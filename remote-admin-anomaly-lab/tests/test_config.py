from pathlib import Path

import pytest

from adminlab.config import (
    FORBIDDEN_FEATURE_COLUMNS,
    load_yaml,
    validate_feature_contract,
    validate_scenarios,
    validate_topology,
)

ROOT = Path(__file__).resolve().parents[1]


def test_topology_has_unique_host_ids_namespaces_and_ips():
    data = load_yaml(ROOT / "configs/topology.yaml")
    validate_topology(data)
    hosts = data["hosts"]
    assert len({h["id"] for h in hosts}) == len(hosts)
    assert len({h["namespace"] for h in hosts}) == len(hosts)
    assert len({h["ip"] for h in hosts}) == len(hosts)
    assert data["lab"]["external_routing"] is False


def test_topology_rejects_duplicate_ip():
    data = load_yaml(ROOT / "configs/topology.yaml")
    data["hosts"][1]["ip"] = data["hosts"][0]["ip"]
    with pytest.raises(ValueError, match="duplicate host ip"):
        validate_topology(data)


def test_scenarios_use_known_protocols_roles_and_lab_only_targets():
    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    validate_scenarios(scenarios, topology)
    assert scenarios["safety"]["allow_external_targets"] is False
    assert scenarios["safety"]["allow_proxy_forwarding"] is False
    assert scenarios["safety"]["allow_payload_execution"] is False


def test_feature_contract_rejects_ground_truth_leakage():
    contract = load_yaml(ROOT / "configs/feature_contract.yaml")
    validate_feature_contract(contract)
    assert "scenario_id" in FORBIDDEN_FEATURE_COLUMNS
    assert not (set(contract["production_allowlist"]) & FORBIDDEN_FEATURE_COLUMNS)


def test_feature_contract_rejects_forbidden_allowlist_entry():
    contract = load_yaml(ROOT / "configs/feature_contract.yaml")
    contract["production_allowlist"].append("scenario_id")
    with pytest.raises(ValueError, match="forbidden production feature"):
        validate_feature_contract(contract)
