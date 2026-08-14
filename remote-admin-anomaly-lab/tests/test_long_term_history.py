from pathlib import Path

import pandas as pd

from adminlab.config import load_yaml
from adminlab.features import build_temporal_features, map_zeek_flows_to_sessions

ROOT = Path(__file__).resolve().parents[1]


def test_feature_contract_has_24h_7d_30d_history():
    contract = load_yaml(ROOT / "configs/feature_contract.yaml")
    allow = set(contract["production_allowlist"])
    required = {
        "connections_24h", "connections_7d", "connections_30d",
        "unique_dst_ip_24h", "unique_dst_ip_7d", "unique_dst_ip_30d",
        "pair_connections_24h", "pair_connections_7d", "pair_connections_30d",
        "new_dst_24h", "new_dst_7d", "new_dst_30d",
        "protocol_entropy_24h",
    }
    assert required <= allow


def test_temporal_features_keep_long_history_after_one_hour():
    sessions = pd.DataFrame([
        {"session_id": "a", "src_host_id": "s", "dst_host_id": "d1", "src_ip": "10.77.0.1", "dst_ip": "10.77.0.21", "protocol": "ssh", "start_ts": "2026-01-01T00:00:00+00:00"},
        {"session_id": "b", "src_host_id": "s", "dst_host_id": "d1", "src_ip": "10.77.0.1", "dst_ip": "10.77.0.21", "protocol": "ssh", "start_ts": "2026-01-01T02:00:00+00:00"},
        {"session_id": "c", "src_host_id": "s", "dst_host_id": "d2", "src_ip": "10.77.0.1", "dst_ip": "10.77.0.22", "protocol": "ssh", "start_ts": "2026-01-03T00:00:00+00:00"},
    ])
    windows, _ = build_temporal_features(sessions)
    b = windows.set_index("session_id").loc["b"]
    assert b["connections_1h"] == 0
    assert b["connections_24h"] == 1
    assert b["connections_7d"] == 1
    assert b["connections_30d"] == 1
    assert b["pair_connections_24h"] == 1
    c = windows.set_index("session_id").loc["c"]
    assert c["connections_24h"] == 0
    assert c["connections_7d"] == 2
    assert c["new_dst_24h"] == 1


def test_flow_mapping_uses_execution_time_not_simulated_time():
    sessions = pd.DataFrame([
        {
            "session_id": "s1", "src_ip": "10.77.0.11", "dst_ip": "10.77.0.21", "dst_port": 22,
            "start_ts": "2026-01-10T10:00:00+00:00", "end_ts": "2026-01-10T10:10:00+00:00",
            "execution_start_ts": "2026-08-14T11:00:00+00:00", "execution_end_ts": "2026-08-14T11:00:05+00:00",
        }
    ])
    conn = pd.DataFrame([
        {"ts": pd.Timestamp("2026-08-14T11:00:02Z").timestamp(), "id.orig_h": "10.77.0.11", "id.resp_h": "10.77.0.21", "id.resp_p": 22}
    ])
    mapped, report = map_zeek_flows_to_sessions(sessions, conn)
    assert report["session_mapping_coverage"] == 1.0
    assert mapped.iloc[0]["session_id"] == "s1"
    assert report["mapping_time_source"] == "execution_start_ts/execution_end_ts"
