from datetime import datetime, timedelta, timezone

import pandas as pd

from adminlab.features import (
    aggregate_flow_features,
    build_temporal_features,
    map_zeek_flows_to_sessions,
    select_model_columns,
)


def sample_sessions() -> pd.DataFrame:
    base = datetime(2026, 8, 14, 9, 0, tzinfo=timezone.utc)
    rows = []
    for i in range(4):
        rows.append(
            {
                "session_id": f"s{i}",
                "campaign_id": f"c{i // 2}",
                "pair_id": "",
                "src_host_id": "paw01",
                "dst_host_id": "linux01" if i < 2 else "linux02",
                "src_ip": "10.77.0.11",
                "dst_ip": "10.77.0.21" if i < 2 else "10.77.0.22",
                "dst_port": 22,
                "protocol": "ssh",
                "start_ts": (base + timedelta(seconds=i * 30)).isoformat(),
                "end_ts": (base + timedelta(seconds=i * 30 + 10)).isoformat(),
            }
        )
    return pd.DataFrame(rows)


def test_session_can_map_to_multiple_real_tcp_flows():
    sessions = sample_sessions()
    base = pd.Timestamp(sessions.loc[0, "start_ts"]).timestamp()
    conn = pd.DataFrame(
        [
            {"ts": base + 1, "id.orig_h": "10.77.0.11", "id.orig_p": 50001, "id.resp_h": "10.77.0.21", "id.resp_p": 22, "duration": 1.0, "orig_bytes": 100, "resp_bytes": 200, "orig_pkts": 3, "resp_pkts": 4, "service": "ssh"},
            {"ts": base + 4, "id.orig_h": "10.77.0.11", "id.orig_p": 50002, "id.resp_h": "10.77.0.21", "id.resp_p": 22, "duration": 2.0, "orig_bytes": 300, "resp_bytes": 400, "orig_pkts": 5, "resp_pkts": 6, "service": "ssh"},
        ]
    )
    mapped, report = map_zeek_flows_to_sessions(sessions.iloc[[0]], conn)
    assert report["session_mapping_coverage"] == 1.0
    assert report["conn_mapping_coverage"] == 1.0
    assert report["raw_conn_count"] == 2
    assert report["eligible_conn_count"] == 2
    assert report["background_conn_count"] == 0
    assert set(mapped["session_id"]) == {"s0"}
    features = aggregate_flow_features(sessions.iloc[[0]], mapped)
    assert features.loc[0, "flow_count"] == 2
    assert features.loc[0, "src_bytes"] == 400
    assert features.loc[0, "dst_bytes"] == 600


def test_mapping_coverage_excludes_parser_background_that_cannot_match_any_planned_session():
    sessions = sample_sessions().iloc[[0]].copy()
    base = pd.Timestamp(sessions.iloc[0]["start_ts"]).timestamp()
    conn = pd.DataFrame([
        {"ts": base + 1, "id.orig_h": "10.77.0.11", "id.orig_p": 50001, "id.resp_h": "10.77.0.21", "id.resp_p": 22},
        # NetBIOS and internal forwarding/background flows are retained by the
        # parser, but they are not the direct remote-admin session unit.
        {"ts": base + 1, "id.orig_h": "10.77.0.11", "id.orig_p": 50002, "id.resp_h": "10.77.0.23", "id.resp_p": 139},
        {"ts": base + 1, "id.orig_h": "10.77.0.21", "id.orig_p": 50003, "id.resp_h": "10.77.0.22", "id.resp_p": 22},
    ])
    mapped, report = map_zeek_flows_to_sessions(sessions, conn)
    assert len(mapped) == 1
    assert report["raw_conn_count"] == 3
    assert report["eligible_conn_count"] == 1
    assert report["background_conn_count"] == 2
    assert report["mapped_conn_count"] == 1
    assert report["conn_mapping_coverage"] == 1.0


def test_mapping_report_has_per_protocol_session_coverage():
    sessions = sample_sessions()
    base = pd.Timestamp(sessions.loc[0, "start_ts"]).timestamp()
    conn = pd.DataFrame([
        {"ts": base + 1, "id.orig_h": "10.77.0.11", "id.orig_p": 50001, "id.resp_h": "10.77.0.21", "id.resp_p": 22},
    ])
    _, report = map_zeek_flows_to_sessions(sessions, conn)
    assert report["session_count_by_protocol"] == {"ssh": 4}
    assert report["mapped_session_count_by_protocol"] == {"ssh": 1}
    assert report["session_mapping_coverage_by_protocol"] == {"ssh": 0.25}


def test_temporal_features_use_only_prior_sessions():
    sessions = sample_sessions()
    windows, graph = build_temporal_features(sessions)
    by_id = windows.set_index("session_id")
    assert by_id.loc["s0", "connections_1m"] == 0
    assert by_id.loc["s1", "connections_1m"] == 1
    assert by_id.loc["s0", "new_dst_for_src"] == 1
    assert by_id.loc["s1", "new_dst_for_src"] == 0
    assert by_id.loc["s2", "new_dst_for_src"] == 1
    graph_by_id = graph.set_index("session_id")
    assert graph_by_id.loc["s0", "src_out_degree_1h"] == 0
    assert graph_by_id.loc["s2", "src_out_degree_1h"] == 1


def test_model_selection_excludes_generator_nuisance_and_identifiers():
    frame = pd.DataFrame(
        {
            "flow_count": [1],
            "duration": [2.0],
            "netem_loss_pct": [1.5],
            "session_id": ["s1"],
            "scenario_id": ["attack_x"],
        }
    )
    contract = {
        "production_allowlist": ["flow_count", "duration"],
        "forbidden": ["netem_loss_pct", "session_id", "scenario_id"],
    }
    selected = select_model_columns(frame, contract)
    assert list(selected.columns) == ["flow_count", "duration"]
