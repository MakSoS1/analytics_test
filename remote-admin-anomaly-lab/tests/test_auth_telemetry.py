import pandas as pd

from adminlab.auth_features import build_split_isolated_outcome_features, enrich_ssh_auth_by_uid


def test_ssh_auth_enrichment_joins_by_uid_only():
    conn = pd.DataFrame({"uid": ["a", "b"], "service": ["ssh", "ssh"], "conn_state": ["SF", "REJ"]})
    ssh = pd.DataFrame({"uid": ["a"], "auth_success": [True], "auth_attempts": [1]})
    out = enrich_ssh_auth_by_uid(conn, ssh).set_index("uid")
    assert out.loc["a", "ssh_auth_observed"] == 1
    assert out.loc["a", "ssh_auth_success"] == 1
    assert out.loc["a", "ssh_auth_attempts"] == 1
    assert out.loc["b", "ssh_auth_observed"] == 0


def test_outcome_rates_are_prior_only_and_split_isolated():
    rows = pd.DataFrame([
        {"uid": "a", "session_id": "a", "behavior_ts": 0.0, "id.orig_h": "10.0.0.1", "conn_state": "REJ", "split": "train"},
        {"uid": "v", "session_id": "v", "behavior_ts": 10.0, "id.orig_h": "10.0.0.1", "conn_state": "SF", "split": "validation"},
        {"uid": "b", "session_id": "b", "behavior_ts": 20.0, "id.orig_h": "10.0.0.1", "conn_state": "SF", "split": "train"},
    ])
    out = build_split_isolated_outcome_features(rows).set_index("flow_uid")
    assert out.loc["a", "failed_connection_rate_15m"] == 0.0
    assert out.loc["b", "failed_connection_rate_15m"] == 1.0
    assert out.loc["b", "successful_connection_rate_15m"] == 0.0
    assert out.loc["v", "failed_connection_rate_15m"] == 0.0


def test_24h_outcome_history_survives_beyond_one_hour():
    rows = pd.DataFrame([
        {"uid": "a", "session_id": "a", "behavior_ts": 0.0, "id.orig_h": "10.0.0.1", "conn_state": "REJ", "split": "train"},
        {"uid": "b", "session_id": "b", "behavior_ts": 7200.0, "id.orig_h": "10.0.0.1", "conn_state": "SF", "split": "train"},
    ])
    out = build_split_isolated_outcome_features(rows).set_index("flow_uid")
    assert out.loc["b", "failed_connection_rate_1h"] == 0.0
    assert out.loc["b", "failed_connection_rate_24h"] == 1.0
