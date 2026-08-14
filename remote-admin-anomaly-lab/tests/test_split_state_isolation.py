import pandas as pd

from adminlab.flow_gold import build_split_isolated_production_flow_features


def _row(uid, sid, ts, src, dst, split):
    return {
        "uid": uid,
        "session_id": sid,
        "behavior_ts": ts,
        "ts": ts,
        "id.orig_h": src,
        "id.resp_h": dst,
        "id.resp_p": 22,
        "service": "ssh",
        "duration": 1.0,
        "orig_bytes": 10,
        "resp_bytes": 20,
        "orig_pkts": 1,
        "resp_pkts": 1,
        "split": split,
    }


def test_validation_state_never_contaminates_later_train_row():
    frame = pd.DataFrame([
        _row("t1", "s1", 100.0, "10.0.0.1", "10.0.0.2", "train"),
        _row("v1", "s2", 110.0, "10.0.0.1", "10.0.0.3", "validation"),
        _row("t2", "s3", 120.0, "10.0.0.1", "10.0.0.4", "train"),
    ])
    features = build_split_isolated_production_flow_features(frame).set_index("flow_uid")
    assert features.loc["t2", "connections_1m"] == 1
    assert features.loc["v1", "connections_1m"] == 0


def test_each_evaluation_split_has_independent_state():
    frame = pd.DataFrame([
        _row("v1", "v1", 100.0, "10.0.0.1", "10.0.0.2", "validation"),
        _row("x1", "x1", 101.0, "10.0.0.1", "10.0.0.2", "test"),
        _row("c1", "c1", 102.0, "10.0.0.1", "10.0.0.2", "challenge"),
    ])
    features = build_split_isolated_production_flow_features(frame).set_index("flow_uid")
    assert features.loc["v1", "connections_1m"] == 0
    assert features.loc["x1", "connections_1m"] == 0
    assert features.loc["c1", "connections_1m"] == 0


def test_long_term_flow_state_uses_behavior_time():
    frame = pd.DataFrame([
        _row("a", "a", 0.0, "10.0.0.1", "10.0.0.2", "train"),
        _row("b", "b", 7200.0, "10.0.0.1", "10.0.0.2", "train"),
    ])
    features = build_split_isolated_production_flow_features(frame).set_index("flow_uid")
    assert features.loc["b", "connections_1h"] == 0
    assert features.loc["b", "connections_24h"] == 1
    assert features.loc["b", "pair_connections_24h"] == 1
