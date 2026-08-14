from copy import deepcopy

import pandas as pd

from adminlab.online_features import EveFeatureState
from adminlab.suricata_gold import build_split_isolated_suricata_features


def _event(flow_id: int, timestamp: str, src: str, dst: str, port: int, app: str, b1: int, b2: int):
    return {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "event_type": "flow",
        "src_ip": src,
        "src_port": 40000 + flow_id,
        "dest_ip": dst,
        "dest_port": port,
        "proto": "TCP",
        "app_proto": app,
        "flow": {
            "start": timestamp,
            "end": timestamp,
            "bytes_toserver": b1,
            "bytes_toclient": b2,
            "pkts_toserver": 2,
            "pkts_toclient": 3,
        },
    }


def test_offline_suricata_gold_uses_same_state_machine_as_online_sidecar():
    events = [
        _event(1, "2026-01-01T10:00:00+00:00", "10.0.0.1", "10.0.0.2", 22, "ssh", 100, 200),
        _event(2, "2026-01-01T10:10:00+00:00", "10.0.0.1", "10.0.0.3", 3389, "rdp", 300, 400),
    ]
    mapped = pd.DataFrame({
        "flow_uid": ["suri:1", "suri:2"],
        "session_id": ["s1", "s2"],
        "split": ["train", "train"],
        "behavior_ts": [1767261600.0, 1767262200.0],
        "event": [deepcopy(events[0]), deepcopy(events[1])],
    })
    offline = build_split_isolated_suricata_features(mapped).set_index("flow_uid")

    state = EveFeatureState()
    online_rows = []
    for event, behavior_ts in zip(events, mapped["behavior_ts"]):
        replay = deepcopy(event)
        replay["timestamp"] = pd.to_datetime(behavior_ts, unit="s", utc=True).isoformat()
        result = state.consume_flow(replay)
        online_rows.append(result["features"])

    for idx, uid in enumerate(["suri:1", "suri:2"]):
        for name, value in online_rows[idx].items():
            assert name in offline.columns, name
            assert offline.loc[uid, name] == value, (uid, name, offline.loc[uid, name], value)


def test_online_state_retains_30_day_history():
    state = EveFeatureState()
    first = _event(1, "2026-01-01T00:00:00+00:00", "10.0.0.1", "10.0.0.2", 22, "ssh", 1, 1)
    second = _event(2, "2026-01-01T02:00:00+00:00", "10.0.0.1", "10.0.0.2", 22, "ssh", 1, 1)
    state.consume_flow(first)
    features = state.consume_flow(second)["features"]
    assert features["connections_1h"] == 0
    assert features["connections_24h"] == 1
    assert features["connections_7d"] == 1
    assert features["connections_30d"] == 1
