from __future__ import annotations

from copy import deepcopy

import pandas as pd

import adminlab.suricata_gold as suricata_gold


def _event(flow_id: int, timestamp: str):
    return {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "event_type": "flow",
        "src_ip": "10.0.0.1",
        "src_port": 40000 + flow_id,
        "dest_ip": "10.0.0.2",
        "dest_port": 22,
        "proto": "TCP",
        "app_proto": "ssh",
        "flow": {
            "start": timestamp,
            "end": timestamp,
            "bytes_toserver": 10,
            "bytes_toclient": 20,
            "pkts_toserver": 2,
            "pkts_toclient": 3,
        },
    }


def test_reference_context_replay_gives_validation_and_test_prior_train_history_only():
    assert hasattr(suricata_gold, "build_reference_context_suricata_features")
    events=[
        _event(1,"2026-01-01T10:00:00+00:00"),
        _event(2,"2026-01-01T10:10:00+00:00"),
        _event(3,"2026-01-01T10:20:00+00:00"),
        _event(4,"2026-01-01T10:30:00+00:00"),
    ]
    mapped=pd.DataFrame({
        "uid":["suri:1","suri:2","suri:3","suri:4"],
        "session_id":["train-1","validation-1","test-1","validation-2"],
        "split":["train","validation","test","validation"],
        "behavior_ts":[1767261600.0,1767262200.0,1767262800.0,1767263400.0],
        "event":[deepcopy(e) for e in events],
    })

    out=suricata_gold.build_reference_context_suricata_features(mapped).set_index("flow_uid")
    assert out.loc["suri:1","connections_24h"] == 0
    # Both held-out splits see the earlier train event, but not one another.
    assert out.loc["suri:2","connections_24h"] == 1
    assert out.loc["suri:3","connections_24h"] == 1
    # The second validation event sees train-1 + validation-1; test-1 remains
    # excluded from validation context.
    assert out.loc["suri:4","connections_24h"] == 2
