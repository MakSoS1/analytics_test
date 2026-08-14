import math

import numpy as np

from adminlab.online_features import EveFeatureState


def test_eve_feature_state_handles_nullable_flow_scalars_without_nan_features():
    state = EveFeatureState()
    result = state.consume_flow({
        "event_type": "flow",
        "timestamp": "2026-08-14T13:40:00+00:00",
        "src_ip": "10.77.0.11",
        "dest_ip": "10.77.0.21",
        "dest_port": np.nan,
        "app_proto": np.nan,
        "proto": "TCP",
        "flow": {
            "bytes_toserver": np.nan,
            "bytes_toclient": None,
            "pkts_toserver": np.nan,
            "pkts_toclient": None,
            "start": np.nan,
            "end": np.nan,
        },
    })

    features = result["features"]
    assert features["dst_port"] == 0
    assert features["app_proto"] == "TCP"
    assert features["src_bytes"] == 0.0
    assert features["dst_bytes"] == 0.0
    assert features["src_packets"] == 0.0
    assert features["dst_packets"] == 0.0
    assert features["duration"] == 0.0
    for value in features.values():
        if isinstance(value, float):
            assert math.isfinite(value)


def test_eve_feature_state_does_not_use_nan_as_state_identity():
    state = EveFeatureState()
    result = state.consume_flow({
        "event_type": "flow",
        "timestamp": np.nan,
        "src_ip": np.nan,
        "dest_ip": np.nan,
        "dest_port": np.nan,
        "flow": {},
    })
    assert result["context"]["src_ip"] == ""
    assert result["context"]["dest_ip"] == ""
    assert result["context"]["dest_port"] == 0
