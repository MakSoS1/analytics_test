import math

import numpy as np
import pandas as pd

from adminlab.suricata_gold import normalize_suricata_flow_events


def test_normalize_suricata_flow_events_filters_non_flow_and_handles_nan_ports():
    eve = pd.DataFrame([
        {
            "event_type": "stats",
            "timestamp": "2026-08-14T13:40:00.000000+00:00",
            "src_ip": np.nan,
            "dest_ip": np.nan,
            "src_port": np.nan,
            "dest_port": np.nan,
            "flow_id": np.nan,
        },
        {
            "event_type": "flow",
            "timestamp": "2026-08-14T13:40:01.000000+00:00",
            "src_ip": "10.77.0.11",
            "dest_ip": "10.77.0.21",
            "src_port": 51001.0,
            "dest_port": 22.0,
            "flow_id": 123456.0,
            "flow": {"pkts_toserver": 4, "pkts_toclient": 3},
        },
        {
            "event_type": "flow",
            "timestamp": "2026-08-14T13:40:02.000000+00:00",
            "src_ip": "10.77.0.11",
            "dest_ip": "10.77.0.21",
            "src_port": np.nan,
            "dest_port": np.nan,
            "flow_id": np.nan,
            "flow": {"pkts_toserver": 1, "pkts_toclient": 0},
        },
    ])

    normalized = normalize_suricata_flow_events(eve)

    assert len(normalized) == 2
    assert normalized.loc[0, "id.orig_p"] == 51001
    assert normalized.loc[0, "id.resp_p"] == 22
    assert normalized.loc[1, "id.orig_p"] == 0
    assert normalized.loc[1, "id.resp_p"] == 0
    assert normalized.loc[1, "uid"] == "suri-row:000000000001"
    assert normalized.loc[1, "id.orig_h"] == "10.77.0.11"
    assert normalized.loc[1, "id.resp_h"] == "10.77.0.21"
    assert math.isfinite(float(normalized.loc[1, "ts"]))


def test_normalize_suricata_flow_events_does_not_stringify_nan_addresses():
    eve = pd.DataFrame([
        {
            "event_type": "flow",
            "timestamp": "2026-08-14T13:40:03.000000+00:00",
            "src_ip": np.nan,
            "dest_ip": np.nan,
            "src_port": np.nan,
            "dest_port": np.nan,
            "flow_id": 999,
            "flow": {},
        }
    ])

    normalized = normalize_suricata_flow_events(eve)
    assert normalized.loc[0, "id.orig_h"] == ""
    assert normalized.loc[0, "id.resp_h"] == ""


def test_offline_suricata_mapping_timestamp_prefers_nested_flow_start_over_shutdown_event_timestamp():
    # Offline Suricata can flush many flow records during engine shutdown with
    # an identical top-level EVE timestamp. The captured connection start/end
    # inside the flow object retain the actual packet time and must drive PCAP
    # to session mapping.
    eve = pd.DataFrame([
        {
            "event_type": "flow",
            "timestamp": "2026-08-14T13:55:07.622703+00:00",
            "src_ip": "10.77.0.12",
            "src_port": 44574,
            "dest_ip": "10.77.0.25",
            "dest_port": 5900,
            "flow_id": 171808569033198,
            "flow": {
                "start": "2026-08-14T13:55:20.040002+00:00",
                "end": "2026-08-14T13:55:20.249964+00:00",
                "pkts_toserver": 14,
                "pkts_toclient": 14,
            },
        }
    ])
    normalized = normalize_suricata_flow_events(eve)
    expected = pd.Timestamp("2026-08-14T13:55:20.040002+00:00").timestamp()
    assert abs(float(normalized.loc[0, "ts"]) - expected) < 1e-6
    assert normalized.loc[0, "mapping_timestamp_source"] == "flow.start"
