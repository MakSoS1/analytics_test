import math
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

from adminlab.suricata_gold import map_suricata_flows_to_sessions, normalize_suricata_flow_events


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


def test_suricata_mapping_coverage_uses_only_direct_manifest_tuples_and_reports_background():
    base = datetime(2026, 8, 14, 13, 55, tzinfo=timezone.utc)
    sessions = pd.DataFrame([
        {
            "session_id": "s-ssh",
            "src_ip": "10.77.0.11",
            "dst_ip": "10.77.0.21",
            "dst_port": 22,
            "protocol": "ssh",
            "start_ts": base.isoformat(),
            "end_ts": (base + timedelta(seconds=3)).isoformat(),
            "execution_start_ts": base.isoformat(),
            "execution_end_ts": (base + timedelta(seconds=3)).isoformat(),
        },
        {
            "session_id": "s-smb",
            "src_ip": "10.77.0.12",
            "dst_ip": "10.77.0.23",
            "dst_port": 445,
            "protocol": "smb",
            "start_ts": (base + timedelta(seconds=10)).isoformat(),
            "end_ts": (base + timedelta(seconds=13)).isoformat(),
            "execution_start_ts": (base + timedelta(seconds=10)).isoformat(),
            "execution_end_ts": (base + timedelta(seconds=13)).isoformat(),
        },
    ])
    normalized = pd.DataFrame([
        {"uid": "a", "ts": base.timestamp() + 1, "id.orig_h": "10.77.0.11", "id.orig_p": 50001, "id.resp_h": "10.77.0.21", "id.resp_p": 22, "event": {}},
        {"uid": "b", "ts": base.timestamp() + 11, "id.orig_h": "10.77.0.12", "id.orig_p": 50002, "id.resp_h": "10.77.0.23", "id.resp_p": 445, "event": {}},
        {"uid": "netbios", "ts": base.timestamp() + 11, "id.orig_h": "10.77.0.12", "id.orig_p": 50003, "id.resp_h": "10.77.0.23", "id.resp_p": 139, "event": {}},
        {"uid": "proxy-hop", "ts": base.timestamp() + 1, "id.orig_h": "10.77.0.21", "id.orig_p": 50004, "id.resp_h": "10.77.0.22", "id.resp_p": 22, "event": {}},
    ])

    mapped, report = map_suricata_flows_to_sessions(sessions, normalized)

    assert len(mapped) == 2
    assert report["raw_conn_count"] == 4
    assert report["eligible_conn_count"] == 2
    assert report["background_conn_count"] == 2
    assert report["mapped_conn_count"] == 2
    assert report["unmapped_eligible_conn_count"] == 0
    assert report["conn_mapping_coverage"] == 1.0
    assert report["session_mapping_coverage"] == 1.0
    assert report["session_mapping_coverage_by_protocol"] == {"smb": 1.0, "ssh": 1.0}
