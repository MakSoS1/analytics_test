from __future__ import annotations

import pandas as pd

from adminlab.wire_paths import expected_wire_tuples
from adminlab.features import map_zeek_flows_to_sessions


def _session(*, task_id: str = "diagnostics") -> dict:
    return {
        "session_id": "s1",
        "src_ip": "10.77.0.13",
        "dst_ip": "10.77.0.22",
        "dst_port": 22,
        "protocol": "ssh",
        "task_id": task_id,
        "start_ts": "2026-01-01T10:00:00+00:00",
        "end_ts": "2026-01-01T10:01:00+00:00",
        "execution_start_ts": "2026-08-15T10:00:00+00:00",
        "execution_end_ts": "2026-08-15T10:00:10+00:00",
    }


def test_expected_wire_tuples_expands_approved_forwarding_into_two_real_ssh_hops():
    row = _session(task_id="approved_forwarding")
    assert expected_wire_tuples(row) == [
        ("10.77.0.13", "10.77.0.21", 22),
        ("10.77.0.21", "10.77.0.22", 22),
    ]


def test_expected_wire_tuples_keeps_normal_remote_admin_direct():
    row = _session(task_id="diagnostics")
    assert expected_wire_tuples(row) == [("10.77.0.13", "10.77.0.22", 22)]


def test_flow_mapper_maps_both_proxyjump_legs_to_same_orchestrated_session():
    sessions = pd.DataFrame([_session(task_id="approved_forwarding")])
    conn = pd.DataFrame([
        {"uid": "leg1", "ts": 1786788001.0, "id.orig_h": "10.77.0.13", "id.resp_h": "10.77.0.21", "id.resp_p": 22},
        {"uid": "leg2", "ts": 1786788002.0, "id.orig_h": "10.77.0.21", "id.resp_h": "10.77.0.22", "id.resp_p": 22},
    ])
    # Use the actual execution epoch rather than the simulated clock.
    conn["ts"] = pd.Timestamp("2026-08-15T10:00:01Z").timestamp() + pd.Series([0.0, 1.0])
    mapped, report = map_zeek_flows_to_sessions(sessions, conn)
    assert list(mapped["session_id"]) == ["s1", "s1"]
    assert report["mapped_session_count"] == 1
    assert report["session_mapping_coverage"] == 1.0
    assert report["mapping_policy"].startswith("expected-wire-hop")
