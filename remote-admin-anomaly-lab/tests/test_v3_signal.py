from collections import defaultdict
from dataclasses import replace
from datetime import datetime

from adminlab.manifest import SessionRecord
from adminlab.v3_signal import audit_v3_signal_plan, build_v3_signal_plan, v3_current_signature


def _row(*, label: int, session_id: str, day: int, hour: int, protocol: str) -> SessionRecord:
    port = {"ssh": 22, "smb": 445, "rdp": 3389, "vnc": 5900}[protocol]
    return SessionRecord(
        campaign_id=f"campaign-{session_id}",
        scenario_id="scenario-v3",
        session_id=session_id,
        pair_id="",
        label_binary=label,
        label_family="benign" if label == 0 else "suspicious",
        mitre_technique="T1021.004",
        src_role="AdminWorkstation",
        dst_role="Server",
        src_host_id=f"src-{int(session_id.split('-')[-1]) % 7}",
        dst_host_id=f"dst-{int(session_id.split('-')[-1]) % 13}",
        src_ip=f"10.77.0.{10 + int(session_id.split('-')[-1]) % 7}",
        dst_ip=f"10.77.0.{30 + int(session_id.split('-')[-1]) % 13}",
        src_port=0,
        dst_port=port,
        protocol=protocol,
        action="bounded_admin_session",
        wire_fidelity="real_wire",
        semantic_fidelity="high",
        ground_truth_source="scenario_orchestrator",
        netem_profile="normal" if int(session_id.split('-')[-1]) % 2 == 0 else "constrained",
        generator_seed=20260814,
        start_ts=f"2026-06-{day:02d}T{hour:02d}:15:00+00:00",
        end_ts=f"2026-06-{day:02d}T{hour:02d}:17:00+00:00",
        status="planned",
        persona_id=f"persona-{int(session_id.split('-')[-1]) % 11}",
        task_id="diagnostics",
        calendar_id="business_hours",
        intent_profile="approved" if label == 0 else "lateral",
        behavior_profile=("interactive", "small_transfer", "maintenance_fanout", "reconnect")[int(session_id.split('-')[-1]) % 4],
        campaign_type="routine_admin" if label == 0 else "rare_pair",
        historical_relation="known_pair" if label == 0 else "new_pair",
        auth_outcome="success",
        client_stack="client",
        server_stack="server",
        implementation_id=f"{protocol}:client->server",
        simulated_day=day - 1,
    )


def _correlated_rows() -> list[SessionRecord]:
    rows = []
    protocols = ("ssh", "smb", "rdp", "vnc")
    for idx in range(160):
        label = idx % 2
        protocol = protocols[(idx // 2) % 4]
        day = 2 + (idx % 26)
        # Deliberately bad V2-like shortcut: benign mornings, suspicious evenings.
        hour = 9 if label == 0 else 21
        rows.append(_row(label=label, session_id=f"row-{idx}", day=day, hour=hour, protocol=protocol))
    return rows


def test_v3_signal_plan_removes_hour_label_shortcut_without_relabeling():
    rows = _correlated_rows()
    labels_before = {row.session_id: row.label_binary for row in rows}
    prepared = build_v3_signal_plan(rows, seed=20260814, matched_fraction=0.40)
    assert {row.session_id: row.label_binary for row in prepared} == labels_before
    report = audit_v3_signal_plan(prepared)
    assert report["matched_hour_pair_fraction"] >= 0.80
    assert report["max_hour_label_fraction_gap"] <= 0.10


def test_v3_counterfactual_pairs_have_same_current_session_time_and_controls():
    prepared = build_v3_signal_plan(_correlated_rows(), seed=20260814, matched_fraction=0.40)
    by_pair = defaultdict(list)
    for row in prepared:
        if row.pair_id:
            by_pair[row.pair_id].append(row)
    valid = [pair for pair in by_pair.values() if len(pair) == 2]
    assert valid
    for pair in valid:
        left, right = pair
        assert {left.label_binary, right.label_binary} == {0, 1}
        ldt = datetime.fromisoformat(left.start_ts)
        rdt = datetime.fromisoformat(right.start_ts)
        assert (ldt.hour, ldt.minute) == (rdt.hour, rdt.minute)
        assert v3_current_signature(left) == v3_current_signature(right)
        # Relational identity is deliberately allowed to differ: that is the intended signal.
        assert (left.src_host_id, left.dst_host_id) != (right.src_host_id, right.dst_host_id) or left.session_id != right.session_id


def test_v3_pairing_has_no_protocol_fallback_to_different_hours():
    rows = _correlated_rows()
    prepared = build_v3_signal_plan(rows, seed=7, matched_fraction=0.50)
    by_pair = defaultdict(list)
    for row in prepared:
        if row.pair_id:
            by_pair[row.pair_id].append(row)
    for pair in by_pair.values():
        if len(pair) != 2:
            continue
        a, b = pair
        assert datetime.fromisoformat(a.start_ts).hour == datetime.fromisoformat(b.start_ts).hour
