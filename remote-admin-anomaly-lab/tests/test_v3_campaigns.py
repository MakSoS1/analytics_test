from collections import Counter
from dataclasses import replace

from adminlab.manifest import SessionRecord
from adminlab.v3_campaigns import audit_v3_campaigns, organize_v3_campaigns


def _row(idx: int) -> SessionRecord:
    label = idx % 2
    protocol = ("ssh", "smb", "rdp", "vnc")[(idx // 2) % 4]
    port = {"ssh": 22, "smb": 445, "rdp": 3389, "vnc": 5900}[protocol]
    day = idx % 20
    hour = 8 + (idx % 10)
    return SessionRecord(
        campaign_id=f"old-{idx}", scenario_id="v3", session_id=f"s-{idx:04d}", pair_id="",
        label_binary=label, label_family="benign" if label == 0 else "suspicious",
        mitre_technique="T1021.004", src_role="AdminWorkstation", dst_role="Server",
        src_host_id=f"src-{idx % 6}", dst_host_id=f"dst-{idx % 19}",
        src_ip=f"10.77.0.{10 + idx % 6}", dst_ip=f"10.77.0.{40 + idx % 19}",
        src_port=0, dst_port=port, protocol=protocol, action="bounded_admin_session",
        wire_fidelity="real_wire", semantic_fidelity="high", ground_truth_source="scenario_orchestrator",
        netem_profile="normal", generator_seed=20260814,
        start_ts=f"2026-06-{day + 1:02d}T{hour:02d}:00:00+00:00",
        end_ts=f"2026-06-{day + 1:02d}T{hour:02d}:02:00+00:00", status="planned",
        persona_id=f"persona-{idx % 23}", task_id="diagnostics", calendar_id="business_hours",
        intent_profile="approved" if label == 0 else "lateral",
        behavior_profile="interactive",
        campaign_type=("incident_response" if label == 0 and idx % 10 == 0 else ("routine_admin" if label == 0 else "rare_pair")),
        historical_relation="known_pair" if label == 0 else "new_pair", auth_outcome="success",
        client_stack="client", server_stack="server", implementation_id=f"{protocol}:client->server",
        simulated_day=day,
    )


def test_v3_campaigns_are_many_small_independent_units():
    rows = [_row(idx) for idx in range(1000)]
    prepared = organize_v3_campaigns(rows, seed=20260814)
    report = audit_v3_campaigns(prepared)
    assert report["campaign_count"] >= 180
    assert report["max_campaign_fraction"] <= 0.025
    assert report["benign_campaign_count"] >= 60
    assert report["suspicious_campaign_count"] >= 60
    assert report["multi_protocol_campaign_count"] >= 30
    assert report["max_campaign_size"] <= 8


def test_v3_campaign_assignment_preserves_labels_pair_ids_and_session_ids():
    rows = [_row(idx) for idx in range(120)]
    rows[0] = replace(rows[0], pair_id="cf-1")
    rows[1] = replace(rows[1], pair_id="cf-1")
    before = {row.session_id: (row.label_binary, row.pair_id) for row in rows}
    prepared = organize_v3_campaigns(rows, seed=1)
    after = {row.session_id: (row.label_binary, row.pair_id) for row in prepared}
    assert before == after
    assert Counter(row.label_binary for row in prepared) == Counter(row.label_binary for row in rows)
