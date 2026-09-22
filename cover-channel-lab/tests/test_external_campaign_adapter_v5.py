from coverlab.external_campaign_adapter_v5 import ech_campaign, framework_campaign


REQUIRED_GOLD_FIELDS = {
    "campaign_id",
    "label_binary",
    "label_family",
    "protocol",
    "persona",
    "client_impl",
    "visibility_mode",
    "expected_events",
    "inspection_policy",
    "sni_visibility",
    "status",
    "external_dependency",
    "source_ip",
    "started_at",
    "ended_at",
}


def test_framework_adapter_matches_gold_campaign_schema():
    row = {
        "campaign_id": "j-mythic-1",
        "framework": "mythic_httpx",
        "label_binary": 1,
        "label_family": "web_c2_mimicry",
        "protocol": "https",
        "source_ip": "10.77.0.21",
        "started_at": "2026-09-22T10:00:00Z",
        "ended_at": "2026-09-22T10:01:00Z",
    }
    out = framework_campaign(row)
    assert REQUIRED_GOLD_FIELDS <= set(out)
    assert out["client_impl"] == "mythic_httpx"
    assert out["visibility_mode"] == "opaque_and_ground_truth"
    assert out["status"] == "success"
    assert out["external_dependency"] is False


def test_ech_adapter_marks_sni_hidden_only_when_effective():
    base = {
        "campaign_id": "ech-1",
        "label_binary": 0,
        "label_family": "benign",
        "protocol": "h3",
        "source_ip": "10.77.0.31",
        "started_at": "2026-09-22T10:00:00Z",
        "ended_at": "2026-09-22T10:00:10Z",
    }
    accepted = ech_campaign(dict(base, ech_enabled=True, ech_mode="accepted_h3"))
    rejected = ech_campaign(dict(base, ech_enabled=True, ech_mode="rejected"))
    disabled = ech_campaign(dict(base, ech_enabled=False, ech_mode="accepted_h3"))

    assert REQUIRED_GOLD_FIELDS <= set(accepted)
    assert accepted["sni_visibility"] == "hidden"
    assert rejected["sni_visibility"] == "clear"
    assert disabled["sni_visibility"] == "clear"
