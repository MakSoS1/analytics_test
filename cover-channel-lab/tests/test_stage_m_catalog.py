from collections import defaultdict

from coverlab.stage_m_catalog import (
    EVENT_COUNTS,
    FAMILY_SPECS,
    NETWORK_PROFILES,
    build_split_summary,
    iter_campaigns,
    validate_plan,
)


def test_stage_m_catalog_is_positive_diverse_and_complete():
    plans = list(iter_campaigns())
    report = validate_plan(plans)
    assert report["passed"], report
    assert len(plans) == 4950
    assert len({p.campaign_id for p in plans}) == len(plans)
    assert {p.family_id for p in plans} == {s.family_id for s in FAMILY_SPECS}
    assert {p.network_profile for p in plans} == set(NETWORK_PROFILES)
    assert set(EVENT_COUNTS).issubset({p.event_count_target for p in plans})


def test_primary_implementation_holdout_has_no_train_leakage():
    plans = list(iter_campaigns())
    by_family = defaultdict(lambda: {"train": set(), "holdout": set()})
    for p in plans:
        key = "holdout" if p.primary_split == "implementation_holdout" else "train"
        by_family[p.family_id][key].add(p.implementation_id)
    for spec in FAMILY_SPECS:
        assert spec.primary_holdout_impl in by_family[spec.family_id]["holdout"]
        assert spec.primary_holdout_impl not in by_family[spec.family_id]["train"]


def test_dns_has_both_topologies_and_wire_transports():
    plans = [p for p in iter_campaigns() if p.family_id in {"M-DNS-BEACON", "M-DNS-BULK"}]
    assert {p.dns_topology for p in plans} == {"direct_authoritative", "recursive_local"}
    assert {p.connection_policy for p in plans} >= {"datagram", "tcp"}
    assert {p.qtype for p in plans} == {"A", "AAAA", "TXT"}


def test_shared_fronts_are_local_only():
    plans = [p for p in iter_campaigns() if p.family_id == "M-HTTPS-FRONT"]
    assert plans
    assert all(p.front_host.endswith(".stage-m.test") for p in plans)


def test_leave_one_out_metadata_covers_requested_axes():
    summary = build_split_summary(list(iter_campaigns()))
    for axis in ("implementation_id", "network_profile", "payload_style", "nominal_interval_seconds"):
        assert axis in summary["dimensions"]
        assert summary["dimensions"][axis]
