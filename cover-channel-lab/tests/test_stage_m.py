import json
from pathlib import Path

from coverlab.stage_m_contract import (
    EXPECTED_TOTAL_CAMPAIGNS, FAMILIES, NETWORK_PROFILES, campaign_plan,
)
from coverlab.stage_m_report import build_report
from coverlab.dns_fixture import _authoritative_response
import dns.message
import dns.rcode


def test_stage_m_plan_is_4750_positive_contract_with_expected_tiers():
    p=campaign_plan()
    assert len(p)==EXPECTED_TOTAL_CAMPAIGNS==4750
    assert sum(x['tier']=='core' for x in p)==2950
    assert sum(x['tier']=='implementation_diversity' for x in p)==1200
    assert sum(x['tier']=='implementation_holdout' for x in p)==600
    assert {x['network_profile'] for x in p}==set(NETWORK_PROFILES)


def test_stage_m_has_multiple_independent_implementations_per_family():
    p=campaign_plan()
    for f in FAMILIES:
        rows=[x for x in p if x['family_id']==f.family_id]
        assert len({x['implementation_id'] for x in rows}) >= (2 if f.family_id=='M-RMM-SHAPE' else 3)
    assert {'direct_authoritative','recursive_resolver'} == {x['dns_path'] for x in p if x['family_id']=='M-DNS-BEACON'}
    assert {'python_websockets','java_websocket','chromium_websocket'} <= {x['client_stack'] for x in p if x['family_id']=='M-WSS-LONG'}
    assert {'python_socket','go_socket','java_socket'} <= {x['client_stack'] for x in p if x['family_id']=='M-TUNNEL'}


def test_stage_m_holdout_is_explicit_and_training_ineligible():
    p=campaign_plan()
    hold=[x for x in p if x['tier']=='implementation_holdout']
    assert hold and all(x['training_eligible'] is False for x in hold)
    assert all(x['stage_m_split_role']=='implementation_holdout' for x in hold)
    assert all(x['training_eligible'] is True for x in p if x['tier']!='implementation_holdout')


def test_stage_m_only_uses_local_aliases_and_real_netem_names():
    p=campaign_plan()
    assert all(x['front_host'].endswith('.test') for x in p)
    assert all(x['network_profile'] in NETWORK_PROFILES for x in p)


def test_stage_m_coverage_report_rejects_non_positive(tmp_path: Path):
    p=tmp_path/'campaigns.jsonl'
    p.write_text(json.dumps({'campaign_id':'x','family_id':'M-HTTPS-BEACON','label_binary':0,'positive_only':True,'external_dependency':False})+'\n')
    coverage,_=build_report(p)
    assert coverage['passed'] is False


def test_local_dns_fixture_answers_and_nxdomain():
    q=dns.message.make_query('abc.stage-m.test.','A')
    r=dns.message.from_wire(_authoritative_response(q.to_wire()))
    assert r.rcode()==dns.rcode.NOERROR and r.answer
    q=dns.message.make_query('abc.nx.stage-m.test.','A')
    r=dns.message.from_wire(_authoritative_response(q.to_wire()))
    assert r.rcode()==dns.rcode.NXDOMAIN
