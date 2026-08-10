import pandas as pd
import torch

from coverlab.research_contract_v3 import FRAMEWORKS, LONG_TIMING_SECONDS, NETEM_PROFILES, NETWORK_EVIDENCE_TYPES, framework_record, validate_framework_records, validate_ech_record, validation_role
from coverlab.pipeline_v3 import assign_split
from coverlab.sequence_fusion_v3 import TinyTCN, OPAQUE_CHANNELS, VISIBLE_CHANNELS, encode_opaque_sequence, encode_visible_sequence
from coverlab.train_baseline_v3 import availability_flags_v3
from coverlab.orchestrate_v3 import _benign_event_count, _long_event_count, _timing_factor


def test_validation_roles_are_four_way_and_deterministic():
    roles={validation_role(f'c-{i}') for i in range(500)}
    assert roles=={'expert_calibration','expert_threshold','fusion_train','fusion_threshold'}
    assert validation_role('same')==validation_role('same')


def test_framework_holdout_is_challenge_only():
    rec=framework_record('sliver','j-sliver-1',protocol='https',pcap_sha256='0'*64,lifecycle=['registration','idle','poll','synthetic_task','synthetic_result','sleep','reconnect'])
    assert validate_framework_records([rec])==[]
    assert rec['training_eligible'] is False and rec['post_exploitation'] is False
    assert validate_framework_records([dict(rec,training_eligible=True)])
    assert set(FRAMEWORKS)=={'sliver','adaptix','mythic_httpx','mythic_websocket'}


def test_ech_itself_is_never_attack_label():
    benign={'ech_mode':'accepted_h3','wire_real':True,'label_binary':0}
    assert validate_ech_record(benign)==[]
    assert validate_ech_record(dict(benign,label_binary=1))
    assert validate_ech_record({'ech_mode':'shared_frontend_suspicious','wire_real':True,'label_binary':1})==[]


def test_training_ineligible_is_forced_to_challenge():
    assert assign_split(pd.Series({'campaign_id':'l-00','experiment_stage':'L_long_timing','dataset_role':'long_timing_challenge','training_eligible':False}))=='challenge'
    assert assign_split(pd.Series({'campaign_id':'j-00','experiment_stage':'J_framework_holdout','dataset_role':'external_framework_holdout','training_eligible':False}))=='challenge'


def test_real_timing_and_network_contracts_are_populated():
    assert LONG_TIMING_SECONDS==(5,30,120,300,1200,3600)
    names={p.name for p in NETEM_PROFILES}
    assert {'clean','wan_20ms','wan_80ms','lossy_wifi','constrained'} <= names
    assert {'partial_capture','capture_loss','nat','forward_proxy','tls_inspection','tls_bypass','connection_migration'} <= set(NETWORK_EVIDENCE_TYPES)
    assert not ({'partial_capture','nat','forward_proxy','tls_inspection'} & names)


def test_reason_aware_missingness():
    df=pd.DataFrame({'visibility_mode':['opaque_and_ground_truth','content'],'inspection_policy':['bypass','not_applicable'],'sni_visibility':['hidden','clear'],'suricata_events':[0,4],'zeek_events':[0,5],'protocol':['h3','http'],'capture_tail_pass':[1,0],'suricata_parser_ok':[1,1],'zeek_parser_ok':[1,1]})
    out=availability_flags_v3(df)
    assert out.loc[0,'missing_reason_encrypted']==1
    assert out.loc[0,'missing_reason_parser_unsupported']==1
    assert out.loc[1,'missing_reason_truncated']==1


def test_opaque_tcn_uses_packet_only_shape_and_forward():
    pkt=pd.DataFrame({'ts':[1.,1.1,1.5],'direction':[1,-1,1],'packet_size':[150,420,180],'delta_t':[0,.1,.4],'transport':['tcp']*3,'tcp_syn':[1,0,0],'tcp_ack':[0,1,1],'tcp_fin':[0,0,1],'tcp_rst':[0,0,0],'tcp_psh':[0,1,1],'tcp_retransmit':[0,0,1],'flow_boundary':[1,0,0]})
    x,m=encode_opaque_sequence(pkt)
    assert x.shape==(len(OPAQUE_CHANNELS),96) and m.sum()==3
    model=TinyTCN(len(OPAQUE_CHANNELS));y=model(torch.tensor(x[None,:,:]),torch.tensor(m[None,:]));assert tuple(y.shape)==(1,)


def test_visible_sequence_categories_are_one_hot_not_hashed_scalars():
    tx=pd.DataFrame({'ts':[1.,2.,5.],'request_body_length':[10,0,20],'response_body_length':[0,30,0],'protocol':['https','grpc','wss'],'response_status':[200,204,200],'kind':['poll','result','heartbeat']})
    x,m=encode_visible_sequence(tx)
    assert x.shape==(len(VISIBLE_CHANNELS),96) and m.sum()==3
    protocol_start=4;kind_start=4+9
    assert all(x[protocol_start:kind_start,j].sum()==1 for j in range(3))
    assert all(x[kind_start:,j].sum()==1 for j in range(3))


def test_stage_k_length_distribution_has_all_matched_buckets():
    counts=[_benign_event_count(i) for i in range(100)]
    assert sum(n==1 for n in counts)==20
    assert sum(2<=n<=3 for n in counts)==20
    assert sum(4<=n<=10 for n in counts)==20
    assert sum(10<=n<=30 for n in counts)>=20
    assert any(n>=60 for n in counts)


def test_stage_l_is_multi_event_and_jittered():
    assert {_long_event_count(x) for x in (5,30,120,300)} >= {10,20,30}
    assert _timing_factor('jitter_20',1)!=_timing_factor('jitter_20',2)
    assert _timing_factor('burst_silence',4)>_timing_factor('burst_silence',1)
