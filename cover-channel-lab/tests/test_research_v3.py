import hashlib

import numpy as np
import pandas as pd
import torch

from coverlab.research_contract_v3 import (
    FRAMEWORKS, LONG_TIMING_SECONDS, NETEM_PROFILES, framework_record,
    validate_framework_records, validate_ech_record, validation_role,
)
from coverlab.pipeline_v3 import assign_split
from coverlab.sequence_fusion_v3 import TinyTCN, encode_sequence
from coverlab.train_baseline_v3 import availability_flags_v3


def test_validation_roles_are_four_way_and_deterministic():
    roles={validation_role(f'c-{i}') for i in range(500)}
    assert roles=={'expert_calibration','expert_threshold','fusion_train','fusion_threshold'}
    assert validation_role('same')==validation_role('same')


def test_framework_holdout_is_challenge_only():
    rec=framework_record('sliver','j-sliver-1',protocol='https',pcap_sha256='0'*64,lifecycle=['registration','idle','poll','synthetic_task','synthetic_result','sleep','reconnect'])
    assert validate_framework_records([rec])==[]
    assert rec['training_eligible'] is False and rec['post_exploitation'] is False
    bad=dict(rec,training_eligible=True)
    assert validate_framework_records([bad])
    assert set(FRAMEWORKS)=={'sliver','adaptix','mythic_httpx','mythic_websocket'}


def test_ech_itself_is_never_attack_label():
    benign={'ech_mode':'accepted_h3','wire_real':True,'label_binary':0}
    assert validate_ech_record(benign)==[]
    assert validate_ech_record(dict(benign,label_binary=1))
    suspicious={'ech_mode':'shared_frontend_suspicious','wire_real':True,'label_binary':1}
    assert validate_ech_record(suspicious)==[]


def test_training_ineligible_is_forced_to_challenge():
    row=pd.Series({'campaign_id':'l-00','experiment_stage':'L_long_timing','dataset_role':'long_timing_challenge','training_eligible':False})
    assert assign_split(row)=='challenge'
    row2=pd.Series({'campaign_id':'j-00','experiment_stage':'J_framework_holdout','dataset_role':'external_framework_holdout','training_eligible':False})
    assert assign_split(row2)=='challenge'


def test_real_timing_and_netem_contracts_are_populated():
    assert LONG_TIMING_SECONDS==(5,30,120,300,1200,3600)
    names={p.name for p in NETEM_PROFILES}
    assert {'clean','wan_20ms','lossy_wifi','constrained','partial_capture'} <= names


def test_reason_aware_missingness():
    df=pd.DataFrame({'visibility_mode':['opaque_and_ground_truth','content'],'inspection_policy':['bypass','not_applicable'],
                     'sni_visibility':['hidden','clear'],'suricata_events':[0,4],'zeek_events':[0,5],
                     'protocol':['h3','http'],'capture_tail_pass':[1,0],'suricata_parser_ok':[1,1],'zeek_parser_ok':[1,1]})
    out=availability_flags_v3(df)
    assert out.loc[0,'missing_reason_encrypted']==1
    assert out.loc[0,'missing_reason_parser_unsupported']==1
    assert out.loc[1,'missing_reason_truncated']==1


def test_tcn_sequence_shape_and_forward():
    tx=pd.DataFrame({'ts':[1.0,2.0,5.0],'request_body_length':[10,0,20],'response_body_length':[0,30,0],
                     'protocol':['https']*3,'response_status':[200,204,200],'kind':['poll','result','poll']})
    x,m=encode_sequence(tx)
    assert x.shape==(6,64) and m.sum()==3
    model=TinyTCN(); y=model(torch.tensor(x[None,:,:]),torch.tensor(m[None,:]))
    assert tuple(y.shape)==(1,)
