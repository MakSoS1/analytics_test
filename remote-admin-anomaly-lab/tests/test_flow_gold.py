import pandas as pd
from adminlab.flow_gold import build_production_flow_features


def test_production_features_use_observed_flow_state_without_identifiers():
    conn=pd.DataFrame([
      {'uid':'C1','session_id':'s1','ts':1.0,'id.orig_h':'10.0.0.1','id.resp_h':'10.0.0.2','id.resp_p':22,'service':'ssh','duration':1.0,'orig_bytes':100,'resp_bytes':200,'orig_pkts':3,'resp_pkts':4},
      {'uid':'C2','session_id':'s2','ts':2.0,'id.orig_h':'10.0.0.1','id.resp_h':'10.0.0.3','id.resp_p':22,'service':'ssh','duration':1.0,'orig_bytes':80,'resp_bytes':120,'orig_pkts':2,'resp_pkts':3},
    ])
    f=build_production_flow_features(conn)
    assert list(f['flow_uid'])==['C1','C2']
    assert f.loc[0,'connections_1m']==0
    assert f.loc[1,'connections_1m']==1
    assert f.loc[0,'new_dst_for_src']==1 and f.loc[1,'new_dst_for_src']==1
    assert f.loc[1,'src_out_degree_1h']==1
    assert 'src_ip' not in f.columns and 'dst_ip' not in f.columns
    assert f.loc[0,'bytes_total']==300
