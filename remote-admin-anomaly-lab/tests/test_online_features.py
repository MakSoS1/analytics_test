from adminlab.online_features import EveFeatureState


def flow(ts,src,dst,flow_id):
    return {'timestamp':ts,'event_type':'flow','flow_id':flow_id,'src_ip':src,'src_port':50000,'dest_ip':dst,'dest_port':22,'proto':'TCP','app_proto':'ssh','flow':{'start':ts,'end':ts,'bytes_toserver':100,'bytes_toclient':200,'pkts_toserver':3,'pkts_toclient':4}}


def test_online_state_is_prior_only_and_does_not_emit_ip_as_feature():
    s=EveFeatureState()
    a=s.consume_flow(flow('2026-08-14T09:00:00+00:00','10.0.0.1','10.0.0.2',1))
    b=s.consume_flow(flow('2026-08-14T09:00:10+00:00','10.0.0.1','10.0.0.3',2))
    assert a['features']['connections_1m']==0
    assert b['features']['connections_1m']==1
    assert b['features']['src_out_degree_1h']==1
    assert a['features']['new_dst_for_src']==1 and b['features']['new_dst_for_src']==1
    assert 'src_ip' not in a['features'] and 'dest_ip' not in a['features']
    assert a['context']['src_ip']=='10.0.0.1'
