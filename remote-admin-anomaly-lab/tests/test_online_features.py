from adminlab.online_features import EveFeatureState


def flow(ts,src,dst,flow_id,*,port=22,app_proto='ssh'):
    return {'timestamp':ts,'event_type':'flow','flow_id':flow_id,'src_ip':src,'src_port':50000,'dest_ip':dst,'dest_port':port,'proto':'TCP','app_proto':app_proto,'flow':{'start':ts,'end':ts,'bytes_toserver':100,'bytes_toclient':200,'pkts_toserver':3,'pkts_toclient':4}}


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


def test_ngfw_state_exposes_pair_recency_protocol_familiarity_and_destination_prevalence():
    s=EveFeatureState()
    first=s.consume_flow(flow('2026-08-14T09:00:00+00:00','10.0.0.1','10.0.0.2',1))
    second=s.consume_flow(flow('2026-08-14T09:05:00+00:00','10.0.0.1','10.0.0.2',2))
    third=s.consume_flow(flow('2026-08-14T09:06:00+00:00','10.0.0.1','10.0.0.3',3,port=445,app_proto='smb'))
    other=s.consume_flow(flow('2026-08-14T09:07:00+00:00','10.0.0.9','10.0.0.2',4))

    assert first['features']['pair_recency_s'] == -1.0
    assert second['features']['pair_recency_s'] == 300.0
    assert second['features']['source_protocol_seen_count_prior'] == 1
    assert second['features']['source_protocol_novelty'] == 0
    assert third['features']['source_protocol_seen_count_prior'] == 0
    assert third['features']['source_protocol_novelty'] == 1
    assert third['features']['recent_protocol_switch_count_1h'] >= 0
    assert other['features']['destination_seen_count_prior'] == 2
    assert second['features']['source_pair_protocol_seen_count_prior'] == 1


def test_current_event_is_inserted_only_after_scoring_new_edge_ratio():
    s=EveFeatureState()
    a=s.consume_flow(flow('2026-08-14T09:00:00+00:00','10.0.0.1','10.0.0.2',1))
    b=s.consume_flow(flow('2026-08-14T09:00:10+00:00','10.0.0.1','10.0.0.3',2))
    c=s.consume_flow(flow('2026-08-14T09:00:20+00:00','10.0.0.1','10.0.0.2',3))
    assert a['features']['new_edge_ratio_1h'] == 0.0
    assert b['features']['new_edge_ratio_1h'] == 1.0
    assert 0.0 < c['features']['new_edge_ratio_1h'] <= 1.0


def test_state_snapshot_restore_preserves_next_feature_vector_exactly():
    original=EveFeatureState()
    original.consume_flow(flow('2026-08-14T09:00:00+00:00','10.0.0.1','10.0.0.2',1))
    original.consume_flow(flow('2026-08-14T09:05:00+00:00','10.0.0.1','10.0.0.3',2,port=445,app_proto='smb'))
    snapshot=original.to_dict()
    restored=EveFeatureState.from_dict(snapshot)
    event=flow('2026-08-14T09:10:00+00:00','10.0.0.1','10.0.0.2',3)
    expected=original.consume_flow(event)
    actual=restored.consume_flow(event)
    assert actual['features']==expected['features']
    assert actual['context']==expected['context']
    assert restored.to_dict()==original.to_dict()
