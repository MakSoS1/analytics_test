"""Branch-local observer of the existing assembler; its features/state stay unchanged.

Held packets already carry exact times and endpoint identity in the baseline
checkpoint. Immutable positive evidence is kept for the entire run, so the
observer can label emitted segments after any batch boundary without guessing
session instance counters or changing the baseline checkpoint format.
"""
from __future__ import annotations
import argparse
import json
import sys
from collections import defaultdict,Counter
from contextlib import contextmanager
from pathlib import Path
import extract_office_sessions as office
from .records import iter_rows,flow_key
from .source import sha256


@contextmanager
def observe_gt(registry,out_path):
    lookup=defaultdict(dict)
    for item in registry:
        path=Path(item['path'])
        if item.get('sha256') and sha256(path)!=item['sha256']:raise ValueError('positive evidence changed')
        for x,_ in iter_rows(path):
            key=flow_key(x);stamp=round(x[0]*1e6)
            previous=lookup[key].get(stamp)
            if previous and previous['injection_id']!=item['injection_id']:
                raise ValueError('ambiguous positive packet membership')
            lookup[key][stamp]=item
    original=office._build_row
    target=Path(out_path);target.parent.mkdir(parents=True,exist_ok=True)
    with target.open('w') as output, target.with_suffix('.lineage.jsonl').open('w') as lineage:
        def build(sess,*args,**kwargs):
            result=original(sess,*args,**kwargs)
            if result is None:return result
            r=result[0]
            lineage.write(json.dumps({'session_uid':r['session_uid'],'segment_uid':r['segment_uid'],
                'wire_packet_count':len(sess.ts),'feature_packet_count':int(r['pkt_count'])})+'\n')
            key=(sess.ip_a,sess.port_a,sess.ip_b,sess.port_b,6 if sess.proto=='tcp' else 17)
            evidence=lookup.get(key)
            if evidence:
                counts=Counter();metas={}
                for ts in sess.ts:
                    item=evidence.get(round(ts*1e6))
                    if item: counts[item['injection_id']]+=1;metas[item['injection_id']]=item
                for ident,count in counts.items():
                    item=metas[ident];r=result[0]
                    if count!=len(sess.ts):raise ValueError('positive and background packets share a segment')
                    output.write(json.dumps({'session_uid':r['session_uid'],'segment_uid':r['segment_uid'],
                        'segment_index':r['segment_index'],'injection_id':ident,
                        'campaign_id':item.get('campaign_id'),'technique':item.get('technique'),
                        'arm':item.get('arm','scenario'),
                        'dataset_role':item.get('dataset_role','scenario_and_matched_control'),
                        'positive_packet_count':count,'modeled_positive_packet_count':int(r['pkt_count']),
                        'label_scope':item.get('label_scope','transport_session_positive_campaign'),
                        'label_state':'hard_negative_confirmed' if item.get('dataset_role')=='hard_negative' else 'negative_control_confirmed' if item.get('arm')=='control' else 'positive_confirmed',
                        'training_eligible':item.get('training_eligible',False),
                        'timing_training_eligible':item.get('timing_training_eligible',False)})+'\n')
            return result
        office._build_row=build
        try:yield
        finally:office._build_row=original


def main():
    p=argparse.ArgumentParser();p.add_argument('--gt-registry',required=True,type=Path)
    p.add_argument('--gt-out',required=True,type=Path)
    args,rest=p.parse_known_args()
    sys.argv=[str(Path(office.__file__)),*rest]
    with observe_gt(json.loads(args.gt_registry.read_text()),args.gt_out):return office.main()


if __name__=='__main__':raise SystemExit(main())
