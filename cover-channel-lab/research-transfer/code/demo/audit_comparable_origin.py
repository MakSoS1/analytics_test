"""Origin on Internet-style whole TCP/TLS sessions, with context days matched.

Keeps all 89 X columns. Office private/public and whole-flow facts select a
comparison population only; they are never classifier inputs. Does not change
any traffic or replace a broad origin diagnostic.
"""
import argparse
import json
from pathlib import Path
import random
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from demo.audit_origin_families import _auc, families
from office_injection.training_contract import SESSION_FEATURES,source_identity
from office_injection.source import sha256


TLS_FIELDS=('tls_cipher_count','tls_ext_count','tls_group_count','tls_sigalg_count')


def common_tls_support(generated,office,min_generated=10,min_office=20):
    """Frozen TRAIN support of observed count-tuples; not proof of stack identity."""
    from collections import Counter
    def count(d):
        return Counter(tuple(map(float,v)) for v in d[list(TLS_FIELDS)].to_numpy(dtype=float,na_value=np.nan) if np.isfinite(v).all())
    g,o=count(generated),count(office)
    return {t for t,n in g.items() if n>=min_generated and o[t]>=min_office}


def tls_inside(d,support):
    return np.array([np.isfinite(v).all() and tuple(v) in support for v in d[list(TLS_FIELDS)].to_numpy(dtype=float,na_value=np.nan)],dtype=bool)


def generated_mask(labels,techniques=None,states=('matched_control',),arm='control'):
    mask=labels.label_state.isin(states)
    if arm is not None:mask &= labels.arm.eq(arm)
    if techniques is not None:mask &= labels.technique.isin(techniques)
    return mask


def audit(root,max_per_day=5000,generated_techniques=None,generated_states=('matched_control',),generated_arm='control',power_check=False):
    root=Path(root);t=root/'research_training_v2';combined=root/'combined_sessions_v2'
    complete=json.loads((t/'COMPLETE.json').read_text())
    if source_identity(combined)!=complete['source_identity']:raise ValueError('source changed')
    for name,pin in complete['files'].items():
        if sha256(t/name)!=pin:raise ValueError('training changed: '+name)
    manifest=json.loads((t/'manifest.json').read_text());names=list(SESSION_FEATURES)
    features=pd.read_parquet(t/'features_all.parquet');labels=pd.read_parquet(t/'labels_metadata.parquet')
    ref=manifest['office_reference_day'];days=manifest['office_days'];last=days[-1]
    member=set()
    for p in combined.glob('batches/*/parquet/segment_gt.parquet'):
        member.update(pq.ParquetFile(p).read(columns=['global_segment_uid'])['global_segment_uid'].to_pylist())
    rng=random.Random(1701);samples={day:[] for day in days};counts={day:0 for day in days}
    from datetime import timezone
    from zoneinfo import ZoneInfo
    for p in sorted(combined.glob('batches/*/parquet/office_sessions.parquet')):
        reader=pq.ParquetFile(p)
        extra=['tcp_share','client_internal','server_internal','segment_start_ts','global_segment_uid']
        for b in reader.iter_batches(batch_size=4096,columns=names+extra):
            for r in b.to_pylist():
                if r['global_segment_uid'] in member:continue
                if r['client_internal']!=1 or r['server_internal']!=0:continue
                if not (r['tcp_share']==1 and all(r.get(k) is not None and r[k]>0 for k in ('syn_count','data_pkt_up','data_pkt_down','tls_sni_len'))):continue
                day=r['segment_start_ts'].replace(tzinfo=timezone.utc).astimezone(ZoneInfo('Europe/Moscow')).date().isoformat()
                if day not in samples:raise ValueError('office day outside manifest')
                counts[day]+=1;row={n:r[n] for n in names}
                if len(samples[day])<max_per_day:samples[day].append(row)
                elif (j:=rng.randrange(counts[day]))<max_per_day:samples[day][j]=row
    controls=generated_mask(labels,generated_techniques,generated_states,generated_arm)
    # Generated TCP/TLS candidates are selected by observed SYN and SNI;
    # tcp_share is metadata in full office rows, outside the 89-feature X.
    shape=(features.syn_count>0)&(features.data_pkt_up>0)&(features.data_pkt_down>0)&(features.tls_sni_len>0)
    tr=controls & shape & labels.split.eq('train') & labels.office_capture_day.eq(ref)
    te=controls & shape & labels.split.eq('test') & labels.office_capture_day.eq(last)
    og=pd.DataFrame(samples[ref],columns=names);oe=pd.DataFrame(samples[last],columns=names)
    train_x=pd.concat([features.loc[tr,names],og]);test_x=pd.concat([features.loc[te,names],oe])
    train_y=np.r_[np.zeros(int(tr.sum())),np.ones(len(og))];test_y=np.r_[np.zeros(int(te.sum())),np.ones(len(oe))]
    result={'source_identity':complete['source_identity'],'training_complete_sha256':sha256(t/'COMPLETE.json'),
        'selection':'private client -> public server; TCP; SYN observed; bidirectional payload; SNI present',
        'day_policy':'generated train and office train on reference day; held-out generated profiles and office on last day',
        'feature_order':names,'feature_count':len(names),'origin_auc_all_features':_auc(train_x,train_y,test_x,test_y,names),
        'rows':{'train_control':int(tr.sum()),'test_control':int(te.sum()),'train_office':len(og),'test_office':len(oe)},
        'office_population_by_day':counts,'only_family':{},'production_ready':False,
        'scope':'conditional diagnostic on calibration backgrounds, not independent office-positive transfer',
        'generated_population':{'techniques':generated_techniques,'states':list(generated_states),'arm':generated_arm}}
    if power_check:
        from demo.audit_origin_power import score_models
        result['same_cohort_power_check']=score_models(train_x,train_y,test_x,test_y)
        result['same_cohort_power_scope']='Exact same comparison rows; changes model balance/capacity only. Historical backgrounds and small generated group support remain limitations.'
    for family,columns in families(names).items():result['only_family'][family]=_auc(train_x,train_y,test_x,test_y,columns)
    support=common_tls_support(features.loc[tr,names],og)
    gc_train=features.loc[tr,names];gc_test=features.loc[te,names]
    cg=gc_train.loc[tls_inside(gc_train,support)];co=og.loc[tls_inside(og,support)]
    eg=gc_test.loc[tls_inside(gc_test,support)];eo=oe.loc[tls_inside(oe,support)]
    result['common_tls_tuple']={'fields':list(TLS_FIELDS),'support_fitted_on':'reference-day train only',
        'minimum_train_control_per_tuple':10,'minimum_train_office_per_tuple':20,'tuples':sorted(support),
        'rows':{'train_control':len(cg),'train_office':len(co),'test_control':len(eg),'test_office':len(eo)},
        'origin_auc_all_89':_auc(pd.concat([cg,co]),np.r_[np.zeros(len(cg)),np.ones(len(co))],
            pd.concat([eg,eo]),np.r_[np.zeros(len(eg)),np.ones(len(eo))],names),
        'scope':'conditional overlap diagnostic; equal count-tuples do not establish identical TLS stacks; not an acceptance replacement'}
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();r=audit(a.root)
    with a.out.open('x') as f:f.write(json.dumps(r,indent=2)+'\n')
    print(json.dumps({k:r[k] for k in ('rows','origin_auc_all_features','only_family')},indent=2))
