"""Exploratory validation-only feature masks; persisted X is never edited.

The historic held-out source days have already been inspected. Results here
are diagnostics, not a new independent deployment acceptance or FPR estimate.
"""
import argparse
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score
from demo.audit_origin_families import families
from office_injection.source import sha256
from office_injection.training_contract import SESSION_FEATURES,validate_training_contract


def choose_candidate(rows,origin_limit=.60,technique_min=.70):
    allowed=[r for r in rows if r['validation_origin_auc'] is not None and r['validation_technique_auc'] is not None
        and max(r['validation_origin_auc'],1-r['validation_origin_auc'])<=origin_limit
        and r['validation_technique_auc']>=technique_min]
    return max(allowed,key=lambda r:r['validation_technique_auc']) if allowed else None


def best_origin_candidate(rows):
    available=[r for r in rows if r['validation_origin_auc'] is not None and r['validation_technique_auc'] is not None]
    return min(available,key=lambda r:(max(r['validation_origin_auc'],1-r['validation_origin_auc']),-r['validation_technique_auc'])) if available else None


def fit_score(train,ytrain,validation,yvalidation,names):
    if not names or len(set(ytrain))<2 or len(set(yvalidation))<2:return None,None
    tr=train[names].to_numpy(dtype=float,na_value=np.nan).copy()
    va=validation[names].to_numpy(dtype=float,na_value=np.nan).copy()
    tr[~np.isfinite(tr)]=np.nan;va[~np.isfinite(va)]=np.nan
    empty=~np.isfinite(tr).any(axis=0);tr[:,empty]=0;va[:,empty]=0
    model=HistGradientBoostingClassifier(max_iter=100,max_depth=4,early_stopping=False,random_state=1701)
    model.fit(tr,ytrain)
    return float(roc_auc_score(yvalidation,model.predict_proba(va)[:,1])),(model,empty)


def heldout(model,test,ytest,names):
    if model is None or len(set(ytest))<2:return None
    m,empty=model;x=test[names].to_numpy(dtype=float,na_value=np.nan).copy()
    x[~np.isfinite(x)]=np.nan;x[:,empty]=0
    return float(roc_auc_score(ytest,m.predict_proba(x)[:,1]))


def audit(training,out):
    training=Path(training);out=Path(out)
    if out.exists():raise FileExistsError('retain previous mask diagnostics')
    c=json.loads((training/'COMPLETE.json').read_text())
    for name,pin in c['files'].items():
        if sha256(training/name)!=pin:raise ValueError('training changed')
    x=pd.read_parquet(training/'features_all.parquet');m=pd.read_parquet(training/'labels_metadata.parquet')
    office=pd.read_parquet(training/'office_unlabelled_sample.parquet');om=pd.read_parquet(training/'office_sample_metadata.parquet')
    names=list(SESSION_FEATURES)
    if list(x)!=names or list(office)!=names:raise ValueError('89 persisted feature schema changed')
    tr=m.split.eq('train');va=m.split.eq('validation');te=m.split.eq('test')
    reference=min(om.office_capture_day);last=max(om.office_capture_day)
    # The source test keeps the old matched-control population, without diluting
    # a failed source test using the newly added ordinary-client negatives.
    control=m.label_state.eq('matched_control') & m.arm.eq('control')
    shape=lambda t:(t.data_pkt_up>0)&(t.data_pkt_down>0)&(t.tls_sni_len>0)
    gtr=control & tr & m.office_capture_day.eq(reference) & shape(x)
    gva=control & va & m.office_capture_day.eq(reference) & shape(x)
    gte=control & te & m.office_capture_day.eq(last) & shape(x)
    candidates=np.flatnonzero(om.office_capture_day.eq(reference)&shape(office))
    np.random.default_rng(1701).shuffle(candidates);cut=int(len(candidates)*.7)
    otr=office.iloc[candidates[:cut]];ova=office.iloc[candidates[cut:]]
    ote=office.loc[om.office_capture_day.eq(last)&shape(office)]
    origin_train=pd.concat([x.loc[gtr],otr]);oytr=np.r_[np.zeros(int(gtr.sum())),np.ones(len(otr))]
    origin_val=pd.concat([x.loc[gva],ova]);oyva=np.r_[np.zeros(int(gva.sum())),np.ones(len(ova))]
    origin_test=pd.concat([x.loc[gte],ote]);oyte=np.r_[np.zeros(int(gte.sum())),np.ones(len(ote))]
    groups=families(names);masks={'all_89':names}
    for family,columns in groups.items():
        masks['only_'+family]=columns
        masks['without_'+family]=[n for n in names if n not in columns]
    for a,b in [('size','timing'),('size','tls'),('timing','tls'),('payload','tls')]:
        masks['without_'+a+'_'+b]=[n for n in names if n not in groups[a]+groups[b]]
    # Train-only marginal screening also accounts for source-dependent missingness.
    scores={}
    for n in names:
        v=origin_train[n].to_numpy(dtype=float,na_value=np.nan);finite=np.isfinite(v)
        if len(set(oytr))<2:raise ValueError('origin train requires two populations')
        imputed=np.where(finite,v,np.median(v[finite]) if finite.any() else 0)
        a=roc_auc_score(oytr,imputed);b=roc_auc_score(oytr,~finite)
        scores[n]=float(max(a,1-a,b,1-b))
    for threshold in (.55,.60,.65):masks['marginal_source_max_'+str(threshold)]=[n for n in names if scores[n]<=threshold]
    rows=[];seen=set();trained={}
    for label,columns in masks.items():
        key=tuple(columns)
        if key in seen or not columns:continue
        seen.add(key);validate_training_contract(columns)
        ta,tm=fit_score(x.loc[tr],m.loc[tr,'label_binary'],x.loc[va],m.loc[va,'label_binary'],columns)
        oa,omodel=fit_score(origin_train,oytr,origin_val,oyva,columns)
        rows.append({'mask':label,'features':columns,'feature_count':len(columns),
                     'validation_technique_auc':ta,'validation_origin_auc':oa})
        trained[label]=(tm,omodel)
        print('MASK',label,len(columns),ta,oa,flush=True)
    selected=choose_candidate(rows)
    # A best diagnostic alternative is shown even when the joint gate fails;
    # it is explicitly not selected or qualified for deployment.
    best=best_origin_candidate(rows)
    tested={}
    for r in (rows[0],best,selected):
        if r is None or r['mask'] in tested:continue
        tm,omodel=trained[r['mask']]
        tested[r['mask']]={'test_technique_auc':heldout(tm,x.loc[te],m.loc[te,'label_binary'],r['features']),
            'test_origin_auc':heldout(omodel,origin_test,oyte,r['features'])}
    result={'version':'feature-tradeoff-research-v1','source_identity':c['source_identity'],
        'training_complete_sha256':sha256(training/'COMPLETE.json'),'persisted_features':89,'data_unchanged':True,
        'source_population':'matched controls and office, bidirectional SNI; context day matched; no new-negative dilution',
        'source_rows':{'train_control':int(gtr.sum()),'validation_control':int(gva.sum()),'test_control':int(gte.sum()),
                       'train_office':len(otr),'validation_office':len(ova),'test_office':len(ote)},
        'candidates':rows,'candidate_count':len(rows),'marginal_train_origin_scores':scores,
        'selection_uses':'train for screening/fitting; validation for joint choice; test only for frozen baseline/best-diagnostic/selected',
        'research_gate':{'origin_max_symmetric_auc':.60,'technique_min_auc':.70},
        'selected':selected,'best_origin_diagnostic':best['mask'] if best else None,'test_results':tested,
        'production_ready':False,'naturalness_established':False,
        'limits':['Office validation splits segment rows; session independence is unverified because office sample metadata lacks session identity.','Exploratory masks, not exhaustive subset search.','Historic test backgrounds already inspected; no new independent office transfer test.',
                  'Origin neutrality without technique signal is not acceptance.','AUC is not precision, accuracy or office FPR.']}
    out.write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--training',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();r=audit(a.training,a.out);print('SELECTED',r['selected']['mask'] if r['selected'] else None)
