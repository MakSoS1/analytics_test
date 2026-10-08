"""Origin diagnostics with explicit class balance, model power and session-disjoint office cohorts.
No feature or traffic editing. Existing inspected backgrounds are research-only.
"""
import argparse,hashlib,json
from pathlib import Path
import numpy as np
import pandas as pd
from office_injection.source import sha256

def score_models(train,ytrain,test,ytest):
    from sklearn.ensemble import HistGradientBoostingClassifier,ExtraTreesClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import roc_auc_score
    names=list(train);models={'legacy_unweighted_hgb':HistGradientBoostingClassifier(max_iter=120,max_depth=4,min_samples_leaf=20,early_stopping=False,random_state=1701),
        'balanced_hgb':HistGradientBoostingClassifier(max_iter=120,max_depth=4,min_samples_leaf=10,class_weight='balanced',early_stopping=False,random_state=1701),
        'balanced_extra_trees':ExtraTreesClassifier(n_estimators=128,min_samples_leaf=2,class_weight='balanced',random_state=1701,n_jobs=2),
        'balanced_logistic':make_pipeline(StandardScaler(),LogisticRegression(C=1,class_weight='balanced',max_iter=2000,random_state=1701))}
    yt=np.asarray(ytrain);yv=np.asarray(ytest);counts={'train_generated':int((yt==0).sum()),'train_office':int((yt==1).sum()),'test_generated':int((yv==0).sum()),'test_office':int((yv==1).sum())}
    result={'feature_order':names,'rows':counts,'support_status':'sufficient_segment_count' if min(counts.values(),default=0)>=50 else 'insufficient_generated_train' if counts['train_generated']<50 else 'insufficient_segments'}
    if len(set(yt))<2 or len(set(yv))<2:
        return {**result,'support_status':'missing_class',**{n:{'auc':None} for n in models}}
    a=train.to_numpy(dtype=float,na_value=np.nan).copy();b=test[names].to_numpy(dtype=float,na_value=np.nan).copy()
    a[~np.isfinite(a)]=np.nan;b[~np.isfinite(b)]=np.nan
    native_a=a.copy();native_b=b.copy();empty=~np.isfinite(a).any(axis=0);native_a[:,empty]=0;native_b[:,empty]=0
    result['missingness_policy']='HGB uses observed NaN; train-empty columns fixed to zero; extra trees/logistic use train-only median imputation; every column retained'
    for i in range(len(names)):
        finite=np.isfinite(a[:,i]);median=np.median(a[finite,i]) if finite.any() else 0
        a[~finite,i]=median;b[~np.isfinite(b[:,i]),i]=median
    for name,model in models.items():
        fit_a,fit_b=(native_a,native_b) if name.endswith('hgb') else (a,b)
        model.fit(fit_a,yt);score=model.predict_proba(fit_b)[:,1];auc=float(roc_auc_score(yv,score))
        result[name]={'auc':auc,'symmetric_auc':max(auc,1-auc),'score_std':float(np.std(score)),'unique_scores':int(len(np.unique(score)))}
    return result

def _rank(value):return hashlib.sha256(str(value).encode()).hexdigest()

def audit(source,out):
    source=Path(source);out=Path(out)
    if out.exists():raise FileExistsError('retain previous diagnostics')
    complete=json.loads((source/'COMPLETE.json').read_text())
    for name in ('features_all.parquet','labels_metadata.parquet'):
        if sha256(source/name)!=complete['files'][name]:raise ValueError('training pin differs')
    x=pd.read_parquet(source/'features_all.parquet');m=pd.read_parquet(source/'labels_metadata.parquet');o=pd.read_parquet(source/'office_full_features.parquet')
    shape=lambda a:a.syn_count.gt(0)&a.data_pkt_up.gt(0)&a.data_pkt_down.gt(0)&a.tls_sni_len.gt(0)
    o=o.loc[shape(o)].copy();days=sorted(o.office_capture_day.unique());reference,last=days[0],days[-1]
    # All rows of one session stay in one partition, including sessions spanning days.
    ranks=o.global_session_uid.map(_rank);validation=ranks.str[:2].map(lambda v:int(v,16)%4==0)
    tr=o.office_capture_day.eq(reference)&~validation;va=o.office_capture_day.eq(reference)&validation
    train_sessions=set(o.loc[tr,'global_session_uid']);validation_sessions=set(o.loc[va,'global_session_uid'])
    te=o.office_capture_day.eq(last)&~o.global_session_uid.isin(train_sessions|validation_sessions)
    def sample(mask,n=5000):
        d=o.loc[mask].copy();d['_rank']=d.global_session_uid.map(_rank);return d.sort_values(['_rank','row_index']).iloc[:n]
    cohorts={'train':sample(tr),'validation':sample(va,2000),'test':sample(te)}
    base=m.label_state.eq('matched_control')&m.arm.eq('control')
    populations={'original_matched_controls':base,'ordinary_fixture':m.technique.str.startswith('BENIGN_WEB_'),'public_first':m.technique.str.startswith('BENIGN_PUBLIC_'),'browse_all':m.technique.str.startswith('BENIGN_BROWSE_')}
    for path in range(2):
        for usage in range(2):
            p=m.profile_id.astype(str).str.extract(r'^p(\d+)$')[0].astype(float)
            populations[f'browse_path{path}_usage{usage}']=populations['browse_all']&p.floordiv(6).eq(path)&p.mod(6).floordiv(3).eq(usage)
    rows={}
    for name,mask in populations.items():
        if not mask.any():continue
        train=mask&shape(x)&m.split.eq('train')&m.office_capture_day.eq(reference)
        reports={}
        for split in ('validation','test'):
            generated=mask&shape(x)&m.split.eq(split)&m.office_capture_day.eq(reference if split=='validation' else last)
            a=pd.concat([x.loc[train],cohorts['train'][list(x)]]);b=pd.concat([x.loc[generated],cohorts[split][list(x)]])
            reports[split]=score_models(a,np.r_[np.zeros(train.sum()),np.ones(len(cohorts['train']))],b,np.r_[np.zeros(generated.sum()),np.ones(len(cohorts[split]))])
            reports[split]['generated_train_groups']=int(m.loc[train,'group_id'].nunique());reports[split]['generated_evaluation_groups']=int(m.loc[generated,'group_id'].nunique())
        rows[name]=reports;print('POPULATION',name,json.dumps({sp:{k:q[k]['auc'] for k in ('balanced_hgb','balanced_extra_trees','balanced_logistic')} for sp,q in reports.items()}),flush=True)
    # Same-office random session cohorts: classifier-power sanity, not evidence of office-positive transfer.
    def random_target(d):return d.global_session_uid.map(lambda v:int(_rank('cohort:'+str(v))[:2],16)%2).to_numpy()
    sanity=score_models(cohorts['train'][list(x)],random_target(cohorts['train']),cohorts['test'][list(x)],random_target(cohorts['test']))
    result={'version':'origin-power-v2','audit_code_sha256':sha256(__file__),'source_identity':complete['source_identity'],'training_complete_sha256':sha256(source/'COMPLETE.json'),'office_sha256':sha256(source/'office_full_features.parquet'),'features':list(x),'feature_count':len(x.columns),'office_session_disjoint':True,
        'office_cohorts':{k:len(v) for k,v in cohorts.items()},'populations':rows,'same_office_random_cohort_sanity':sanity,'naturalness_established':False,'production_ready':False,
        'limits':['All retained backgrounds have already been inspected; this is not new independent office validation.','Whole TCP/bidirectional/SNI shape is selected; private/public context is unavailable in this compact export.','Segment counts do not replace independent activity/session group counts.','Balanced diagnostic models retain every feature; they are not deployment models.','50-row support warning is a predeclared diagnostic floor, not statistical certification.','Source differences may reflect application mix; same-office sanity is a negative control, not naturalness certification.']}
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();audit(a.source,a.out)
