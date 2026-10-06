"""Research-only session learning, with campaign siblings kept out of holdouts.

This is deliberately separate from production feature admission. Office rows
have no target; they enter origin diagnostics and unsupervised mixed clusters.
The learned representation is the existing 89-feature session extractor.
"""
import argparse
from collections import Counter
from datetime import timezone
from zoneinfo import ZoneInfo
import json
from pathlib import Path
import random
import math
from .audit import auc
from .training_contract import SESSION_FEATURES, validate_training_contract, source_identity
from .source import sha256
from .pipeline import dump


def group_split(metadata,seed=20261004):
    groups=sorted({r['group_id'] for r in metadata})
    if len(groups)<10:raise ValueError('at least ten distinct observed profile groups required')
    random.Random(seed).shuffle(groups)
    first=max(1,int(.6*len(groups)));second=max(first+1,int(.8*len(groups)))
    mapping={g:'train' if i<first else 'validation' if i<second else 'test' for i,g in enumerate(groups)}
    return [mapping[r['group_id']] for r in metadata]


def extend_group_split(metadata, frozen, seed=20261004):
    """Preserve every old group; assign only new groups to declared holdouts."""
    mapping={}
    for row in frozen:
        group,split=row['group_id'],row['split']
        if split not in ('train','validation','test') or group in mapping and mapping[group]!=split:
            raise ValueError('invalid or conflicting frozen group split')
        mapping[group]=split
    groups={r['group_id'] for r in metadata}
    if not set(mapping)<=groups:raise ValueError('augmented dataset lost frozen groups')
    new=sorted(groups-set(mapping))
    if len(new)<3:raise ValueError('three new profile groups required for declared holdouts')
    random.Random(seed).shuffle(new)
    first=max(1,int(.6*len(new)));second=max(first+1,int(.8*len(new)))
    mapping.update({g:'train' if i<first else 'validation' if i<second else 'test' for i,g in enumerate(new)})
    return [mapping[r['group_id']] for r in metadata]


def choose_features(control,scenario,office,names,technique_threshold=.60,origin_threshold=.60):
    def values(rows,n):
        out=[]
        for r in rows:
            try:x=float(r.get(n))
            except (ValueError,TypeError):continue
            if math.isfinite(x):out.append(x)
        return out
    selected=[];diagnostics=[]
    for name in names:
        c,s,o=(values(rows,name) for rows in (control,scenario,office))
        ta=auc(c,s) if c and s else None
        da=auc(o,c) if o and c else None
        t=max(ta,1-ta) if ta is not None else None
        d=max(da,1-da) if da is not None else None
        missing_c=1-len(c)/len(control) if control else 1
        missing_o=1-len(o)/len(office) if office else 1
        keep=t is not None and d is not None and t>technique_threshold and d<=origin_threshold and abs(missing_c-missing_o)<=.1
        diagnostics.append({'feature':name,'technique_auc':t,'origin_auc':d,'selected_on_train':keep,
                            'control_missing':missing_c,'office_missing':missing_o})
        if keep:selected.append(name)
    return selected,diagnostics


def fit_research(x,metadata,splits,names,out,seed=20261004,office_train=None,office_test=None,office_reference_day=None):
    import numpy as np
    import joblib
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import roc_auc_score,average_precision_score,balanced_accuracy_score,adjusted_rand_score,normalized_mutual_info_score,silhouette_score
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    from sklearn.cluster import KMeans
    from sklearn.pipeline import make_pipeline
    validate_training_contract(names)
    x=np.asarray(x,dtype=float);x[~np.isfinite(x)]=np.nan
    y=np.array([r['label_binary'] for r in metadata]);sp=np.array(splits)
    train=sp=='train';val=sp=='validation';test=sp=='test'
    if x.shape!=(len(y),len(names)) or len(sp)!=len(y):raise ValueError('X/labels/splits alignment differs')
    group_splits={}
    for r,s in zip(metadata,splits):group_splits.setdefault(r['group_id'],set()).add(s)
    if any(len(v)!=1 for v in group_splits.values()):raise ValueError('campaign/profile siblings cross holdouts')
    if any(len(set(y[mask]))!=2 for mask in (train,val,test)):raise ValueError('both labelled classes required in every split')
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    model=HistGradientBoostingClassifier(max_iter=120,max_leaf_nodes=15,min_samples_leaf=10,class_weight='balanced',random_state=seed,early_stopping=False)
    counts=Counter(r['group_id'] for r,s in zip(metadata,splits) if s=='train')
    weight=np.array([1/counts[r['group_id']] for r,s in zip(metadata,splits) if s=='train'])
    weight*=len(weight)/weight.sum()
    model.fit(x[train],y[train],sample_weight=weight)
    joblib.dump({'model':model,'feature_order':list(names),'contract':validate_training_contract(names),
                 'scope':'within_source_campaign_holdout','production_ready':False},out/'baseline.joblib')
    def metrics(mask):
        scores=model.predict_proba(x[mask])[:,1]
        return {'roc_auc':float(roc_auc_score(y[mask],scores)),
                'average_precision':float(average_precision_score(y[mask],scores)),
                'balanced_accuracy_at_050':float(balanced_accuracy_score(y[mask],scores>=.5)),
                'rows':int(mask.sum())}
    report={'evaluation_scope':'within_source_campaign_holdout','production_training_ready':False,
            'feature_order':list(names),'split_rows':dict(Counter(splits)),
            'split_groups':dict(Counter(next(iter(v)) for v in group_splits.values())),
            'binary_validation':metrics(val),'binary_test':metrics(test),
            'meaning':'confirmed generated activities versus matched controls/hard negatives; not office FPR'}
    test_scores=model.predict_proba(x[test])[:,1]
    report['technique_test']={}
    test_meta=[r for r,keep in zip(metadata,test) if keep]
    for technique in sorted({r['technique'] for r in test_meta}):
        ix=[i for i,r in enumerate(test_meta) if r['technique']==technique]
        ty=y[test][ix];ts=test_scores[ix]
        report['technique_test'][technique]={'rows':len(ix),
            'profile_groups':len({test_meta[i]['group_id'] for i in ix}),
            'roc_auc':float(roc_auc_score(ty,ts)) if len(set(ty))==2 else None,
            'measurement_scope':'held-out profiles within this generated source; small groups diagnostic only'}
    if office_train is not None and office_test is not None and len(office_train)>1 and len(office_test)>1:
        ctr_train=train & np.array([r.get('label_state')=='matched_control' for r in metadata])
        ctr_test=test & np.array([r.get('label_state')=='matched_control' for r in metadata])
        if office_reference_day is not None:
            ctr_train &= np.array([r.get('office_capture_day')==office_reference_day for r in metadata])
            ctr_test &= np.array([r.get('office_capture_day')!=office_reference_day for r in metadata])
        if ctr_train.sum()>1 and ctr_test.sum()>1:
            ot=np.asarray(office_train,dtype=float);oh=np.asarray(office_test,dtype=float)
            ot[~np.isfinite(ot)]=np.nan;oh[~np.isfinite(oh)]=np.nan
            origin_train=np.concatenate([ot,x[ctr_train]])
            origin_cols=np.flatnonzero(np.isfinite(origin_train).any(axis=0))
            empty=[n for i,n in enumerate(names) if i not in origin_cols]
            if len(origin_cols):
                origin=HistGradientBoostingClassifier(max_iter=100,max_leaf_nodes=15,min_samples_leaf=10,class_weight='balanced',random_state=seed,early_stopping=False)
                origin.fit(origin_train[:,origin_cols],np.concatenate([np.zeros(len(ot)),np.ones(ctr_train.sum())]))
                score=origin.predict_proba(np.concatenate([oh,x[ctr_test]])[:,origin_cols])[:,1]
                report['origin_test']={'roc_auc':float(roc_auc_score(np.concatenate([np.zeros(len(oh)),np.ones(ctr_test.sum())]),score)),
                    'office_rows':len(oh),'control_rows':int(ctr_test.sum()),'scope':'office capture-day and generated profile holdouts',
                    'feature_order':[names[i] for i in origin_cols],'empty_train_features':empty,
                    'fit_policy':'all declared train rows; no internal early-stopping split',
                    'target_meaning':'capture origin only; office rows are not labelled benign'}
            else:
                report['origin_test']={'status':'no_finite_training_features','empty_train_features':empty}
    # Cluster selection/preprocessing uses train alone; labels are only post-hoc.
    useful=[i for i in range(x.shape[1]) if np.isfinite(x[train,i]).any() and np.nanstd(x[train,i])>0]
    if useful:
        projector=make_pipeline(SimpleImputer(strategy='median'),StandardScaler(),
            PCA(n_components=min(10,len(useful),int(train.sum())-1),random_state=seed))
        z_train=projector.fit_transform(x[train][:,useful]);z=projector.transform(x[:,useful])
        k=min(8,max(2,len(z_train)//20));cl=KMeans(n_clusters=k,n_init=20,random_state=seed).fit(z_train)
        assignments=cl.predict(z);have=len(set(assignments[test]))
        report['clustering']={'k':k,'fitted_on':'train only','test_arm_ARI':float(adjusted_rand_score(y[test],assignments[test])),
            'test_technique_NMI':float(normalized_mutual_info_score(np.array([r['technique'] for r in metadata])[test],assignments[test])),
            'test_silhouette':float(silhouette_score(z[test],assignments[test])) if 1<have<test.sum() else None}
        joblib.dump({'projector':projector,'clusterer':cl,'feature_indices':useful},out/'clusters.joblib')
        import pyarrow as pa,pyarrow.parquet as pq
        pq.write_table(pa.Table.from_pylist([{'row_index':i,'cluster':int(a),'split':splits[i],
            'pc1':float(z[i,0]),'pc2':float(z[i,1]) if z.shape[1]>1 else 0.} for i,a in enumerate(assignments)]),out/'clusters.parquet')
    dump(out/'metrics.json',report)
    return report


def fit_mixed_clusters(data,metadata,splits,office,office_days,names,out,seed=20261004):
    """Cluster an unlabelled office reference and generated train without y."""
    import numpy as np
    import joblib
    import pyarrow as pa,pyarrow.parquet as pq
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    from sklearn.cluster import KMeans
    from sklearn.pipeline import make_pipeline
    from sklearn.metrics import normalized_mutual_info_score
    validate_training_contract(names)
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    days=sorted(set(office_days)-{'unknown'})
    if len(days)<2:
        report={'status':'insufficient_office_days','office_target':None}
        dump(out/'metrics.json',report);return report
    a=np.asarray(data,dtype=float);o=np.asarray(office,dtype=float)
    if a.shape!=(len(metadata),len(names)) or len(splits)!=len(metadata) or o.shape!=(len(office_days),len(names)):
        raise ValueError('mixed clustering rows/features do not align')
    x=np.concatenate([a,o]);x[~np.isfinite(x)]=np.nan
    sp=np.array(list(splits)+['unassigned' if day=='unknown' else 'train' if day==days[0] else 'test' for day in office_days])
    origin=np.array(['generated']*len(a)+['office']*len(o))
    role=np.array([r['label_state'] for r in metadata]+['unlabelled_office']*len(o))
    train=sp=='train';test=sp=='test'
    useful=[i for i in range(x.shape[1]) if np.isfinite(x[train,i]).any() and np.nanstd(x[train,i])>0]
    if not useful:
        report={'status':'insufficient_variable_features','office_target':None}
        dump(out/'metrics.json',report);return report
    projector=make_pipeline(SimpleImputer(strategy='median'),StandardScaler(),
        PCA(n_components=min(10,len(useful),int(train.sum())-1),random_state=seed))
    z_train=projector.fit_transform(x[train][:,useful]);z=projector.transform(x[:,useful])
    k=min(8,max(2,len(z_train)//20));clusterer=KMeans(n_clusters=k,n_init=20,random_state=seed).fit(z_train)
    assignments=clusterer.predict(z)
    report={'status':'research_mixed_clustering','fitted_on':'generated train + unlabelled office reference day',
        'reference_office_day':days[0],'holdout_office_days':days[1:],'fit_rows':int(train.sum()),'test_rows':int(test.sum()),
        'k':k,'office_target':None,'production_training_ready':False,
        'test_origin_NMI':float(normalized_mutual_info_score(origin[test],assignments[test])),
        'meaning':'cluster origins and role composition are post-hoc diagnostics, not malicious labels','clusters':[]}
    for cluster in range(k):
        ix=assignments==cluster
        row={'cluster':cluster,'rows':int(ix.sum())}
        for r in ('unlabelled_office','matched_control','observed_positive','hard_negative'):
            row[r]=int((ix & (role==r)).sum());row['test_'+r]=int((ix & test & (role==r)).sum())
        report['clusters'].append(row)
    joblib.dump({'projector':projector,'clusterer':clusterer,'feature_order':names,'feature_indices':useful,
        'scope':'research_only_office_reference_and_generated_train'},out/'clusters.joblib')
    pq.write_table(pa.Table.from_pylist([{'dataset':'generated' if i<len(a) else 'office_sample',
        'row_index':i if i<len(a) else i-len(a),'cluster':int(c),'split':str(sp[i]),
        'pc1':float(z[i,0]),'pc2':float(z[i,1]) if z.shape[1]>1 else 0.} for i,c in enumerate(assignments)]),
        out/'clusters.parquet',compression='zstd')
    dump(out/'metrics.json',report)
    return report


def export_and_fit(run,out,seed=20261004,max_office=10000,frozen_labels=None):
    import numpy as np
    import pyarrow as pa,pyarrow.parquet as pq
    run=Path(run);out=Path(out)
    if out.exists():raise FileExistsError('research output retained; choose new directory')
    identity=source_identity(run)
    validated=json.loads((run/'validated.json').read_text())
    if validated.get('status')!='validated_local':raise ValueError('validated composition required')
    registry={c['campaign_id']:c for c in json.loads((run/'positive_registry.json').read_text())}
    gt={}
    for p in sorted(run.glob('batches/*/parquet/segment_gt.parquet')):
        for row in pq.ParquetFile(p).read().to_pylist():
            uid=row['global_segment_uid']; c=registry[row['campaign_id']]
            if row['arm']!=c['arm'] or row['positive_packet_count']<=0:raise ValueError('unverified membership')
            if uid in gt:raise ValueError('mixed/duplicate segment membership')
            gt[uid]=row
    if sum(r['positive_packet_count'] for r in gt.values())!=validated['positive_packets']:raise ValueError('GT packets disagree')
    names=list(SESSION_FEATURES);data=[];meta=[];office=[];office_days=[];seen=0;seen_uids=set();rng=random.Random(seed)
    from .training_contract import label_for_memberships
    for p in sorted(run.glob('batches/*/parquet/office_sessions.parquet')):
        reader=pq.ParquetFile(p)
        extra=['segment_start_ts'] if 'segment_start_ts' in reader.schema_arrow.names else []
        for b in reader.iter_batches(batch_size=2048,columns=['global_session_uid','global_segment_uid',*extra,*names]):
            for r in b.to_pylist():
                uid=r['global_segment_uid']
                if uid in seen_uids:raise ValueError('duplicate segment across feature tables')
                seen_uids.add(uid)
                f={n:r[n] for n in names}
                if uid not in gt:
                    seen+=1
                    stamp=r.get('segment_start_ts')
                    day=stamp.replace(tzinfo=timezone.utc).astimezone(ZoneInfo('Europe/Moscow')).date().isoformat() if stamp else 'unknown'
                    if len(office)<max_office:office.append(f);office_days.append(day)
                    else:
                        index=rng.randrange(seen)
                        if index<max_office:office[index]=f;office_days[index]=day
                    continue
                member=gt[uid];c=registry[member['campaign_id']]
                if r['global_session_uid']!=member['global_session_uid']:raise ValueError('session/GT identity mismatch')
                label,state=label_for_memberships([member])
                data.append(f)
                meta.append({'row_index':len(meta),'global_segment_uid':uid,'global_session_uid':r['global_session_uid'],
                    'label_binary':label,'label_state':state,'arm':c['arm'],'technique':c['technique'],
                    'campaign_id':c['campaign_id'],'parent_campaign_id':c['parent_campaign_id'],
                    'profile_id':c.get('profile_id'),
                    'timing_fidelity':c.get('timing_fidelity','unknown'),
                    'source_fidelity':c.get('source_fidelity','unknown'),
                    'cadence_verified':bool(c.get('cadence_evidence',{}).get('verified',False)),
                    'office_capture_day':r['segment_start_ts'].replace(tzinfo=timezone.utc).astimezone(ZoneInfo('Europe/Moscow')).date().isoformat() if r.get('segment_start_ts') else 'unknown',
                    'group_id':c['technique']+'|'+str(c.get('profile_id') or c['parent_campaign_id']),
                    'source_capture_day':c.get('template_moscow_date'),'training_scope':'research_only'})
    if not set(gt)<=seen_uids:raise ValueError('GT rows absent from X')
    frozen_identity=None
    if frozen_labels is not None:
        frozen_labels=Path(frozen_labels)
        frozen_identity={'path':str(frozen_labels),'sha256':sha256(frozen_labels)}
        frozen=pq.ParquetFile(frozen_labels).read(columns=['group_id','split']).to_pylist()
        splits=extend_group_split(meta,frozen,seed)
    else:splits=group_split(meta,seed)
    for r,s in zip(meta,splits):r['split']=s
    # The office origin diagnostic is sampled independently of labels. It is
    # not used to invent benign training targets.
    dated=sorted(set(office_days))
    reference_day=dated[0] if dated else None
    train_control=[d for d,r,s in zip(data,meta,splits) if s=='train' and r['label_state']=='matched_control' and r['office_capture_day']==reference_day]
    train_scenario=[d for d,r,s in zip(data,meta,splits) if s=='train' and r['label_state']=='observed_positive' and r['office_capture_day']==reference_day]
    office_reference=[r for r,day in zip(office,office_days) if day==dated[0]] if dated else []
    office_holdout=[r for r,day in zip(office,office_days) if day!=dated[0]] if len(dated)>1 else []
    selected,diag=choose_features(train_control,train_scenario,office_reference,names)
    out.mkdir(parents=True,exist_ok=False)
    schema=pa.schema([(n,pa.float64()) for n in names])
    pq.write_table(pa.Table.from_pylist(data,schema=schema),out/'features_all.parquet',compression='zstd')
    pq.write_table(pa.Table.from_pylist(meta),out/'labels_metadata.parquet',compression='zstd')
    pq.write_table(pa.Table.from_pylist(office,schema=schema),out/'office_unlabelled_sample.parquet',compression='zstd')
    if selected:pq.write_table(pa.Table.from_pylist([{n:d[n] for n in selected} for d in data]),out/'features_selected.parquet',compression='zstd')
    pq.write_table(pa.Table.from_pylist([{'row_index':i,'office_capture_day':day,'label_binary':None} for i,day in enumerate(office_days)]),out/'office_sample_metadata.parquet',compression='zstd')
    # Baseline on all X is diagnostic; selected X has a separate frozen model.
    x=np.array([[d[n] if d[n] is not None else np.nan for n in names] for d in data],dtype=float)
    def omatrix(rows,cols):return [[r[n] if r[n] is not None else np.nan for n in cols] for r in rows]
    all_result=fit_research(x,meta,splits,names,out/'baseline_all',seed,
        office_train=omatrix(office_reference,names),office_test=omatrix(office_holdout,names),office_reference_day=reference_day)
    chosen_result=fit_research(x[:,[names.index(n) for n in selected]],meta,splits,selected,out/'baseline_selected',seed,
        office_train=omatrix(office_reference,selected),office_test=omatrix(office_holdout,selected),office_reference_day=reference_day) if selected else None
    mixed_result=fit_mixed_clusters(x,meta,splits,omatrix(office,names),office_days,names,out/'mixed_clusters_all',seed)
    mixed_selected=fit_mixed_clusters(x[:,[names.index(n) for n in selected]],meta,splits,omatrix(office,selected),office_days,selected,out/'mixed_clusters_selected',seed) if selected else None
    manifest={'version':'cover-research-training-v1','status':'research_training_exported',
        'source_identity':identity,'training_code_sha256':sha256(Path(__file__)), 'rows':len(meta),'features_all':names,'features_selected':selected,
        'source_days':sorted({r['source_capture_day'] for r in meta if r['source_capture_day']}),
        'split_policy':'entire technique/profile group, all campaigns/arms/sessions/segments together; within-source only',
        'frozen_split_source':frozen_identity,
        'split_rows':dict(Counter(splits)),'label_counts':dict(Counter(r['label_state'] for r in meta)),
        'office_population':seen,'office_sample':len(office),'office_target':None,
        'office_days':dated,'office_reference_day':dated[0] if dated else None,
        'office_holdout_rows':len(office_holdout),
        'per_technique':dict(Counter(r['technique'] for r in meta)),
        'mixed_clustering':mixed_result,'selected_mixed_clustering':mixed_selected,
        'feature_selection':diag,'all_feature_baseline':all_result,'selected_feature_baseline':chosen_result,
        'research_training_ready':True,'production_training_ready':False,
        'limits':['Generated source days are not independent office positives.',
                  'All-feature baseline may learn generator transport/client artifacts.',
                  'Selected features use exploratory marginal screening on train, not an independent office transfer test.',
                  'No technique is guaranteed separable, and cluster identity is not a malicious label.']}
    if source_identity(run)!=identity:raise ValueError('source changed during export')
    if frozen_identity and sha256(frozen_labels)!=frozen_identity['sha256']:raise ValueError('frozen split source changed during export')
    dump(out/'manifest.json',manifest)
    dump(out/'COMPLETE.json',{'source_identity':identity,'files':{str(p.relative_to(out)):sha256(p) for p in out.rglob('*') if p.is_file()}})
    return manifest


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--seed',type=int,default=20261004)
    p.add_argument('--frozen-labels',type=Path,help='preserve existing profile split assignments')
    a=p.parse_args();result=export_and_fit(a.run,a.out,a.seed,frozen_labels=a.frozen_labels)
    print(json.dumps({k:result[k] for k in ('status','rows','features_selected','label_counts','research_training_ready','production_training_ready')},indent=2))


if __name__=='__main__':main()
