"""Explain frozen clusters; optional rounded PCA points contain no raw office features."""
import argparse
from collections import Counter
import json
from pathlib import Path
from office_injection.source import sha256
from office_injection.cover_registry import digest
from office_injection.training_contract import source_identity
from office_injection.full_review import verify_seal


def sealed_mechanics(root, allow_union=False):
    request=json.loads((root/'combined_sessions_v1/request.json').read_text())
    registry=None;catalog=None;pins=[];union_entries={};union_campaigns={};registry_pins=[]
    for composition in request['compositions']:
        sealed=Path(composition['path'])/'sealed';bundle=json.loads((sealed/'bundle.json').read_text())
        if bundle['sha256']!=composition['bundle_sha256']:raise ValueError('composition bundle differs from training request')
        verify_seal(sealed,bundle)
        current=json.loads((sealed/'cover_registry.json').read_text())
        cs=json.loads((sealed/'full_campaign_registry.json').read_text())
        if digest({k:v for k,v in current.items() if k!='sha256'})!=current['sha256']:raise ValueError('sealed registry hash mismatch')
        if allow_union:
            for entry in current['entries']:
                key=entry['entry_id']
                if key in union_entries and union_entries[key]!=entry:raise ValueError('conflicting sealed entry in augmentation')
                union_entries[key]=entry
            for campaign in cs:
                key=campaign['campaign_id']
                if key in union_campaigns and union_campaigns[key]!=campaign:raise ValueError('conflicting sealed campaign in augmentation')
                union_campaigns[key]=campaign
            registry_pins.append(current['sha256']);pins.append(bundle['sha256']);continue
        if registry is not None and current!=registry:raise ValueError('sealed mechanics registries differ')
        key=lambda c:(c['technique'],c['profile_id'],c['arm'],c['timing_fidelity'],c['source_fidelity'])
        if catalog is not None and sorted(map(key,cs))!=sorted(map(key,catalog)):raise ValueError('sealed campaign mechanics differ')
        registry=current;catalog=cs;pins.append(bundle['sha256'])
    if allow_union and union_entries:
        body={'version':'sealed-mechanics-union-v1','source_registry_sha256':registry_pins,
              'entries':sorted(union_entries.values(),key=lambda e:e['entry_id'])}
        registry={**body,'sha256':digest(body)};catalog=list(union_campaigns.values())
    if registry is None:raise ValueError('no sealed composition')
    return registry,catalog,pins


def describe_clusters(x,rows,meta,names):
    import numpy as np
    x=np.asarray(x,float)
    if x.shape!=(len(rows),len(names)):raise ValueError('cluster and feature rows differ')
    train=np.array([r['split']=='train' for r in rows]);test=np.array([r['split']=='test' for r in rows])
    if not train.any() or not test.any():raise ValueError('train and test required')
    x=x.copy();x[~np.isfinite(x)]=np.nan
    finite=np.isfinite(x[train]).any(axis=0);indices=np.flatnonzero(finite)
    mean=np.nanmean(x[train][:,indices],axis=0);scale=np.nanstd(x[train][:,indices],axis=0)
    active=scale>0;indices=indices[active];mean=mean[active];scale=scale[active]
    def role(r):return meta[r['row_index']]['label_state'] if r['dataset']=='generated' else 'unlabelled_office'
    clusters=[]
    for cluster in sorted({r['cluster'] for r in rows}):
        mask=np.array([r['cluster']==cluster for r in rows]);tr=mask&train;te=mask&test
        ranked=[]
        for j,i in enumerate(indices):
            values=x[tr,i];values=values[np.isfinite(values)]
            if not len(values):continue
            effect=(values.mean()-mean[j])/scale[j]
            ranked.append({'feature':names[i],'standardized_mean_difference':float(effect),
                'cluster_median':float(np.median(values)),
                'reference_median':float(np.nanmedian(x[train,i])),
                'cluster_missing_share':float(1-len(values)/max(1,tr.sum()))})
        ranked.sort(key=lambda r:abs(r['standardized_mean_difference']),reverse=True)
        techniques=Counter(meta[r['row_index']]['technique'] for r,keep in zip(rows,tr) if keep and r['dataset']=='generated')
        clusters.append({'cluster':int(cluster),'rows':int(mask.sum()),'train_rows':int(tr.sum()),'test_rows':int(te.sum()),
            'train_roles':dict(Counter(role(r) for r,keep in zip(rows,tr) if keep)),
            'test_roles':dict(Counter(role(r) for r,keep in zip(rows,te) if keep)),
            'top_techniques_train':techniques.most_common(8),'top_features':ranked[:5],
            'interpretation_scope':'train-only descriptive association; not causal or malicious labels'})
    # A binned holdout view contains no per-session points. The zoom limits are
    # fit on train, so an outlying held-out day cannot change the framing.
    coords=np.array([[r['pc1'],r['pc2']] for r in rows]);bounds=[]
    for axis in (0,1):
        lo,hi=np.quantile(coords[train,axis],[.005,.995]);pad=max((hi-lo)*.04,.01)
        bounds.append([float(lo-pad),float(hi+pad)])
    inside=test.copy()
    for i,(lo,hi) in enumerate(bounds):inside &= (coords[:,i]>=lo)&(coords[:,i]<=hi)
    edges=[np.linspace(lo,hi,51) for lo,hi in bounds];grids={}
    for name in ('generated','office_sample'):
        mask=inside & np.array([r['dataset']==name for r in rows])
        grids[name]=np.histogram2d(coords[mask,0],coords[mask,1],bins=edges)[0].astype(int).tolist()
    return {'clusters':clusters,'density':{'bounds':bounds,'grids':grids,'included_rows':int(inside.sum()),
        'outside_zoom_rows':int((test&~inside).sum()),'split':'test','bounds_fitted_on':'train 0.5–99.5 percentiles'}}


def projection_payload(z,rows,meta):
    import numpy as np
    z=np.asarray(z,float)
    if len(z)!=len(rows) or z.ndim!=2 or z.shape[1]<3 or not np.isfinite(z[:,:3]).all():
        raise ValueError('finite aligned 3D projection required')
    train=np.array([r['split']=='train' for r in rows]);points=[]
    if not train.any():raise ValueError('projection framing requires train')
    for position,r in enumerate(rows):
        origin='office' if r['dataset']=='office_sample' else 'generated'
        role='unlabelled_office' if origin=='office' else meta[r['row_index']]['label_state']
        points.append([*np.round(z[position,:3],4).tolist(),int(r['cluster']),origin,r['split'],role])
    zoom=[]
    for i in range(3):
        lo,hi=np.quantile(z[train,i],[.005,.995]);pad=max((hi-lo)*.04,.01);zoom.append([float(lo-pad),float(hi+pad)])
    visible=np.ones(len(z),bool)
    for i,(lo,hi) in enumerate(zoom):visible&=(z[:,i]>=lo)&(z[:,i]<=hi)
    return {'columns':['pc1','pc2','pc3','cluster','origin','split','role'],'points':points,
        'zoom_ranges':zoom,'zoom_visible_rows':int(visible.sum()),'zoom_outside_rows':int((~visible).sum()),
        'sample_policy':'all exported generated segments + entire 10000-row office reservoir; no additional subsampling',
        'precision':4,'raw_office_features_exported':False}


def explain(root,out,training_name='research_training_v2',points_out=None,allow_mechanics_union=False):
    import numpy as np
    import joblib
    import pyarrow.parquet as pq
    root=Path(root).resolve();out=Path(out)
    if out.exists():raise FileExistsError('explanation retained; choose a new output')
    if points_out is not None and Path(points_out).exists():raise FileExistsError('projection retained; choose a new output')
    t=root/training_name;complete=json.loads((t/'COMPLETE.json').read_text())
    for relative,pin in complete['files'].items():
        if sha256(t/relative)!=pin:raise ValueError('changed training artifact: '+relative)
    manifest=json.loads((t/'manifest.json').read_text())
    if manifest['source_identity']!=complete['source_identity'] or source_identity(root/'combined_sessions_v1')!=complete['source_identity']:
        raise ValueError('training source identity changed')
    names=manifest['features_all'];data=pq.read_table(t/'features_all.parquet').to_pandas()[names].to_numpy()
    office=pq.read_table(t/'office_unlabelled_sample.parquet').to_pandas()[names].to_numpy()
    meta=pq.read_table(t/'labels_metadata.parquet').to_pylist();om=pq.read_table(t/'office_sample_metadata.parquet').to_pylist()
    rows=pq.read_table(t/'mixed_clusters_all/clusters.parquet').to_pylist()
    expected=[(d,i) for d,n in [('generated',len(data)),('office_sample',len(office))] for i in range(n)]
    if [(r['dataset'],r['row_index']) for r in rows]!=expected:raise ValueError('cluster row identity/order changed')
    if [r['row_index'] for r in meta]!=list(range(len(data))) or [r['row_index'] for r in om]!=list(range(len(office))):
        raise ValueError('metadata order changed')
    if any(r['split']!=m['split'] for r,m in zip(rows,meta)):raise ValueError('generated split changed')
    reference=manifest['office_reference_day']
    osp=['unassigned' if m['office_capture_day']=='unknown' else 'train' if m['office_capture_day']==reference else 'test' for m in om]
    if [r['split'] for r in rows[len(meta):]]!=osp or any(m['label_binary'] is not None for m in om):raise ValueError('office split/target changed')
    x=np.concatenate([data,office]);result=describe_clusters(x,rows,meta,names)
    model=joblib.load(t/'mixed_clusters_all/clusters.joblib');projector=model['projector'];use=model['feature_indices']
    transform_x=x[:,use].copy();transform_x[~np.isfinite(transform_x)]=np.nan
    z=projector.transform(transform_x);pred=model['clusterer'].predict(z)
    if not np.array_equal(pred,[r['cluster'] for r in rows]) or not np.allclose(z[:,:2],[[r['pc1'],r['pc2']] for r in rows]):
        raise ValueError('frozen model does not reproduce cluster assignments')
    pca=projector.named_steps['pca']
    result['pca']={'explained_variance_ratio':pca.explained_variance_ratio_.tolist(),
        'cluster_centers_2d':model['clusterer'].cluster_centers_[:,:2].tolist(),
        'top_loadings':[sorted([{'feature':names[use[j]],'loading':float(v)} for j,v in enumerate(c)],key=lambda r:abs(r['loading']),reverse=True)[:8] for c in pca.components_[:2]]}
    registry,catalog,bundle_pins=sealed_mechanics(root,allow_mechanics_union);body={k:v for k,v in registry.items() if k!='sha256'}
    if digest(body)!=registry['sha256']:raise ValueError('registry hash mismatch')
    accepted={(c['technique'],c['profile_id'],c['arm']) for c in catalog}
    declared={(e['entry_id'],p['profile_id'],arm) for e in registry['entries'] for p in e['profiles'] for arm in ('scenario','control')}
    if accepted!=declared or len(catalog)!=len(declared):raise ValueError('mechanics coverage mismatch')
    mechanics=[]
    for e in registry['entries']:
        cs=[c for c in catalog if c['technique']==e['entry_id']]
        mechanics.append({k:e.get(k) for k in ('entry_id','namespace','family','carrier','transport','description','dataset_role','source_fidelity')} |
            {'profiles':[p['profile_id'] for p in e['profiles']],'accepted_arms':len(cs),
             'observed_implementations':[dict(zip(('transport','carrier','covert_field','source_kind'),values)) for values in sorted({
                 tuple(str(c.get('mechanic',{}).get(k,'')) for k in ('transport','carrier','covert_field','source_kind')) for c in cs})],
             'timing_fidelity':dict(Counter(c['timing_fidelity'] for c in cs)),
             'labelled_rows':manifest['per_technique'].get(e['entry_id'],0)})
    result.update(version='cover-cluster-explanation-v1',training_complete_sha256=sha256(t/'COMPLETE.json'),
        source_identity=complete['source_identity'],registry_sha256=registry['sha256'],
        sealed_bundle_sha256=bundle_pins,mechanics=mechanics,
        method='frozen StandardScaler + PCA(up to10 dimensions) + KMeans(k8); 2D is a partial view; explanations use train only',
        production_ready=False)
    if source_identity(root/'combined_sessions_v1')!=complete['source_identity']:raise ValueError('source changed during explanation')
    out.write_text(json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False)+'\n')
    if points_out is not None:
        projection=projection_payload(z,rows,meta)
        projection['framework_details']=[{'point_position':position,'technique':meta[r['row_index']]['technique'],
            'role':meta[r['row_index']]['label_state'],'profile':meta[r['row_index']]['profile_id']}
            for position,r in enumerate(rows) if r['dataset']=='generated' and meta[r['row_index']]['technique'].startswith('ADAPTIX_')]
        projection['ordinary_details']=[{'point_position':position,'technique':meta[r['row_index']]['technique'],
            'role':meta[r['row_index']]['label_state'],'profile':meta[r['row_index']]['profile_id']}
            for position,r in enumerate(rows) if r['dataset']=='generated' and meta[r['row_index']]['technique'].startswith(('BENIGN_WEB_','BENIGN_PUBLIC_','BENIGN_BROWSE_'))]
        projection.update(version='cover-cluster-projection3d-v1',source_identity=complete['source_identity'],
            training_complete_sha256=result['training_complete_sha256'],sealed_bundle_sha256=bundle_pins,
            explained_variance_ratio=pca.explained_variance_ratio_.tolist(),
            cluster_centers_3d=model['clusterer'].cluster_centers_[:,:3].tolist(),
            input_features=len(names),used_features=len(use),clustering_dimensions=int(z.shape[1]),
            fit_rows=int(sum(r['split']=='train' for r in rows)),production_ready=False)
        Path(points_out).write_text(json.dumps(projection,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--points-out',type=Path)
    p.add_argument('--union-mechanics',action='store_true',help='explicit augmentation: union compatible sealed registries')
    a=p.parse_args();r=explain(a.root,a.out,points_out=a.points_out,allow_mechanics_union=a.union_mechanics);print(json.dumps({'clusters':len(r['clusters']),'mechanics':len(r['mechanics']),'production_ready':False}))
