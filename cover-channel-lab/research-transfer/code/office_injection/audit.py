"""Measured feature shifts; no claim that replay acquires an office TCP stack."""
import csv
csv.field_size_limit(1<<26)
import json
import math
import random
import statistics
from collections import defaultdict
from pathlib import Path
from .feature_contract import is_feature


def numeric(name,value):
    if not is_feature(name):return None
    try:n=float(value)
    except (ValueError,TypeError):return None
    return n if math.isfinite(n) else None


def auc(a,b):
    # Probability that a positive-origin observation ranks above background.
    ordered=sorted([(x,0) for x in a]+[(x,1) for x in b]);neg=0;wins=0;i=0
    while i<len(ordered):
        j=i
        while j<len(ordered) and ordered[j][0]==ordered[i][0]:j+=1
        ns=sum(y==0 for _,y in ordered[i:j]);ps=j-i-ns
        wins+=ps*(neg+ns/2);neg+=ns;i=j
    return wins/(len(a)*len(b)) if a and b else None


def domain_report(session_csvs,gt_jsonls,profile,schedule,max_background=4000):
    positive=set();controls=set()
    for path in gt_jsonls:
        for x in Path(path).read_text().splitlines():
            if not x:continue
            r=json.loads(x)
            (controls if r.get('arm')=='control' else positive).add(r['segment_uid'])
    rng=random.Random(1701);background=[];positives=[];seen=0
    for path in session_csvs:
        import gzip
        path=Path(path)
        stream=gzip.open(path,'rt') if path.suffix=='.gz' else path.open()
        with stream as f:
            for row in csv.DictReader(f):
                if row['segment_uid'] in positive:positives.append(row)
                elif row['segment_uid'] in controls:continue  # matched controls: see naturalness.py
                else:
                    seen+=1
                    if len(background)<max_background:background.append(row)
                    else:
                        i=rng.randrange(seen)
                        if i<max_background:background[i]=row
    scores=[]
    for name in background[0] if background else []:
        a=[n for r in background if (n:=numeric(name,r.get(name))) is not None]
        b=[n for r in positives if (n:=numeric(name,r.get(name))) is not None]
        if not a or not b:continue
        rank=auc(a,b)
        scores.append({'feature':name,'background_p50':statistics.median(a),'positive_p50':statistics.median(b),
                       'origin_auc':max(rank,1-rank),'background_n':len(a),'positive_n':len(b)})
    scores.sort(key=lambda x:x['origin_auc'],reverse=True)
    hours=sorted({x['moscow_hour'] for x in profile})
    return {'background_segments':seen,'positive_segments':len(positives),'control_segments':len(controls),
            'actual_segment_prevalence':len(positives)/(seen+len(positives)) if seen+len(positives) else 0,
            'moscow_hours_observed':hours,'moscow_hours_injected':sorted({x['moscow_hour'] for x in schedule}),
            'full_day_coverage':len(hours)==24,'not_observed_hours':sorted(set(range(24))-set(hours)),
            'origin_shortcuts':scores[:20],'origin_acceptance':'NOT_ESTABLISHED',
            'comparison_design':'CI-positive versus unlabelled office; class and capture source are confounded',
            'causal_artifact_claim_supported':False,
            'matched_benign_source_controls_available':False,
            'reason':'univariate origin ranks are confounded with class; matched benign controls and independent office-wire positives required',
            'tcp_stack_adapted':False,'production_training_ready':False,
            'source_role':'challenge_only','cross_session_office_context':'dedicated replay pseudonyms; no logical office-host mapping',
            'feature_names':[x['feature'] for x in scores]}
