"""Split connected day/template ancestors before placing any derivatives."""
import hashlib
import json


def build_split_manifest(campaigns, office_days=()):
    rows = list(campaigns); parents = {}
    def find(x):
        parents.setdefault(x, x)
        if parents[x] != x:parents[x] = find(parents[x])
        return parents[x]
    def join(a,b):parents[find(a)] = find(b)
    ids = [r['campaign_id'] for r in rows]
    if len(ids) != len(set(ids)):raise ValueError('duplicate campaign in split manifest')
    tokens = {}
    for r in rows:
        ancestor = r.get('ancestor_group_id') or r.get('template_id') or r.get('parent_campaign_id')
        day = r.get('template_moscow_date')
        if not ancestor or not day:
            return {'status': 'missing_source_lineage', 'campaign_splits': {}, 'component_count': 0}
        own = ['template:' + ancestor, 'capture_day:' + day]
        if r.get('office_moscow_date'):own.append('capture_day:' + r['office_moscow_date'])
        for token in own[1:]:join(own[0],token)
        tokens[r['campaign_id']] = own[0]
    comps = {}
    for r in rows:comps.setdefault(find(tokens[r['campaign_id']]), []).append(r)
    ordered = sorted(comps, key=lambda k: min(r['template_moscow_date'] for r in comps[k]))
    if len(ordered) < 3:
        body = {'status':'insufficient_independent_blocks','component_count':len(ordered),
                'campaign_splits':{r['campaign_id']:'challenge_only' for r in rows}}
    else:
        train_end = max(1, min(len(ordered)-2, int(len(ordered)*0.6)))
        val_end = max(train_end+1, min(len(ordered)-1, int(len(ordered)*0.8)))
        assignments = {k:'train' if i<train_end else 'validation' if i<val_end else 'test'
                       for i,k in enumerate(ordered)}
        body = {'status':'planned','component_count':len(ordered),
                'campaign_splits':{r['campaign_id']:assignments[find(tokens[r['campaign_id']])] for r in rows}}
    body['office_day_splits'] = {r['office_moscow_date']: body['campaign_splits'][r['campaign_id']]
                                for r in rows if r.get('office_moscow_date')}
    body['campaign_components'] = {r['campaign_id']: find(tokens[r['campaign_id']]) for r in rows}
    body['office_day_components'] = {r['office_moscow_date']: find(tokens[r['campaign_id']])
                                   for r in rows if r.get('office_moscow_date')}
    body['policy'] = 'connected template/source-day/office-day components, chronological 60/20/20'
    return {**body,'sha256':hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest()}
