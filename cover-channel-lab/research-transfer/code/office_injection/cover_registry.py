"""Pinned, side-effect-free discovery and evidence-based coverage accounting."""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path

VERSION = 'cover-registry-v1'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _profiles(tree, families):
    # Compile only the small pure catalog function, never import coverlab (its
    # __init__ mutates dispatch and opens runtime dependencies).
    names = {'HTTP_CLIENTS', 'HTTPS_DIRECT', 'HTTPS_FRONTS', 'WSS_DIRECT', 'WSS_FRONT'}
    constants = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in names:
                constants[node.targets[0].id] = ast.literal_eval(node.value)
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'implementation_catalog')
    allowed_calls = {'tuple', 'len', 'enumerate'}
    for node in ast.walk(function):
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal, ast.Lambda, ast.With, ast.Try)):
            raise ValueError('impure implementation catalog')
        if isinstance(node, ast.Attribute) and not (node.attr == 'append' and isinstance(node.value, ast.Name) and node.value.id == 'items' or node.attr == 'lower' and isinstance(node.value, ast.Name) and node.value.id == 'family'):
            raise ValueError('unsafe catalog attribute')
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id not in allowed_calls:
            raise ValueError('unsafe catalog call')
    env = {'__builtins__': {'tuple': tuple, 'len': len, 'enumerate': enumerate}, **constants}
    exec(compile(ast.Module(body=[function], type_ignores=[]), '<pure implementation catalog>', 'exec'), env)
    return {f: [{'profile_id': p[0], 'client': p[1], 'server': p[2], 'topology': p[3]} for p in env['implementation_catalog'](f)] for f in families}


def discover_registry(source_root: Path, source_commit: str) -> dict:
    source_root = Path(source_root)
    lock_path=source_root.parent/'source_lock.json'
    lock=json.loads(lock_path.read_text()) if lock_path.exists() else {}
    if lock and lock.get('main_commit')!=source_commit:raise ValueError('source commit differs from lock')
    expected={s['path']:s['sha256'] for s in lock.get('sources',[])}
    entries = []; sources = []
    for relative in ('main/src/coverlab/scenarios.py', 'main/src/coverlab/scenarios_extra.py', 'stage_m/src/coverlab/stage_m.py'):
        path = source_root / relative
        raw = path.read_bytes(); tree = ast.parse(raw)
        sha = hashlib.sha256(raw).hexdigest()
        if expected and expected.get(relative)!=sha:raise ValueError('source bytes differ from lock: '+relative)
        sources.append({'path': relative, 'sha256': sha})
        if relative.endswith('stage_m.py'):
            node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'FAMILY_COUNTS' for t in n.targets))
            families = ast.literal_eval(node.value); profiles = _profiles(tree, families)
            for family in families:
                entries.append({'entry_id': family, 'namespace': 'stage_m', 'family': family,
                                'carrier': 'implementation_specific', 'profiles': profiles[family],
                                'dataset_role': 'scenario_and_matched_control', 'source_fidelity': 'bounded_shape_generator',
                                'source_path': relative, 'source_sha256': sha})
        else:
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != '_s': continue
                args = [ast.literal_eval(a) for a in node.args]
                sid, family, transport, carrier, _, intent, _, description = args[:8]
                role = 'hard_negative' if family in ('lots', 'privacy') else 'scenario_and_matched_control'
                fidelity = 'semantic_fixture' if 'fixture' in description.lower() or family == 'privacy' else 'bounded_protocol_generator'
                entries.append({'entry_id': sid, 'namespace': 'catalog', 'family': family, 'carrier': carrier,
                                'transport': transport, 'intent': intent, 'description': description,
                                'dataset_role': role, 'source_fidelity': fidelity,
                                'profiles': [{'profile_id': 'original_dispatch', 'client': 'upstream_dispatch', 'server': 'upstream_fixture', 'topology': 'isolated'}],
                                'source_path': relative, 'source_sha256': sha})
    ids = [e['entry_id'] for e in entries]
    if not ids or len(ids) != len(set(ids)): raise ValueError('empty or duplicate source entries')
    body = {'version': VERSION, 'main_commit': source_commit, 'stage_m_commit':lock.get('stage_m_commit'),
            'sources': sources, 'entries': sorted(entries, key=lambda e: e['entry_id'])}
    return {**body, 'sha256': digest(body)}


def validate_coverage(registry: dict, results: list[dict], requested_keys=None) -> dict:
    expected = {(e['entry_id'], p['profile_id'], arm) for e in registry['entries'] for p in e['profiles'] for arm in ('scenario', 'control')}
    parent_expected=len(expected)
    if requested_keys is not None:
        selected=set(map(tuple,requested_keys))
        if not selected or not selected<=expected or len(selected)!=len(requested_keys):raise ValueError('requested scope outside pinned registry or duplicated')
        expected=selected
    seen = set(); passed = set(); failures = []
    for r in results:
        key = (r['entry_id'], r['profile_id'], r['arm'])
        if key not in expected or key in seen: raise ValueError('unknown or duplicate result key: ' + repr(key))
        seen.add(key)
        evidence = r.get('wire_evidence') or {}
        valid = (r.get('status') == 'success' and r.get('registry_sha256') == registry['sha256']
                 and evidence.get('capture_sha256') and evidence.get('observed_packets', 0) > 0
                 and evidence.get('membership_verified') is True and evidence.get('dispatch_verified') is True)
        if valid: passed.add(key)
        else: failures.append({'key': key, 'reason': r.get('reason', 'missing_verified_evidence')})
    return {'registry_sha256': registry['sha256'], 'complete': passed == expected,
            'expected': len(expected),'parent_registry_expected':parent_expected,'requested_scope_sha256':digest(sorted(expected)), 'observed_success': len(passed),
            'missing': sorted(expected - seen), 'failed': failures, 'production_ready': False}


def supplemental_registry(source_root, base):
    """Bounded representatives of every orchestration configuration.

    Repetitions are volume, except Stage A where each rep changes the nuisance
    profile. Stage C keeps all 72 declared profiles and its full 60 transactions.
    The precise upstream campaign ID is required to activate import hooks.
    """
    from types import SimpleNamespace
    import copy
    root=Path(source_root);scenario_order=[]
    by_id={e['entry_id']:e for e in base['entries']}
    for name in ('scenarios.py','scenarios_extra.py'):
        tree=ast.parse((root/'main/src/coverlab'/name).read_text())
        for n in ast.walk(tree):
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='_s':
                sid=ast.literal_eval(n.args[0]);e=by_id[sid]
                scenario_order.append(SimpleNamespace(scenario_id=sid,family=e['family']))
    path=root/'main/src/coverlab/orchestrate.py';raw=path.read_bytes();tree=ast.parse(raw)
    constants={}
    for n in tree.body:
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('PERSONAS','TRANSFORMS','TIMINGS','CLIENTS','SIZES'):
            constants[n.targets[0].id]=ast.literal_eval(n.value)
    scope={};seen=set()
    def invoke(sid,suspicious,seed,cid,run_id,persona,source_ip,events,manifest,events_out,capture_file,config):
        stage=config['experiment_stage'];key=(stage,config['configuration_id'])
        if stage=='A_parser':key+=(tuple(config['transform_chain']),config['timing_profile'],config['payload_size_class'])
        if key in seen:return
        seen.add(key)
        eid='SEQUENCE_MULTI_PHASE' if stage=='C_sequence' else sid
        role=by_id[sid]['dataset_role']
        if stage=='G_commodity' or stage in ('C_sequence','F_challenge','F_future_challenge') and not suspicious:role='hard_negative'
        if role=='hard_negative' and by_id[sid]['dataset_role']!='hard_negative' and stage!='C_sequence':eid=stage+'_'+sid
        if eid not in scope:
            e=copy.deepcopy(by_id[sid]);e.update(entry_id=eid,profiles=[],source_path='main/src/coverlab/orchestrate.py',source_sha256=hashlib.sha256(raw).hexdigest())
            if stage=='C_sequence':e.update(family='sequence',carrier='multi_phase',source_fidelity='bounded_multi_phase_generator')
            else:e['dataset_role']=role
            scope[eid]=e
        profile={'profile_id':'source_'+config['configuration_id']+'_'+cid.split('-')[-2] if stage=='A_parser' else 'source_'+config['configuration_id'],
            'stage':stage,'scenario_id':sid,'source_campaign_id':cid,'events':events,'client':config['client_impl'],
            'server':'upstream_fixture','topology':'isolated','transform':config['transform_chain'][0],
            'timing_profile':config['timing_profile'],'payload_size_class':config['payload_size_class'],
            'dataset_role':role,'source_config':config}
        scope[eid]['profiles'].append(profile)
    def select(stage,shard=0,shards=1):
        values=scenario_order[:60] if stage=='parser' else [s for s in scenario_order if s.family in {'uri','header','custom_header','body','response','syntax','timing'}]
        return [s for i,s in enumerate(values) if i%shards==shard]
    names=('parser_stage','isolated_stage','sequence_stage','challenge_stage','lots_stage','future_stage')
    funcs=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    allowed={'select','list','range','len','int','enumerate','invoke'}
    for f in funcs:
        for n in ast.walk(f):
            if isinstance(n,(ast.Import,ast.ImportFrom,ast.Global,ast.Nonlocal)):raise ValueError('impure source stage')
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id not in allowed:raise ValueError('unsafe source stage call')
    env={'__builtins__':{'list':list,'range':range,'len':len,'int':int,'enumerate':enumerate},'SCENARIOS':scenario_order,'select':select,'invoke':invoke,**constants}
    exec(compile(ast.Module(body=funcs,type_ignores=[]),str(path),'exec'),env)
    args=SimpleNamespace(shard=0,shards=1,seed=20261002,capture_file='isolated')
    for name in names:env[name](args,None,None)
    body={'version':VERSION,'main_commit':base['main_commit'],'stage_m_commit':base['stage_m_commit'],
        'parent_registry_sha256':base['sha256'],'sources':base['sources']+[{'path':'main/src/coverlab/orchestrate.py','sha256':hashlib.sha256(raw).hexdigest()}],
        'scope_policy':'one pair per declared configuration; A retains all five transform repetitions; C retains full60 transactions; volume repetitions not independent profiles',
        'entries':sorted(scope.values(),key=lambda e:e['entry_id'])}
    return {**body,'sha256':digest(body)}
