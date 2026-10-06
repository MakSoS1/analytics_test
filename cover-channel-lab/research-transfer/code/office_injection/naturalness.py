"""Explore signal and capture-source effects without fitting on held-out rows.

Selection is grouped by original template; office is split by observed blocks.
Calendar, ports and provenance never enter a model's explicit session contract.
A candidate needs frozen signal and domain checks with group confidence intervals.
This is exploratory evidence, not an independent office-positive transfer test.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import math
import random
import statistics
from pathlib import Path

from .audit import auc
from .feature_contract import is_feature
from .training_contract import is_training_feature, validate_training_contract, candidate_status, source_identity, VERSION
from .templates import skeleton

csv.field_size_limit(1 << 30)


def _value(row, name):
    try:v = float(row.get(name))
    except (TypeError, ValueError):return None
    return v if math.isfinite(v) else None


def load_groups(run, max_duration=180.0, max_office=5000, seed=1701):
    """scenario/control/office rows, plus each scenario/control row's pair id.

    The pair id is the parent (skeleton) campaign id from positive_registry.json
    when a generated run recorded one (shaped.py's pair_id), else the row's own
    campaign id -- a run without pairing still loads, just without grouping.
    """
    run = Path(run); pair_of_campaign = {}; lineage = {}
    registry = run / 'positive_registry.json'
    if registry.exists():
        for r in json.loads(registry.read_text()):
            pair_of_campaign[r['campaign_id']] = r.get('parent_campaign_id', r['campaign_id'])
            lineage[r['campaign_id']] = r
    split_path=run/'source_split_manifest.json'
    manifest=json.loads(split_path.read_text()) if split_path.exists() else {}
    arm_of, pair_of, meta_of = {}, {}, {}
    for p in run.glob('batches/*/segment_gt.jsonl'):
        for line in p.read_text().splitlines():
            if not line:continue
            r = json.loads(line)
            arm_of[r['segment_uid']] = r.get('arm', 'scenario')
            pair_of[r['segment_uid']] = pair_of_campaign.get(r.get('campaign_id'), r.get('campaign_id'))
            meta_of[r['segment_uid']] = lineage.get(r.get('campaign_id'), {})
    rng = random.Random(seed); office, seen = [], 0
    groups = {'scenario': [], 'control': [], 'hard_negative': []}; pairs = {'scenario': [], 'control': []}
    import gzip
    paths=list(run.glob('batches/*/office_sessions.csv'))+list(run.glob('batches/*/office_sessions.csv.gz'))
    for p in sorted(paths):
        stream=gzip.open(p,'rt') if p.suffix=='.gz' else p.open()
        with stream as f:
            for row in csv.DictReader(f):
                arm = arm_of.get(row['segment_uid'])
                if arm:
                    meta = meta_of[row['segment_uid']]
                    row['_ancestor_group'] = meta.get('ancestor_group_id') or meta.get('template_id') or pair_of[row['segment_uid']]
                    row['_template_date'] = meta.get('template_moscow_date')
                    row['_campaign_id'] = meta.get('campaign_id')
                    row['_technique'] = meta.get('technique')
                    if manifest.get('status') == 'planned':
                        row['_source_split'] = manifest['campaign_splits'][meta['campaign_id']]
                        row['_ancestor_group'] = manifest['campaign_components'][meta['campaign_id']]
                    elif row['_template_date']:
                        row['_ancestor_group'] = 'source-day:' + row['_template_date']
                    if meta.get('dataset_role')=='hard_negative':groups['hard_negative'].append(row);continue
                    groups[arm].append(row); pairs[arm].append(pair_of.get(row['segment_uid'], row['segment_uid']))
                    continue
                if skeleton(row, max_duration=max_duration)[0] is None:continue
                # Disjoint observed blocks, not independent individual office rows.
                from datetime import datetime
                from zoneinfo import ZoneInfo
                day=datetime.fromtimestamp(float(row['session_start_epoch']),ZoneInfo('Europe/Moscow')).date().isoformat()
                row['_office_group'] = 'office-day:' + day
                if manifest.get('status') == 'planned':
                    row['_source_split'] = manifest.get('office_day_splits',{}).get(day,'test')
                    row['_office_group'] = manifest.get('office_day_components',{}).get(day,'unused:'+day)
                seen += 1
                if len(office) < max_office:office.append(row)
                elif (k := rng.randrange(seen)) < max_office:office[k] = row
    groups['office'] = office
    return groups, pairs, seen


def paired_rows(groups, pairs):
    """(scenario_row, control_row, pair_id) for every pair with both arms present."""
    by_pair = {}
    for arm in ('scenario', 'control'):
        for row, pid in zip(groups[arm], pairs[arm]):
            if arm in by_pair.get(pid, {}):
                raise ValueError('duplicate arm or multi-segment pair; session aggregation required')
            by_pair.setdefault(pid, {})[arm] = row
    return [(v['scenario'], v['control'], pid) for pid, v in by_pair.items() if 'scenario' in v and 'control' in v]


def split_pairs(paired, seed=1701):
    """Deterministic half split by pair id, independent of file/row order."""
    if paired and all('_source_split' in s and '_source_split' in c for s,c,p in paired):
        if any(s['_source_split'] != c['_source_split'] for s,c,p in paired):raise ValueError('pair crosses declared split')
        return ({p for s,c,p in paired if s['_source_split']=='train'},
                {p for s,c,p in paired if s['_source_split']=='validation'})
    ids = sorted({pid for *_, pid in paired})
    ancestor = {pid: s.get('_ancestor_group', pid) for s, c, pid in paired}
    selection = {pid for pid in ids if _selection(ancestor[pid], seed)}
    return selection, set(ids) - selection


def _selection(group, seed):
    return int(hashlib.sha256(f'{seed}:{group}'.encode()).hexdigest(), 16) % 2 == 0


def _matrix(rows, names):
    return [[(_value(r, n) if _value(r, n) is not None else math.nan) for n in names] for r in rows]


_SMALL_N_CUTOFF = 20  # see _fit_predict's docstring


def _fit_predict(X_train, y_train, X_test, seed):
    """One fold's out-of-fold scores, model chosen by the training fold's size.

    HistGradientBoostingClassifier's default min_samples_leaf is 20, so it cannot make even
    one split below ~40 training rows -- every leaf stays the root, predict_proba is constant,
    and the resulting AUC is exactly 0.5 regardless of how separable the classes actually are.
    Measured on this module's own per-family output (2026-09-30): every one of 10 families
    reported B=0.5 at 9-20 confirmation rows per class, including M-HTTP-443, whose covert value
    sits in a plaintext HTTP body and IS separable -- a held-out, model-free permutation test on
    the same rows found p_bonferroni=0.002 on `pay_entropy_up`. That is a model artefact, not
    evidence of "no signal", and it made every technique's gate fail for the wrong reason.
    Below `_SMALL_N_CUTOFF` rows per class this uses regularized logistic regression instead,
    which needs only a handful of rows per feature to fit; large runs (hundreds of pairs) are
    unaffected and keep the gradient-boosted model.
    """
    import numpy as np
    if min((y_train == 0).sum(), (y_train == 1).sum()) < _SMALL_N_CUTOFF:
        from sklearn.impute import SimpleImputer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
        model = make_pipeline(SimpleImputer(strategy='median'), StandardScaler(),
                              LogisticRegression(max_iter=2000, class_weight='balanced', random_state=seed))
    else:
        from sklearn.ensemble import HistGradientBoostingClassifier
        model = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.05, class_weight='balanced',
                                               random_state=seed)
    model.fit(X_train, y_train)
    return model.predict_proba(X_test)[:, 1]


def cv_auc(a_rows, b_rows, names, folds=5, seed=1701, group_ids=None):
    """Out-of-fold AUC of a classifier chosen by sample size (see _fit_predict); 0.5 means
    inseparable.

    group_ids, when given (aligned with a_rows + b_rows), keeps a pair's two
    sessions on the same side of every fold via GroupKFold -- required
    whenever a_rows/b_rows are scenario/control, since a fold that splits a
    pair would let the model see one arm's exact skeleton twin at test time.
    """
    try:
        import numpy as np
        from sklearn.model_selection import GroupKFold, StratifiedKFold
    except ImportError as exc:
        return {'auc': None, 'error': f'scikit-learn unavailable: {exc}'}
    names = [n for n in names if any(_value(r, n) is not None for r in a_rows + b_rows)]
    if not names:return {'auc': None, 'error': 'no usable features', 'features': []}
    X = np.array(_matrix(a_rows, names) + _matrix(b_rows, names), dtype=float)
    y = np.array([0] * len(a_rows) + [1] * len(b_rows))
    if min(len(a_rows), len(b_rows)) < folds:return {'auc': None, 'error': 'too few rows', 'features': names}
    if group_ids is not None:
        g = np.array(list(group_ids))
        if len(g) != len(y):raise ValueError('group_ids must align with a_rows + b_rows')
        n_groups = len(set(g))
        if n_groups < 2:return {'auc': None, 'error': 'too few groups for grouped CV', 'features': names}
        splitter = GroupKFold(n_splits=min(folds, n_groups)).split(X, y, g)
    else:
        splitter = StratifiedKFold(folds, shuffle=True, random_state=seed).split(X, y)
    scores = np.full(len(y), np.nan)
    for train, test in splitter:
        if len(set(y[train])) < 2:continue
        scores[test] = _fit_predict(X[train], y[train], X[test], seed)
    have = ~np.isnan(scores)
    if have.sum() < len(y):scores = scores[have]; y = y[have]
    if len(set(y)) < 2 or not len(y):return {'auc': None, 'error': 'no held-out predictions', 'features': names}
    value = auc([s for s, t in zip(scores, y) if t == 0], [s for s, t in zip(scores, y) if t == 1])
    single = []
    for j, n in enumerate(names):
        col = np.array(_matrix(a_rows, [n]) + _matrix(b_rows, [n])).ravel()
        a = [x for x, t in zip(col, [0] * len(a_rows) + [1] * len(b_rows)) if t == 0 and not math.isnan(x)]
        b = [x for x, t in zip(col, [0] * len(a_rows) + [1] * len(b_rows)) if t == 1 and not math.isnan(x)]
        if a and b:
            u = auc(a, b); single.append({'feature': n, 'auc': round(max(u, 1 - u), 4),
                                          'a_p50': statistics.median(a), 'b_p50': statistics.median(b)})
    single.sort(key=lambda x: -x['auc'])
    return {'auc': round(value, 4), 'features': names, 'n_a': len(a_rows), 'n_b': len(b_rows), 'top_single': single[:12]}


def per_feature(groups):
    """office-vs-control separability and missingness -- data-quality gate."""
    names = sorted({n for r in groups['office'][:1] for n in r if is_training_feature(n)})
    office, control = groups['office'], groups['control']
    rows = []
    for n in names:
        a = [v for r in office if (v := _value(r, n)) is not None]
        b = [v for r in control if (v := _value(r, n)) is not None]
        office_missing = 1 - len(a) / len(office) if office else 1.0
        control_missing = 1 - len(b) / len(control) if control else 1.0
        varies = len(set(a) | set(b)) > 1
        origin = None
        if a and b and varies:
            u = auc(a, b); origin = round(max(u, 1 - u), 4)
        rows.append({'feature': n, 'origin_auc': origin, 'office_missing': round(office_missing, 4),
                     'control_missing': round(control_missing, 4), 'varies': varies,
                     'office_p50': round(statistics.median(a), 4) if a else None,
                     'control_p50': round(statistics.median(b), 4) if b else None})
    return rows


def admit(rows, admit_auc, max_missing_gap):
    """Data-quality gate only: comparable and measurable. Says nothing about
    whether a feature carries the technique -- see feature_effects for that."""
    admitted, rejected = [], []
    for r in rows:
        gap = abs(r['office_missing'] - r['control_missing'])
        if not r['varies']:reason = 'constant_or_empty'
        elif r['origin_auc'] is None:reason = 'not_measurable'
        elif gap > max_missing_gap:reason = f'missingness_gap_{gap:.2f}'
        elif r['origin_auc'] > admit_auc:reason = f'origin_auc_{r["origin_auc"]}'
        else:reason = None
        (admitted if reason is None else rejected).append({**r, 'reject_reason': reason})
    return admitted, rejected


def feature_effects(groups, pairs, domain_comparable, pair_ids_subset=None, technique_threshold=0.60):
    """D_j (domain effect) and T_j (technique effect) for each comparable feature.

    domain_comparable restricts to features that already passed admit() (data
    quality). T_j is measured on the paired rows in pair_ids_subset only (the
    selection half, normally) -- classification must not see the rows the
    final check will run on. domain_auc here is recomputed on that same
    restricted control set for consistency with T_j's sample.
    """
    paired = paired_rows(groups, pairs)
    if pair_ids_subset is not None:paired = [p for p in paired if p[2] in pair_ids_subset]
    scenario_sub = [s for s, c, pid in paired]; control_sub = [c for s, c, pid in paired]
    office = groups['office']
    rows = []
    for n in sorted(domain_comparable):
        a = [v for r in office if (v := _value(r, n)) is not None]
        b = [v for r in control_sub if (v := _value(r, n)) is not None]
        c = [v for r in scenario_sub if (v := _value(r, n)) is not None]
        domain_auc = round(max(u := auc(a, b), 1 - u), 4) if a and b else None
        technique_auc = round(max(u := auc(b, c), 1 - u), 4) if b and c else None
        deltas = [sv - cv for s, ctrl, _ in paired
                  if (sv := _value(s, n)) is not None and (cv := _value(ctrl, n)) is not None]
        if technique_auc is not None and technique_auc >= technique_threshold and domain_auc is not None and domain_auc < technique_threshold:
            cls = 'technique_marker'
        elif technique_auc is not None and technique_auc >= technique_threshold:
            cls = 'confounded_with_domain'
        elif domain_auc is not None and domain_auc >= technique_threshold:
            cls = 'domain_shortcut'
        else:
            cls = 'uninformative'
        rows.append({'feature': n, 'domain_auc': domain_auc, 'technique_auc': technique_auc,
                     'technique_delta_p50': round(statistics.median(deltas), 6) if deltas else None,
                     'n_pairs': len(deltas), 'classification': cls})
    rows.sort(key=lambda r: -(r['technique_auc'] or 0))
    return rows


def diagnose_joint_leak(groups, keep, threshold, min_keep, seed=1701):
    """Diagnostic only, never called by report(): which feature the office-vs-
    control classifier leans on most, dropped one at a time. Useful to see
    where a jointly-leaking set's leak is concentrated; NOT a gate, because
    pushing this until AUC hits `threshold` can simply delete all signal."""
    try:
        import numpy as np
        from sklearn.ensemble import HistGradientBoostingClassifier
        from sklearn.inspection import permutation_importance
        from sklearn.model_selection import train_test_split
    except ImportError as exc:
        return keep, [{'error': f'scikit-learn unavailable: {exc}'}], cv_auc(groups['office'], groups['control'], keep)
    keep = list(keep); trace = []
    residual = cv_auc(groups['office'], groups['control'], keep) if keep else {'auc': None}
    office, control = groups['office'], groups['control']
    while keep and residual.get('auc') is not None and residual['auc'] > threshold and len(keep) > min_keep:
        X = np.array(_matrix(office, keep) + _matrix(control, keep), dtype=float)
        y = np.array([0] * len(office) + [1] * len(control))
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.4, stratify=y, random_state=seed)
        model = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.05, class_weight='balanced',
                                               random_state=seed).fit(Xtr, ytr)
        imp = permutation_importance(model, Xte, yte, scoring='roc_auc', n_repeats=5, random_state=seed).importances_mean
        drop = keep[int(np.argmax(imp))]
        trace.append({'dropped': drop, 'residual_auc_before': residual['auc'], 'remaining': len(keep) - 1})
        keep.remove(drop)
        residual = cv_auc(office, control, keep) if keep else {'auc': None, 'error': 'nothing left'}
    return keep, trace, residual


def only_technique(groups, pairs, technique):
    """Scenario/control rows of ONE technique out of a merged multi-family run.

    catalog_tools.merge prefixes every pair id with its technique (`M-DOH__<skeleton>`),
    so the filter needs no extra file. The office group is shared and left as is.
    """
    prefix = technique + '__'
    g, p = {'office': groups['office']}, {}
    for arm in ('scenario', 'control'):
        keep = [i for i, pid in enumerate(pairs[arm]) if groups[arm][i].get('_technique') == technique or str(pid).startswith(prefix)]
        g[arm] = [groups[arm][i] for i in keep]; p[arm] = [pairs[arm][i] for i in keep]
    return g, p


def paired_effects(groups, pairs, alpha=0.05, permutations=20000, seed=1701):
    """Does the covert value move ANY feature, judged pair by pair on all pairs at once?

    The gradient-boosted B in report() cannot fit on the ~10 pairs per half a single
    family has (HistGradientBoosting needs >= 2 x min_samples_leaf=20 rows to split,
    so it returns constant scores and B is exactly 0.5 -- an artefact of size, not
    evidence of no signal). This test needs no model: for each feature the paired
    difference scenario - control is tested with a sign-flip permutation test
    (all derivatives of one source/day component swap arms together under 'the covert value does
    nothing'), then Bonferroni-corrected over the features tried. A feature whose two
    arms are byte-for-byte equal in every pair (length-preserving control) is listed
    as `identical`, not tested. There is no selection half: a single pass over a
    fixed feature list, corrected for that list.
    """
    import numpy as np
    paired = paired_rows(groups, pairs)
    names = sorted({n for s_, c_, _ in paired[:1] for n in s_ if is_training_feature(n)})
    rng = np.random.default_rng(seed)
    rows, identical = [], []
    for n in names:
        d = []; cluster_sums = {}
        for s_, c_, _pid in paired:
            a, b = _value(s_, n), _value(c_, n)
            if a is not None and b is not None:
                d.append(a-b)
                cluster=s_.get('_ancestor_group',_pid)
                cluster_sums[cluster]=cluster_sums.get(cluster,0)+(a-b)
        if len(d) < 5:continue
        d = np.array(d)
        if not np.any(d):identical.append(n);continue
        units = np.array(list(cluster_sums.values()))
        if len(units)<=12:
            import itertools
            signs=np.array(list(itertools.product((-1.,1.),repeat=len(units))))
            null=np.abs(signs @ units / len(d))
            p_val=float((null>=abs(d.mean())-1e-12).mean())
        else:
            signs=rng.choice((-1.,1.),size=(permutations,len(units)))
            null=np.abs(signs @ units / len(d))
            p_val=(1+int((null>=abs(d.mean())-1e-12).sum()))/(permutations+1)
        nonzero = d[d != 0]
        # A real, usable effect should point the same way in most pairs, not just average out
        # non-zero across many pairs split near evenly. A significant mean CAN come from a near
        # coin-flip split (found 2026-09-30: M-HTTPS-BEACON's iat_p90 passed p_bonferroni=0.047
        # at 76 pairs, but split 12/20 and 30/56 on two independent skeleton draws -- barely
        # above chance in each) -- reported here rather than silently folded into the p-value.
        same_sign = float((np.sign(nonzero) == np.sign(d.mean())).mean()) if len(nonzero) else None
        rows.append({'feature': n, 'n_pairs': len(d), 'independent_groups':len(units), 'mean_diff': float(d.mean()), 'median_diff': float(np.median(d)),
                     'share_nonzero': round(float((d != 0).mean()), 3),
                     'share_same_sign_as_mean': round(same_sign, 3) if same_sign is not None else None, 'p': p_val})
    m = len(rows)
    for r in rows:r['p_bonferroni'] = min(1.0, r['p'] * m)
    rows.sort(key=lambda r: r['p'])
    return {'pairs': len(paired), 'features_tested': m, 'features_identical_in_every_pair': identical,
            'feature_tests':rows,
            'alpha': alpha, 'significant_after_bonferroni': [r for r in rows if r['p_bonferroni'] < alpha],
            'top': rows[:10]}


def heldout_auc(a_train, b_train, a_test, b_test, names, seed=1701,
                a_groups=None, b_groups=None, bootstrap=400):
    """Fit once on selection; score untouched confirmation with cluster CI."""
    try:
        import numpy as np
    except ImportError:
        return {'auc': None, 'error': 'numpy unavailable'}
    if not names or min(map(len, (a_train, b_train, a_test, b_test))) < 2:
        return {'auc': None, 'error': 'insufficient held-out data'}
    if any(not any(_value(r, n) is not None for r in a_train + b_train) for n in names):
        return {'auc': None, 'error': 'feature unavailable on selection'}
    try:
        y = np.array([0] * len(a_train) + [1] * len(b_train))
        scores = _fit_predict(np.array(_matrix(a_train + b_train, names)), y,
                              np.array(_matrix(a_test + b_test, names)), seed)
    except (ImportError, ValueError) as exc:
        return {'auc': None, 'error': type(exc).__name__ + ': ' + str(exc)}
    if not np.isfinite(scores).all():return {'auc': None, 'error': 'non-finite scores'}
    a = scores[:len(a_test)]; b = scores[len(a_test):]
    value = auc(a.tolist(), b.tolist())
    ga = list(a_groups) if a_groups is not None else list(range(len(a)))
    gb = list(b_groups) if b_groups is not None else list(range(len(b)))
    if len(ga) != len(a) or len(gb) != len(b):raise ValueError('bootstrap groups must align')
    # Resample connected components together, including partial overlap
    # between generated ancestors and office capture-day groups.
    ua, ub = sorted(set(ga)), sorted(set(gb)); rng = np.random.default_rng(seed)
    intervals = []
    for _ in range(bootstrap):
        union = sorted(set(ua) | set(ub))
        da = db = rng.choice(union, len(union), replace=True)
        aa = [a[i] for g in da for i, k in enumerate(ga) if k == g]
        bb = [b[i] for g in db for i, k in enumerate(gb) if k == g]
        if aa and bb:intervals.append(auc(aa, bb))
    ci = [float(x) for x in np.quantile(intervals, [0.025, 0.975])] if intervals else None
    return {'auc': round(value, 4), 'ci95': ci, 'features': list(names),
            'n_a': len(a), 'n_b': len(b), 'groups_a': len(ua), 'groups_b': len(ub),
            'evaluation': 'frozen_selection_model', 'bootstrap': 'ancestor_or_office_block'}


def correct_family(reports, alpha=0.05):
    """Bonferroni over the predeclared technique x nonconstant-feature family."""
    m = sum(r['features_tested'] for r in reports)
    for r in reports:
        r['family_hypotheses'] = m
        tested = r.get('feature_tests',r.get('top', []))
        for x in tested:x['p_family'] = min(1.0, x['p'] * m)
        r['significant_family'] = [x for x in tested if x['p_family'] < alpha]
    return reports


def run_integrity(run):
    run=Path(run)
    if not (run/'validated.json').exists() or not (run/'schedule.json').exists():return 'not_measured'
    if json.loads((run/'validated.json').read_text()).get('status') != 'validated_local':return 'failed'
    paired={}
    for r in json.loads((run/'schedule.json').read_text()):
        if not r.get('generated'):return 'not_measured'
        pid=r.get('parent_campaign_id')
        if not pid:return 'failed'
        paired.setdefault(pid,[]).append(r)
    for members in paired.values():
        # Repeated pairs have multiple occurrences; compare each paired context
        # rather than collapsing by parent source id.
        arms={a:[r for r in members if r.get('arm')==a] for a in ('scenario','control')}
        if len(arms['scenario']) != len(arms['control']) or sum(map(len,arms.values())) != len(members):return 'failed'
        def contexts(rows):return sorted((r['placed_start'],r['office_batch'],r['office_interval_start'],r['load_stratum']) for r in rows)
        if contexts(arms['scenario']) != contexts(arms['control']):return 'failed'
    return 'passed' if paired else 'not_measured'


def report(run, technique_threshold=0.60, domain_threshold=0.75, admit_auc=0.60, max_missing_gap=0.10,
           min_controls=30, min_admitted=1, max_duration=180.0, seed=1701, technique=None, loaded=None):
    """Exploratory signal/domain check with no fitting on confirmation rows.

    It is not an office transfer test: independent real-office positives and
    day/endpoint holdouts remain required even for an exploratory candidate.
    """
    fixture = loaded is not None and not (Path(run)/'validated.json').exists()
    groups, pairs, office_total = loaded or load_groups(run, max_duration, seed=seed)
    if technique:groups, pairs = only_technique(groups, pairs, technique)
    paired = paired_rows(groups, pairs)
    selection_ids, confirmation_ids = split_pairs(paired, seed)
    select = [(s, c, pid) for s, c, pid in paired if pid in selection_ids]
    confirm = [(s, c, pid) for s, c, pid in paired if pid in confirmation_ids]
    def ancestors(rows):return [str(s.get('_ancestor_group', pid)) for s, c, pid in rows]
    office_select, office_confirm = [], []
    for i, r in enumerate(groups['office']):
        # Fixtures may supply a block; real rows carry their 10-minute block.
        key = r.get('_office_group', 'fixture-' + str(i))
        if '_source_split' in r:
            if r['_source_split']=='train':office_select.append(r)
            elif r['_source_split']=='validation':office_confirm.append(r)
        else:(office_select if _selection(key, seed) else office_confirm).append(r)
    train = {'office': office_select, 'scenario': [s for s, c, p in select],
             'control': [c for s, c, p in select]}
    quality, quality_rejected = admit(per_feature(train), admit_auc, max_missing_gap)
    domain_comparable = {r['feature'] for r in quality}
    insufficient = min(len(set(ancestors(select))), len(set(ancestors(confirm)))) < min_controls
    insufficient |= min(len(office_select), len(office_confirm)) < 2
    effects = feature_effects(train, {'scenario': [p for s, c, p in select],
                                     'control': [p for s, c, p in select]},
                             domain_comparable, technique_threshold=technique_threshold) if not insufficient else []
    markers = sorted(r['feature'] for r in effects if r['classification'] == 'technique_marker')
    ctrl = [c for s, c, p in confirm]; scen = [s for s, c, p in confirm]
    cg = ancestors(confirm)
    og = [str(r.get('_office_group', i)) for i, r in enumerate(office_confirm)]
    default = {'auc': None, 'error': 'insufficient independent groups or no selected markers'}
    B, D = dict(default), dict(default)
    if not insufficient and len(markers) >= min_admitted:
        B = heldout_auc(train['control'], train['scenario'], ctrl, scen, markers, seed, cg, cg)
        D = heldout_auc(train['office'], train['control'], office_confirm, ctrl, markers, seed, og, cg)
    # Naturalness diagnostic uses the full pinned numeric representation,
    # including columns rejected from training. It cannot authorize export.
    all_names = sorted(n for n in groups['office'][0] if is_feature(n)
                       and any(_value(r, n) is not None for r in train['office'] + train['control'])) if groups['office'] else []
    C = heldout_auc(train['office'], train['control'] + train['scenario'],
                   office_confirm, ctrl + scen, all_names, seed, og, cg + cg) if not insufficient else dict(default)
    b, d = B.get('auc'), D.get('auc')
    if insufficient:decision = 'insufficient_data'
    elif b is None or not markers:decision = 'no_signal_in_current_features'
    elif d is None:decision = 'domain_not_measured'
    elif max(d, 1-d) >= domain_threshold:decision = 'signal_with_domain_shortcut'
    elif b <= technique_threshold:decision = 'no_signal_in_current_features'
    else:decision = 'clean_candidate'
    # CI, not just a noisy point estimate, must support both assertions.
    bci, dci = B.get('ci95'), D.get('ci95')
    tstatus = 'passed' if bci and bci[0] > technique_threshold else 'not_passed'
    dstatus = 'passed' if dci and max(dci[1], 1-dci[0]) < domain_threshold else 'not_measured' if d is None else 'not_passed'
    split_path=Path(run)/'source_split_manifest.json'
    manifest=json.loads(split_path.read_text()) if split_path.exists() else {}
    split_applied=bool(paired) and manifest.get('status')=='planned' and all(
        '_source_split' in s and '_source_split' in c for s,c,p in paired)
    out = {'evaluation_version': VERSION, 'counts': {k: len(v) for k,v in groups.items()} | {
              'pairs_total': len(paired), 'pairs_selection': len(select), 'pairs_confirmation': len(confirm),
              'ancestors_selection': len(set(ancestors(select))), 'ancestors_confirmation': len(set(cg))},
           'office_population_total': office_total,
           'thresholds': {'technique_threshold': technique_threshold, 'domain_threshold': domain_threshold,
                          'admit_auc': admit_auc, 'max_missing_gap': max_missing_gap,
                          'min_controls': min_controls, 'min_admitted': min_admitted},
           'domain_comparable_features': sorted(domain_comparable), 'quality_rejected_features': quality_rejected,
           'feature_effects_selection_half': effects, 'technique_marker_features': markers,
           'admitted_features': markers,
           'training_contract': validate_training_contract(markers) if markers else None,
           'confirmation': {'B_scenario_vs_control_on_technique_markers': B,
                            'joint_domain_auc_on_technique_markers': D},
           'C_generated_vs_office_all_admissible_features': C,
           'C_feature_scope': 'all_pinned_numeric_diagnostic_only',
           'decision': decision, 'integrity_status': 'passed' if fixture else run_integrity(run),
           'source_identity':None if fixture else source_identity(run),
           'source_split_status':json.loads((Path(run)/'source_split_manifest.json').read_text()).get('status')
                                 if (Path(run)/'source_split_manifest.json').exists() else 'not_planned',
           'source_split_applied':split_applied, 'source_split_sha256':manifest.get('sha256'),
           'evaluated_campaign_ids':sorted({r['_campaign_id'] for a in ('scenario','control') for r in groups[a] if r.get('_campaign_id')}),
           'technique_status': tstatus, 'domain_status': dstatus,
           'production_training_ready': False,
           'transfer_status': 'independent_office_positive_holdout_required',
           'split_policy': 'declared connected day components when available; otherwise exploratory day holdout; test unused',
           'meaning': 'No detected signal is limited to this experiment, representation and sample size.'}
    out['gate'] = 'passed' if candidate_status(out) == 'passed' else 'failed'
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--run', required=True, type=Path)
    p.add_argument('--technique-threshold', type=float, default=0.60, help='min held-out scenario-vs-control AUC (B)')
    p.add_argument('--domain-threshold', type=float, default=0.75, help='max joint office-vs-control AUC on exported set')
    p.add_argument('--admit-auc', type=float, default=0.60, help='per-feature data-quality gate (see admit())')
    p.add_argument('--max-missing-gap', type=float, default=0.10)
    p.add_argument('--min-controls', type=int, default=30)
    p.add_argument('--seed', type=int, default=1701)
    p.add_argument('--paired-tests', action='store_true', help='per family, model-free paired test on all pairs '
                   '(paired_<technique>.json); use this when a family has too few pairs for the classifier')
    p.add_argument('--technique', help="judge one family of a merged run, or 'each' for every family "
                   "(naturalness_<technique>.json each, plus naturalness.json for all pooled)")
    p.add_argument('--out-dir', type=Path, help='new report directory; default RUN/evaluation-v2')
    a = p.parse_args()
    output = a.out_dir or a.run / 'evaluation-v2'
    output.mkdir(parents=True, exist_ok=True)
    def save(name, value):
        # Never overwrite historical reports or a partially completed revision.
        with (output / name).open('x') as f:f.write(json.dumps(value, indent=2, default=str) + '\n')
    loaded = load_groups(a.run, seed=a.seed)
    if a.paired_tests:
        reports=[]
        for t in sorted({str(pid).split('__')[0] for pid in loaded[1]['scenario']}):
            g, pr = only_technique(loaded[0], loaded[1], t)
            r = paired_effects(g, pr, seed=a.seed); r['technique'] = t;reports.append(r)
        for r in correct_family(reports):
            save('paired_' + r['technique'] + '.json', r)
            print(json.dumps({'technique':r['technique'],'pairs':r['pairs'],'tested':r['features_tested'],
                              'significant_family':[x['feature'] for x in r['significant_family']]}))
        return
    def evaluate(technique):
        return report(a.run, a.technique_threshold, a.domain_threshold, a.admit_auc, a.max_missing_gap,
                      a.min_controls, seed=a.seed, technique=technique, loaded=loaded)
    if a.technique == 'each':
        for t in sorted({str(pid).split('__')[0] for pid in loaded[1]['scenario']}):
            r=evaluate(t);r['technique']=t;save('naturalness_' + t + '.json', r)
            print(json.dumps({'technique':t,'pairs':r['counts']['pairs_total'],'decision':r['decision'],
                              'gate':r['gate'],'markers':r['technique_marker_features']}))
    r = evaluate(None if a.technique == 'each' else a.technique)
    save('naturalness_' + a.technique + '.json' if a.technique and a.technique!='each' else 'naturalness.json',r)
    brief = {k:r[k] for k in ('counts','decision','gate')}
    brief['technique_markers']=r['technique_marker_features']
    brief['B']=r['confirmation']['B_scenario_vs_control_on_technique_markers'].get('auc')
    brief['joint_domain_auc']=r['confirmation']['joint_domain_auc_on_technique_markers'].get('auc')
    brief['C']=r['C_generated_vs_office_all_admissible_features'].get('auc')
    print(json.dumps(brief,indent=2))


if __name__ == '__main__':main()
