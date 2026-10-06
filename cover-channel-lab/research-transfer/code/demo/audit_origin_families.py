"""Which feature families still separate generated controls from the office, by stratum.

Read-only and descriptive. Generated rows are split by profile group (the
exported train/validation/test split) and office rows by capture day, so a
profile or a day never appears on both sides. Families are declared by name
before any result is read. This is a diagnostic of the capture environment,
never a detector score, a threshold source or an office FPR.
"""
import argparse
import json
import re
from pathlib import Path

FAMILIES = (  # first match wins; order is part of the declaration
    ('tls', r'^tls_'),
    ('payload', r'^pay_'),
    ('handshake_rtt', r'^tcp_handshake_rtt_ms$'),
    ('retransmission', r'^tcp_retx_'),
    ('flags', r'^(syn|fin|rst|psh|ack|urg)_count$'),
    ('timing', r'^(iat_|flow_duration$|pkt_rate$|byte_rate$|idle_|low_rate_long$|burst_|ra_)'),
    ('direction', r'^(pkt_count|up_pkt_count|down_pkt_count|data_pkt_|direction_changes|dir_|up_down_pkt_ratio)'),
    ('size', r'^(pkt_len_|len_|up_bytes|down_bytes|total_bytes|up_down_bytes_ratio|small_|const_len_|.*_bytes_per_pkt)'),
)
STRATA = (
    ('all', lambda d: d.index == d.index),
    ('bidirectional', lambda d: (d.data_pkt_up > 0) & (d.data_pkt_down > 0)),
    ('bidirectional_sni', lambda d: (d.data_pkt_up > 0) & (d.data_pkt_down > 0) & (d.tls_sni_len > 0)),
)


def family_of(name):
    for family, pattern in FAMILIES:
        if re.search(pattern, name):
            return family
    return 'other'


def families(columns):
    out = {}
    for c in columns:
        out.setdefault(family_of(c), []).append(c)
    return out


def _auc(train_x, train_y, test_x, test_y, columns, seed=1701):
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import roc_auc_score
    if not columns or len(set(train_y)) < 2 or len(set(test_y)) < 2:
        return None
    a=train_x[columns].copy();b=test_x[columns].copy()
    a=a.replace([np.inf,-np.inf],np.nan);b=b.replace([np.inf,-np.inf],np.nan)
    # Keep all columns. Train-empty columns convey no learned information;
    # a fixed constant avoids sklearn's empty-bin bug without reading test.
    empty=a.isna().all()
    a.loc[:,empty]=0.;b.loc[:,empty]=0.
    model = HistGradientBoostingClassifier(max_iter=120, max_depth=4, random_state=seed, early_stopping=False)
    model.fit(a, train_y)
    return float(roc_auc_score(test_y, model.predict_proba(b)[:, 1]))


def volume_matched(generated, office, minimum=10):
    """Coarsened exact matching on observable activity volume only.

    Rows are binned by floor(log2) of packet count and byte count; a bin is kept
    when both populations have at least `minimum` rows in it. Origin appears only
    in that presence test, never in the bin definition, and no feature value is changed.
    """
    import numpy as np

    def bins(d):
        return list(zip(np.floor(np.log2(d.pkt_count.clip(lower=1))).astype(int),
                        np.floor(np.log2(d.total_bytes.clip(lower=1))).astype(int)))
    gb, ob = bins(generated), bins(office)
    from collections import Counter
    keep = {b for b, n in Counter(gb).items() if n >= minimum} & {b for b, n in Counter(ob).items() if n >= minimum}
    return keep, gb, ob


def audit(training_dir, test_splits=('test',),match_capture_days=False):
    import numpy as np
    import pandas as pd
    root = Path(training_dir)
    complete_path=root/'COMPLETE.json'
    if complete_path.exists():
        from office_injection.source import sha256
        complete=json.loads(complete_path.read_text())
        for name,pin in complete['files'].items():
            if sha256(root/name)!=pin:raise ValueError('training artifact changed: '+name)
    features = pd.read_parquet(root / 'features_all.parquet')
    labels = pd.read_parquet(root / 'labels_metadata.parquet')
    office = pd.read_parquet(root / 'office_unlabelled_sample.parquet')
    office_meta = pd.read_parquet(root / 'office_sample_metadata.parquet')
    columns = list(features.columns)  # retain even empty persisted feature columns
    control = labels.arm.eq('control').values & labels.label_state.eq('matched_control').values
    generated = features.loc[control, columns].reset_index(drop=True)
    gsplit = labels.loc[control, 'split'].reset_index(drop=True)
    office = office[columns].reset_index(drop=True)
    days = sorted(office_meta.office_capture_day.unique())
    oday = office_meta.office_capture_day.reset_index(drop=True)
    train_office, test_office = office[oday == days[0]], office[oday == days[-1]]
    train_generated = generated[gsplit == 'train']
    test_generated = generated[gsplit.isin(test_splits)]
    if match_capture_days:
        if 'office_capture_day' not in labels:raise ValueError('placement day required for matched-context origin audit')
        gday=labels.loc[control,'office_capture_day'].reset_index(drop=True)
        train_generated=train_generated[gday.loc[train_generated.index]==days[0]]
        test_generated=test_generated[gday.loc[test_generated.index]==days[-1]]
    groups = families(columns)
    report = {'training_dir': str(root), 'office_train_day': days[0], 'office_test_day': days[-1],
              'generated_test_splits': list(test_splits),'generated_context_days_matched':match_capture_days, 'feature_count':len(columns),'empty_train_column_policy':'constant zero in train and test; columns retained; mask learned from train only','early_stopping':False, 'families': {k: len(v) for k, v in groups.items()}, 'strata': {}}
    for name, selector in STRATA:
        tg, te = train_generated[selector(train_generated)], test_office[selector(test_office)]
        tr_g, tr_o = train_generated[selector(train_generated)], train_office[selector(train_office)]
        eg, eo = test_generated[selector(test_generated)], test_office[selector(test_office)]
        train_x = pd.concat([tr_g, tr_o]); train_y = np.r_[np.zeros(len(tr_g)), np.ones(len(tr_o))]
        test_x = pd.concat([eg, eo]); test_y = np.r_[np.zeros(len(eg)), np.ones(len(eo))]
        entry = {'rows': {'train_generated': len(tr_g), 'train_office': len(tr_o), 'test_generated': len(eg), 'test_office': len(eo)},
                 'all_features': _auc(train_x, train_y, test_x, test_y, columns), 'drop_family': {}, 'only_family': {}}
        for family, names in groups.items():
            entry['drop_family'][family] = _auc(train_x, train_y, test_x, test_y, [c for c in columns if c not in names])
            entry['only_family'][family] = _auc(train_x, train_y, test_x, test_y, names)
        report['strata'][name] = entry
    # Freeze comparable volume bins on the selected reference-day TRAIN rows.
    base = STRATA[2][1]
    pg, po = train_generated[base(train_generated)], train_office[base(train_office)]
    keep = volume_matched(pg, po)[0] if {'pkt_count', 'total_bytes'} <= set(columns) else set()
    if keep:
        def inside(d):
            gb = volume_matched(d, d, 1)[1]
            return [b in keep for b in gb]
        sel = lambda d: d.index.isin(d.index[inside(d)])
        tr_g = train_generated[base(train_generated)]; tr_g = tr_g[sel(tr_g)]
        tr_o = train_office[base(train_office)]; tr_o = tr_o[sel(tr_o)]
        eg = test_generated[base(test_generated)]; eg = eg[sel(eg)]
        eo = test_office[base(test_office)]; eo = eo[sel(eo)]
        train_x = pd.concat([tr_g, tr_o]); train_y = np.r_[np.zeros(len(tr_g)), np.ones(len(tr_o))]
        test_x = pd.concat([eg, eo]); test_y = np.r_[np.zeros(len(eg)), np.ones(len(eo))]
        entry = {'rows': {'train_generated': len(tr_g), 'train_office': len(tr_o), 'test_generated': len(eg), 'test_office': len(eo)},
                 'bins_kept': len(keep), 'bins_fitted_on':'selected reference-day train only', 'all_features': _auc(train_x, train_y, test_x, test_y, columns), 'drop_family': {}, 'only_family': {}}
        for family, names in groups.items():
            entry['drop_family'][family] = _auc(train_x, train_y, test_x, test_y, [c for c in columns if c not in names])
            entry['only_family'][family] = _auc(train_x, train_y, test_x, test_y, names)
        report['strata']['bidirectional_sni_volume_matched'] = entry
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--training-dir', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--test-splits', default='test', help='comma-separated generated splits held out')
    a = p.parse_args()
    report = audit(a.training_dir, tuple(a.test_splits.split(',')))
    with a.out.open('x') as f:
        f.write(json.dumps(report, indent=2) + '\n')
    for stratum, e in report['strata'].items():
        print(stratum, e['rows'], 'all', None if e['all_features'] is None else round(e['all_features'], 3))
        print('  drop :', {k: None if v is None else round(v, 3) for k, v in e['drop_family'].items()})
        print('  only :', {k: None if v is None else round(v, 3) for k, v in e['only_family'].items()})


if __name__ == '__main__':
    main()
