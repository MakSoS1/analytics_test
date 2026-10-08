"""Synthetic positive rows for TRAIN ONLY: real office row + measured technique delta.

x_synthetic = x_office + T_j(feature)   for every feature classified 'technique_marker'
            = x_office                  for every other feature (domain effect not applied)

T_j is the per-pair median delta (scenario - control) from naturalness.py's
feature_effects on the CONFIRMATION half only -- the half the gate itself
used to certify the effect is real, not the half that chose the features.
Using the selection half here would launder the same leakage the gate exists
to catch.

This does not invent what an attack looks like: only features whose paired
measurement showed the covert value moves them are edited, and only by the
median amount actually measured. RTT, TLS fingerprint fields, TTL-derived
context and everything classified domain_shortcut or uninformative are left
exactly as the real office row had them -- a synthetic row's environment is a
real office session's environment, unedited.

Boundary this module enforces, not just documents: rows built here carry
`synthetic=True` and `office_injection.dataset.export` must never see them.
There is no eval/validation code path in this file, and none should be added;
validation stays real office + independently-sourced positives. See
naturalness.py's docstring and the office-injection review of 2026-09-28 for
why (a model validated on its own generator's assumptions proves nothing).
"""
from __future__ import annotations
import argparse
import csv
import json
import random
from pathlib import Path

from .naturalness import load_groups, paired_rows, split_pairs, feature_effects, per_feature
from .naturalness import _value  # noqa: F401  (re-exported for callers that need the same parsing)
from .naturalness import admit as _admit

csv.field_size_limit(1 << 30)


def technique_deltas(run, admit_auc=0.60, max_missing_gap=0.10, technique_threshold=0.60, seed=1701):
    """{feature: median paired delta} for technique_marker features, measured
    on the CONFIRMATION half (mirrors naturalness.report's split so a train
    set built here is consistent with whatever naturalness.json already
    certified for the same run -- run naturalness first)."""
    groups, pairs, _ = load_groups(run, seed=seed)
    paired = paired_rows(groups, pairs)
    selection_ids, confirmation_ids = split_pairs(paired, seed)
    quality, _ = _admit(per_feature(groups), admit_auc, max_missing_gap)
    domain_comparable = {r['feature'] for r in quality}
    effects = feature_effects(groups, pairs, domain_comparable, confirmation_ids, technique_threshold)
    return {r['feature']: r['technique_delta_p50'] for r in effects
            if r['classification'] == 'technique_marker' and r['technique_delta_p50'] is not None}


def synthesize(office_rows, deltas, rng):
    """One synthetic positive per office row: office_rows + measured deltas.

    Every output row keeps every office column untouched except the
    technique_marker features, which are shifted by the paired median delta.
    No feature is sampled or invented; office_rows should be real, unlabelled
    background rows the run itself observed (not from an office window used
    to certify the gate, if that matters to the caller -- this function does
    not enforce that; naturalness.report's own held-out split is the
    certification, this is downstream production of train rows only).
    """
    del rng  # no randomness: the delta is a fixed, measured shift, not a draw
    out = []
    for row in office_rows:
        r = dict(row)
        for name, delta in deltas.items():
            try:v = float(r.get(name))
            except (TypeError, ValueError):continue
            r[name] = v + delta
        r['synthetic'] = True; r['synthetic_deltas_applied'] = sorted(deltas)
        out.append(r)
    return out


def check_gate_allows_synthesis(gate):
    if gate.get('decision') == 'no_signal_in_current_features':
        raise ValueError('naturalness.py found no technique signal in current features for this run; '
                         'synthesizing rows from a measured delta of ~0 would fabricate a detector, not train one')


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--run', required=True, type=Path, help='a mixed run naturalness.py has already scored')
    p.add_argument('--office-csv', required=True, type=Path, help='real office rows to synthesize positives from')
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--limit', type=int, default=0)
    p.add_argument('--seed', type=int, default=1701)
    a = p.parse_args()
    gate = json.loads((a.run / 'naturalness.json').read_text()) if (a.run / 'naturalness.json').exists() else {}
    check_gate_allows_synthesis(gate)
    deltas = technique_deltas(a.run, seed=a.seed)
    if not deltas:
        raise ValueError('no technique_marker features on the confirmation half; nothing to apply')
    with a.office_csv.open() as f:rows = list(csv.DictReader(f))
    if a.limit:rows = rows[:a.limit]
    synthetic = synthesize(rows, deltas, random.Random(a.seed))
    a.out.parent.mkdir(parents=True, exist_ok=True)
    with a.out.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(synthetic[0])); w.writeheader(); w.writerows(synthetic)
    print(json.dumps({'deltas_applied': deltas, 'rows_in': len(rows), 'rows_out': len(synthetic),
                      'warning': 'TRAIN ONLY -- see counterfactual.py docstring; never use these rows for eval'}, indent=2))


if __name__ == '__main__':main()
