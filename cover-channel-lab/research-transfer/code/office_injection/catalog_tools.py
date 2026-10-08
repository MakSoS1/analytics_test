"""Merge the catalogs of several shaped.py runs into one, so several families
can be injected into the same office snapshot in a single branch run.

Two things a plain concatenation gets wrong, both measured rather than assumed:

* Every family samples skeletons with the same seed, so two families routinely
  pick the same template and produce the same `campaign_id` (`<template>-<arm>`).
  Ids are therefore prefixed with the technique -- otherwise the ground-truth
  table could not tell two campaigns apart.
* Each session runs in its own namespace with the same two IP addresses and a
  random ephemeral client port, so with ~100 sessions two of them share a flow
  key with real probability (birthday bound: n(n-1)/2 / ~28k ports, ~20% at
  110 sessions). pipeline.merge_rows refuses such a merge ("source attribution
  would be ambiguous") and would throw the whole run away. A colliding pair is
  dropped here, whole (never one arm: an unmatched arm would reintroduce origin
  imbalance), and reported.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from .source import read_pcap, transport


def flow_key(path):
    for _, frame in read_pcap(path):
        p = transport(frame)
        if p:return p['key']
    raise ValueError(f'no transport flow in {path}')


def merge(catalog_paths):
    campaigns, sources = [], []
    for cp in map(Path, catalog_paths):
        cat = json.loads(cp.read_text())
        sources.append({'catalog': str(cp), 'technique': cat.get('technique'), 'campaigns': len(cat['campaigns'])})
        for c in cat['campaigns']:
            p = Path(c['path'])
            if not p.is_absolute():p = cp.parent / p
            tech = c['technique']
            campaigns.append({**c, 'path': str(p.resolve()), 'source_catalog': str(cp),
                              'ancestor_group_id': c.get('ancestor_group_id', c.get('template_id', c['parent_campaign_id'])),
                              'campaign_id': f"{tech}__{c['campaign_id']}",
                              'parent_campaign_id': f"{tech}__{c['parent_campaign_id']}"})
    # The same skeleton drawn again (a second seed over the same pool) is the same pair id:
    # keep the copy from the first catalog, report the rest. Whole pairs only, never one arm.
    first_source = {}
    for c in campaigns:first_source.setdefault(c['parent_campaign_id'], c['source_catalog'])
    duplicate_pairs = sorted({c['parent_campaign_id'] for c in campaigns if c['source_catalog'] != first_source[c['parent_campaign_id']]})
    campaigns = [c for c in campaigns if c['source_catalog'] == first_source[c['parent_campaign_id']]]
    ids = [c['campaign_id'] for c in campaigns]
    if len(ids) != len(set(ids)):raise ValueError('campaign_id not unique inside one catalog')
    pairs = {}
    for c in campaigns:pairs.setdefault(c['parent_campaign_id'], []).append(c)
    for pid, members in pairs.items():
        if sorted(m['arm'] for m in members) != ['control', 'scenario']:
            raise ValueError(f'pair {pid} is not exactly one scenario + one control')
    seen, dropped, kept = {}, [], []
    for pid in sorted(pairs):
        members = pairs[pid]
        keys = [flow_key(m['path']) for m in members]
        clash = next((k for k in keys if k in seen), None)
        if clash is None and keys[0] == keys[1]:clash = keys[0]
        if clash is not None:
            dropped.append({'pair': pid, 'technique': members[0]['technique'],
                            'clashes_with': seen.get(clash, 'its own other arm')})
            continue
        for m, k in zip(members, keys):seen[k] = m['campaign_id']
        kept.extend(members)
    kept.sort(key=lambda c: c['campaign_id'])
    techniques = sorted({c['technique'] for c in kept})
    return {'campaigns': kept, 'role': 'office_skeleton_generated', 'techniques': techniques,
            'merged_from': sources, 'flow_collisions_dropped': dropped, 'duplicate_pairs_dropped': duplicate_pairs,
            'pairs_kept': len(kept) // 2}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('catalogs', nargs='+', type=Path)
    p.add_argument('--out', required=True, type=Path)
    a = p.parse_args()
    merged = merge(a.catalogs)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(merged, indent=2) + '\n')
    print(json.dumps({k: merged[k] for k in ('techniques', 'pairs_kept', 'flow_collisions_dropped', 'duplicate_pairs_dropped')}, indent=2))


if __name__ == '__main__':main()
