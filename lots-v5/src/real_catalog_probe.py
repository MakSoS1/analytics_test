from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import time
from typing import Iterable

from .catalog import CatalogEntry, load_catalog
from .real_probe import probe_https


def probe_host_for_pattern(pattern: str) -> str:
    p = pattern.strip().lower().rstrip('.')
    return p[2:] if p.startswith('*.') else p


def shard_entries(entries: Iterable[CatalogEntry], shard_index: int, shard_count: int) -> list[CatalogEntry]:
    if shard_count <= 0 or not 0 <= shard_index < shard_count:
        raise ValueError('invalid shard')
    ordered = sorted(entries, key=lambda e: e.domain_pattern)
    return [e for i, e in enumerate(ordered) if i % shard_count == shard_index]


def accepted_manifest(manifest: dict) -> dict:
    out = copy.deepcopy(manifest)
    out['actions'] = [
        a for a in (manifest.get('actions') or [])
        if a.get('accepted_attempt') and a.get('actual_outcome') == 'success'
    ]
    return out


def _stable_action_id(pattern: str, attempt: int) -> str:
    return hashlib.sha256(f'{pattern}|{attempt}'.encode()).hexdigest()[:24]


def run_catalog_probe(
    catalog_path: str | Path,
    *,
    shard_index: int = 0,
    shard_count: int = 1,
    timeout_s: float = 8.0,
    retries: int = 2,
    max_body_bytes: int = 32768,
) -> dict:
    entries = shard_entries(load_catalog(catalog_path), shard_index, shard_count)
    actions: list[dict] = []
    started = time.time()
    for entry in entries:
        host = probe_host_for_pattern(entry.domain_pattern)
        best: dict | None = None
        for attempt in range(1, retries + 1):
            result = probe_https(host, timeout_s=timeout_s, max_body_bytes=max_body_bytes)
            result['action_id'] = _stable_action_id(entry.domain_pattern, attempt)
            result['attempt'] = attempt
            result['domain_pattern'] = entry.domain_pattern
            result['probe_host'] = host
            result['wildcard_proxy'] = entry.domain_pattern.startswith('*.')
            result['provider'] = entry.provider
            result['catalog_tags'] = sorted(entry.tags)
            result['source'] = entry.source
            result['snapshot_date'] = entry.snapshot_date
            if result.get('accepted_attempt'):
                result['accepted_attempt'] = True
                best = result
                break
            best = result
            time.sleep(0.05)
        assert best is not None
        actions.append(best)

    succeeded = sum(bool(a.get('accepted_attempt')) for a in actions)
    return {
        'campaign_id': f'real-catalog-shard-{shard_index}-of-{shard_count}',
        'scenario_run_id': f'real-catalog-shard-{shard_index}-of-{shard_count}',
        'scenario_id': 'real_catalog_observation',
        'pair_id': 'real_catalog_observation',
        'label': 'reference',
        'mechanism': 'public_reference',
        'timing_profile': 'single',
        'payload_profile': 'headers_only',
        'expected_sni': '',
        'catalog_path': str(catalog_path),
        'shard_index': shard_index,
        'shard_count': shard_count,
        'capture_started_at': started,
        'capture_completed_at': time.time(),
        'actions': actions,
        'coverage': {
            'attempted': len(actions),
            'succeeded': succeeded,
            'failed': len(actions) - succeeded,
            'success_fraction': (succeeded / len(actions)) if actions else 0.0,
            'wildcard_entries': sum(bool(a.get('wildcard_proxy')) for a in actions),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description='Read-only real HTTPS observation across LOTS catalog')
    ap.add_argument('--catalog', default='catalog/lots_project_2026-08-25.csv')
    ap.add_argument('--shard-index', type=int, default=0)
    ap.add_argument('--shard-count', type=int, default=1)
    ap.add_argument('--timeout-s', type=float, default=8.0)
    ap.add_argument('--retries', type=int, default=2)
    ap.add_argument('--max-body-bytes', type=int, default=32768)
    ap.add_argument('--out', required=True)
    ap.add_argument('--accepted-out')
    args = ap.parse_args()
    manifest = run_catalog_probe(args.catalog, shard_index=args.shard_index, shard_count=args.shard_count,
                                 timeout_s=args.timeout_s, retries=args.retries, max_body_bytes=args.max_body_bytes)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    if args.accepted_out:
        accepted = Path(args.accepted_out)
        accepted.parent.mkdir(parents=True, exist_ok=True)
        accepted.write_text(json.dumps(accepted_manifest(manifest), indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(manifest['coverage'], indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
