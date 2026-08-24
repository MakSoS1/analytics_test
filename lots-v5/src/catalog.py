from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import csv
import hashlib
import re
from typing import Any

import yaml

ALLOWED_TAGS = frozenset({'phishing', 'c2', 'download', 'exfiltration'})
TAG_TO_MECHANISM = {
    'c2': {'c2_poll', 'dead_drop', 'c2_bidirectional'},
    'download': {'staging_download'},
    'exfiltration': {'exfil_upload'},
}


@dataclass(frozen=True)
class CatalogEntry:
    domain_pattern: str
    tags: frozenset[str]
    provider: str
    source: str
    snapshot_date: str

    @property
    def phishing_only(self) -> bool:
        return self.tags == frozenset({'phishing'})

    @property
    def concrete_domain(self) -> bool:
        return '*' not in self.domain_pattern


@dataclass(frozen=True)
class ScenarioSpec:
    scenario_id: str
    pair_id: str
    domain_pattern: str
    provider: str
    mechanism: str
    label: str
    generation_mode: str
    timing_profile: str
    payload_profile: str
    client_profile: str
    behavior_profile: str
    benign_level: str | None
    catalog_tags: frozenset[str]
    train_eligible: bool


def _norm_tag(tag: str) -> str:
    tag = tag.strip().lower().replace('&', '')
    aliases = {
        'cc': 'c2',
        'c&c': 'c2',
        'c2': 'c2',
        'phishing': 'phishing',
        'download': 'download',
        'exfiltration': 'exfiltration',
    }
    if tag not in aliases:
        raise ValueError(f'unsupported LOTS tag: {tag!r}')
    return aliases[tag]


def load_catalog(path: str | Path) -> list[CatalogEntry]:
    path = Path(path)
    entries: list[CatalogEntry] = []
    with path.open(newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            raw_tags = [x for x in row['tags'].split(';') if x.strip()]
            tags = frozenset(_norm_tag(t) for t in raw_tags)
            if not tags or not tags <= ALLOWED_TAGS:
                raise ValueError(f'invalid tags for {row["domain_pattern"]}: {tags}')
            entry = CatalogEntry(
                domain_pattern=row['domain_pattern'].strip().lower(),
                tags=tags,
                provider=row['provider'].strip(),
                source=row.get('source', '').strip(),
                snapshot_date=row.get('snapshot_date', '').strip(),
            )
            entries.append(entry)
    patterns = [e.domain_pattern for e in entries]
    if len(patterns) != len(set(patterns)):
        dupes = sorted({p for p in patterns if patterns.count(p) > 1})
        raise ValueError(f'duplicate catalog entries: {dupes}')
    return entries


def load_policy(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding='utf-8') as f:
        policy = yaml.safe_load(f)
    if not isinstance(policy, dict) or 'mechanisms' not in policy:
        raise ValueError('invalid scenario policy')
    return policy


def _slug(value: str) -> str:
    value = value.lower().replace('*.', 'wildcard-')
    value = re.sub(r'[^a-z0-9]+', '-', value).strip('-')
    if len(value) <= 54:
        return value
    digest = hashlib.sha1(value.encode()).hexdigest()[:8]
    return f'{value[:45]}-{digest}'


def compile_scenarios(entries: list[CatalogEntry], policy: dict[str, Any]) -> list[ScenarioSpec]:
    out: list[ScenarioSpec] = []
    mechanisms_cfg = policy['mechanisms']

    for entry in entries:
        if entry.phishing_only:
            for block in policy.get('phishing_only', {}).get('mechanisms', []):
                mech = block['mechanism']
                for variant_idx, variant in enumerate(block.get('variants', []), start=1):
                    base = f'{_slug(entry.domain_pattern)}-{mech}-{variant_idx}'
                    out.append(ScenarioSpec(
                        scenario_id=f'{base}-benign',
                        pair_id=base,
                        domain_pattern=entry.domain_pattern,
                        provider=entry.provider,
                        mechanism=mech,
                        label='benign',
                        generation_mode='controlled_tls_hard_negative',
                        timing_profile=variant['timing_profile'],
                        payload_profile=variant['payload_profile'],
                        client_profile=variant['client_profile'],
                        behavior_profile='interactive_browse',
                        benign_level='B1',
                        catalog_tags=entry.tags,
                        train_eligible=True,
                    ))
        else:
            for tag in ('c2', 'download', 'exfiltration'):
                if tag not in entry.tags:
                    continue
                for block in mechanisms_cfg.get(tag, []):
                    mech = block['mechanism']
                    if mech not in TAG_TO_MECHANISM[tag]:
                        raise ValueError(f'mechanism {mech!r} not allowed for tag {tag!r}')
                    for variant_idx, variant in enumerate(block.get('variants', []), start=1):
                        base = f'{_slug(entry.domain_pattern)}-{mech}-{variant_idx}'
                        common = dict(
                            pair_id=base,
                            domain_pattern=entry.domain_pattern,
                            provider=entry.provider,
                            mechanism=mech,
                            generation_mode='controlled_tls_pair',
                            timing_profile=variant['timing_profile'],
                            payload_profile=variant['payload_profile'],
                            client_profile=variant['client_profile'],
                            catalog_tags=entry.tags,
                        )
                        out.append(ScenarioSpec(
                            scenario_id=f'{base}-lots', label='lots',
                            behavior_profile='persistent_cycle', benign_level=None,
                            train_eligible=True, **common))
                        out.append(ScenarioSpec(
                            scenario_id=f'{base}-b1', label='benign',
                            behavior_profile='event_driven_burst', benign_level='B1',
                            train_eligible=True, **common))
                        out.append(ScenarioSpec(
                            scenario_id=f'{base}-b2', label='benign',
                            behavior_profile='bounded_automation', benign_level='B2',
                            train_eligible=True, **common))
                        out.append(ScenarioSpec(
                            scenario_id=f'{base}-b3', label='benign',
                            behavior_profile='persistent_cycle', benign_level='B3',
                            train_eligible=False, **common))

        if policy.get('reference_probe', {}).get('enabled') and entry.concrete_domain:
            out.append(ScenarioSpec(
                scenario_id=f'{_slug(entry.domain_pattern)}-public-reference',
                pair_id=f'{_slug(entry.domain_pattern)}-public-reference',
                domain_pattern=entry.domain_pattern,
                provider=entry.provider,
                mechanism='public_reference',
                label='reference',
                generation_mode='public_read_only',
                timing_profile='single',
                payload_profile='headers_only',
                client_profile='curl_h1',
                behavior_profile='public_reference',
                benign_level=None,
                catalog_tags=entry.tags,
                train_eligible=False,
            ))

    ids = [s.scenario_id for s in out]
    if len(ids) != len(set(ids)):
        raise ValueError('scenario_id collision')
    return out
