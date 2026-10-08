"""Read-only, revision-bound population and stratified origin diagnostics.

Runs next to existing training artifacts. No capture rewriting or training of
the detector. The diagnostic classifier uses held-out days/profile groups.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def positive(row, key):
    value = row.get(key)
    return value is not None and value > 0


def strata(row):
    bi = positive(row, 'data_pkt_up') and positive(row, 'data_pkt_down')
    return {'all': True, 'bidirectional': bi,
            'sni_bidirectional': bi and positive(row, 'tls_sni_len'),
            'parsed_tls_bidirectional': bi and positive(row, 'tls_version')}


def populations(rows):
    n = len(rows)
    def share(predicate):
        return sum(predicate(r) for r in rows) / n if n else None
    return {'rows': n, 'tls_sni_observed_share': share(lambda r: positive(r, 'tls_sni_len')),
            'tls_parsed_share': share(lambda r: positive(r, 'tls_version')),
            'tls_details_available_share': share(lambda r: r.get('tls_version') is not None),
            'down_data_share': share(lambda r: positive(r, 'data_pkt_down')),
            'at_most_four_packets_share': share(lambda r: r['pkt_count'] <= 4),
            'fin_observed_share': share(lambda r: positive(r, 'fin_count')),
            'iat_min_zero_share': share(lambda r: r['iat_min'] == 0),
            'frame_max_modes': Counter(r['pkt_len_max'] for r in rows).most_common(5)}


def day_counts(metadata, mask):
    return dict(Counter(m['office_capture_day'] for m, yes in zip(metadata, mask) if yes))


def holdout_status(train_counts, test_counts, minimum=20):
    if min(*train_counts, *test_counts) < minimum:
        return 'insufficient_independent_holdout'
    return 'eligible_day_and_profile_holdout'


def verified_sources(training, compositions, complete):
    from office_injection.full_review import verify_seal
    from office_injection.training_contract import source_identity
    combined = Path(training).parent / 'combined_sessions_v1'
    if source_identity(combined) != complete['source_identity']:
        raise ValueError('training source identity changed')
    request = json.loads((combined / 'request.json').read_text())
    declared = request['compositions']
    if [Path(p).resolve() for p in compositions] != [Path(r['path']).resolve() for r in declared[:2]]:
        raise ValueError('full office sources must match the two original pinned compositions')
    verified = []
    clean_files = {}
    for item in declared:
        sealed = Path(item['path']) / 'sealed'
        bundle = json.loads((sealed / 'bundle.json').read_text())
        if bundle['sha256'] != item['bundle_sha256']:
            raise ValueError('composition bundle differs from training request')
        verified.append(verify_seal(sealed, bundle))
    for comp in compositions:
        ref = json.loads((Path(comp) / 'sealed/clean_reference.json').read_text())
        clean = Path(ref['path'])
        for name, pin in ref['files'].items():
            if digest(clean / name) != pin:
                raise ValueError('clean reference changed: ' + name)
        files = sorted(name for name in ref['files'] if name.endswith('/parquet/office_sessions.parquet'))
        if not files:
            raise ValueError('no pinned clean parquet sources')
        clean_files[str(comp)] = [(clean / name, ref['files'][name]) for name in files]
    return verified, clean_files


def audit(training, compositions):
    import numpy as np
    import pyarrow.parquet as pq
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.metrics import roc_auc_score
    from sklearn.pipeline import make_pipeline

    training = Path(training)
    complete_path = training / 'COMPLETE.json'
    complete_pin = digest(complete_path)
    complete = json.loads(complete_path.read_text())
    for name, pin in complete['files'].items():
        if digest(training / name) != pin:
            raise ValueError('sealed training artifact changed: ' + name)
    verified_compositions, clean_files = verified_sources(training, compositions, complete)
    f = pq.read_table(training / 'features_all.parquet').to_pylist()
    m = pq.read_table(training / 'labels_metadata.parquet').to_pylist()
    o = pq.read_table(training / 'office_unlabelled_sample.parquet').to_pylist()
    om = pq.read_table(training / 'office_sample_metadata.parquet').to_pylist()
    manifest = json.loads((training / 'manifest.json').read_text())
    names = manifest['features_all']
    if len(f) != len(m) or len(o) != len(om):
        raise ValueError('feature/metadata rows differ')
    controls = [r for r, meta in zip(f, m) if meta['label_state'] == 'matched_control']
    negatives = [r for r, meta in zip(f, m) if meta['label_binary'] == 0]
    by_day = {day: populations([r for r, meta in zip(o, om) if meta['office_capture_day'] == day])
              for day in sorted({meta['office_capture_day'] for meta in om})}
    out = {'version': 'stratified-origin-audit-v2', 'training_complete_sha256': complete_pin,
           'source_identity': complete['source_identity'], 'audit_code_sha256': digest(__file__),
           'verified_compositions': verified_compositions,
           'populations': {'office': populations(o), 'matched_control': populations(controls),
                           'all_label_zero_including_hard_negative': populations(negatives)},
           'office_days': by_day, 'strata': {}, 'full_office': [],
           'limits': ['Origin diagnostics do not measure naturalness or office FPR directly.',
                      'SNI does not identify all TLS; parsed TLS depends on sidecar availability.',
                      'Only two retained office days and one framework source build/day.',
                      'No raw office SYN PCAP in retained composition; MSS/encapsulation cause unconfirmed.',
                      'Six paired framework groups do not support standalone generalization claims.'],
           'corrections': {'timestamp_requantization_justified': False,
                           'fixed_frame_1304_mss_justified': False,
                           'tls_fingerprint_spoofing_justified': False,
                           'office_labels_known': False}}
    for stratum in ('all', 'bidirectional', 'sni_bidirectional', 'parsed_tls_bidirectional'):
        cmask = [meta['label_state'] == 'matched_control' and strata(row)[stratum] for row, meta in zip(f, m)]
        omask = [strata(row)[stratum] for row in o]
        c = [row for row, yes in zip(f, cmask) if yes]
        office = [row for row, yes in zip(o, omask) if yes]
        entry = {'matched_control': populations(c), 'office': populations(office),
                 'office_days': day_counts(om, omask), 'single_feature_descriptive_auc': {},
                 'scope': 'descriptive whole stratum; supervised diagnostic below uses held-out profiles/days'}
        for key in ('pkt_len_max', 'iat_min', 'tls_sigalg_count'):
            cv = [row[key] for row in c if row.get(key) is not None]
            ov = [row[key] for row in office if row.get(key) is not None]
            value = None
            if cv and ov:
                raw = roc_auc_score([0]*len(ov)+[1]*len(cv), ov+cv)
                value = float(max(raw, 1-raw))
            entry['single_feature_descriptive_auc'][key] = {'auc': value, 'office_rows': len(ov), 'control_rows': len(cv)}
        # Full fingerprint diversity is descriptive, only among records where
        # all four parsed fields exist; never equate it with stack identity.
        fields = ('tls_cipher_count', 'tls_ext_count', 'tls_group_count', 'tls_sigalg_count')
        entry['tls_tuple_diversity'] = {label: len({tuple(row[k] for k in fields) for row in rows
                                                   if positive(row, 'tls_version') and all(row.get(k) is not None for k in fields)})
                                        for label, rows in (('office', office), ('control', c))}
        train_c = [row for row, meta, yes in zip(f, m, cmask) if yes and meta['split'] == 'train']
        test_c = [row for row, meta, yes in zip(f, m, cmask) if yes and meta['split'] == 'test']
        train_o = [row for row, meta, yes in zip(o, om, omask) if yes and meta['office_capture_day'] == '2026-09-22']
        test_o = [row for row, meta, yes in zip(o, om, omask) if yes and meta['office_capture_day'] == '2026-09-28']
        entry['holdout'] = {'train_office': len(train_o), 'train_control': len(train_c),
                            'test_office': len(test_o), 'test_control': len(test_c),
                            'status': holdout_status((len(train_o), len(train_c)), (len(test_o), len(test_c)))}
        if entry['holdout']['status'].startswith('eligible'):
            # Exclude measurements unavailable throughout either source's
            # train partition. Missingness itself remains a reported diagnostic.
            used = [k for k in names if any(row.get(k) is not None for row in train_o)
                    and any(row.get(k) is not None for row in train_c)]
            matrix = lambda rows: np.array([[np.nan if row.get(k) is None else row[k] for k in used] for row in rows])
            model = make_pipeline(SimpleImputer(strategy='median'), HistGradientBoostingClassifier(
                max_iter=100, max_leaf_nodes=15, random_state=20261005, early_stopping=False))
            model.fit(matrix(train_o + train_c), [0]*len(train_o) + [1]*len(train_c))
            scores = model.predict_proba(matrix(test_o + test_c))[:, 1]
            entry['holdout']['roc_auc'] = float(roc_auc_score([0]*len(test_o)+[1]*len(test_c), scores))
            entry['holdout']['features'] = used
        out['strata'][stratum] = entry
    # Use all retained clean office segments for population estimates, without
    # sending rows, identifiers or raw bytes to the caller.
    for composition in compositions:
        comp = Path(composition)
        rows = []
        columns = ['proto', 'pkt_count', 'data_pkt_down', 'data_pkt_up', 'tls_sni_len',
                   'tls_version', 'tls_sigalg_count', 'fin_count', 'iat_min', 'pkt_len_max']
        files = clean_files[str(comp)]
        pins = {}
        for file, pin in files:
            if digest(file) != pin:
                raise ValueError('clean parquet changed during audit')
            pins[file.name + ':' + str(len(pins))] = pin
            rows.extend(pq.read_table(file, columns=columns).to_pylist())
        out['full_office'].append({'composition': comp.name, 'files': len(files), 'file_pins': pins,
                                  'population': populations(rows),
                                  'protocol_counts': dict(Counter(r['proto'] for r in rows)),
                                  'strata': {name: populations([row for row in rows if strata(row)[name]])
                                             for name in ('sni_bidirectional', 'parsed_tls_bidirectional')}})
    # Pin the observed capture precision, not an inferred timing distribution.
    capture_magic = Counter()
    request = json.loads((training.parent / 'combined_sessions_v1/request.json').read_text())
    for comp in [item['path'] for item in request['compositions']]:
        for file in (Path(comp) / 'sealed/wire_evidence').glob('*/campaign.pcap'):
            with file.open('rb') as stream:
                capture_magic[stream.read(4).hex()] += 1
    out['source_pcap_magic_counts'] = dict(capture_magic)
    out['pcap_count_scope'] = 'retained copies: original 568 arms repeated on two office contexts, plus 12 new framework arms'
    out['clock_note'] = 'Classic d4c3b2a1/a1b2c3d4 PCAP is already microsecond precision; equal timestamps also depend on scheduling/capture batching.'
    if digest(complete_path) != complete_pin:
        raise ValueError('training revision changed during audit')
    return out


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--training', type=Path, required=True)
    parser.add_argument('--composition', type=Path, action='append', default=[])
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise FileExistsError('Retain audit revisions: choose a new output file')
    result = audit(args.training, args.composition)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'status': 'complete', 'out': str(args.out), 'strata': {k: v['holdout'] for k, v in result['strata'].items()}}, ensure_ascii=False))
