"""Import paired activity captures without depending on a generator's implementation.

Membership is verified from isolated captures; semantic claims remain operator
assertions backed by retained receipts. This adapter never authorizes training.
"""
import argparse
from datetime import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
from zoneinfo import ZoneInfo
from .source import read_pcap, sha256, transport
from .path_conformance import OFFICE_PATH_V1_MTU, check_capture
from .wire_observation import _header, observe_capture


def prepare_activity(spec_path, out):
    spec_path = Path(spec_path).resolve()
    spec = json.loads(spec_path.read_text())
    out = Path(out).resolve()
    if out.exists():
        raise FileExistsError('output retained; choose a new output directory')
    for key in ('activity_id', 'pair_id'):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,60}', spec.get(key, '')):
            raise ValueError('explicit safe ' + key + ' required')
    if spec.get('training_eligible') or spec.get('timing_training_eligible'):
        raise ValueError('activity configuration cannot authorize training')
    if spec.get('capture_environment') != 'isolated':
        raise ValueError('this adapter requires isolated per-arm captures; mixed office PCAP needs finer membership')
    if set(spec.get('arms', {})) != {'scenario', 'control'}:
        raise ValueError('exactly one scenario and one matched control required')
    role = spec.get('dataset_role', 'scenario_and_matched_control')
    if role not in ('scenario_and_matched_control', 'hard_negative'):
        raise ValueError('unsupported dataset role')
    pair = spec['activity_id'] + '__' + spec['pair_id']

    def checked_file(path, expected):
        p = (spec_path.parent / path).resolve()
        if not p.is_file() or sha256(p) != expected:
            raise ValueError('source/evidence hash mismatch: ' + str(p))
        return p

    declared_path = spec.get('path_profile')
    if declared_path == 'office_path_v1':
        declared_path = {'client_mtu': OFFICE_PATH_V1_MTU}
    if declared_path is not None and not (isinstance(declared_path, dict) and isinstance(declared_path.get('client_mtu'), int)):
        raise ValueError("path_profile must be 'office_path_v1' or an object with an integer client_mtu")
    prepared = []
    for arm in ('scenario', 'control'):
        item = spec['arms'][arm]
        if not item.get('description') or not item.get('evidence'):
            raise ValueError('arm description and application evidence required')
        ipaddress.ip_address(item['source_ip'])
        path = checked_file(item['pcap'], item['sha256'])
        evidence = [checked_file(e['path'], e['sha256']) for e in item['evidence']]
        flows = set()
        first = last = None
        count = 0
        for stamp, frame in read_pcap(path):
            header = _header(frame)
            p = transport(frame)
            if not header['supported'] or p is None:
                raise ValueError('unsupported frame; use a carrier-specific adapter')
            if item['source_ip'] not in (p['src'], p['dst']):
                raise ValueError('foreign traffic in isolated activity capture')
            if p['key'] not in flows:
                if p['src'] != item['source_ip'] or p['proto'] == 6 and p['flags'] & 0x12 != 2:
                    raise ValueError('whole client-initiated flow required, including TCP SYN')
                flows.add(p['key'])
            first = stamp if first is None else first
            last = stamp
            count += 1
        if count < 2 or last <= first:
            raise ValueError('nonempty activity span required')
        conformance = {'status': 'not_declared'}
        if declared_path:
            conformance = check_capture(path, item['source_ip'], declared_path['client_mtu'],
                                        item.get('client_tcp_timestamps', declared_path.get('client_tcp_timestamps')))
            if not conformance['ok']:
                raise ValueError('declared path profile not on the wire (' + arm + '): ' + '; '.join(conformance['findings']))
            conformance['status'] = 'verified'
        prepared.append((arm, item, path, evidence, first, last, count, conformance))

    # All input checks precede creating artifacts. Failed writes remain for inspection.
    source_pair = hashlib.sha256(json.dumps(sorted(item['sha256'] for item in spec['arms'].values())).encode()).hexdigest()
    out.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(spec_path, out / 'activity.json')
    campaigns = []
    for arm, item, path, evidence, first, last, count, conformance in prepared:
        directory = out / arm
        directory.mkdir()
        capture = directory / 'capture.pcap'
        shutil.copyfile(path, capture)
        if sha256(capture) != item['sha256']:
            raise ValueError('capture changed during import')
        receipts = []
        for i, original in enumerate(evidence):
            target = directory / ('receipt_' + str(i) + original.suffix)
            shutil.copyfile(original, target)
            expected = item['evidence'][i]['sha256']
            if sha256(target) != expected:
                raise ValueError('receipt changed during import')
            receipts.append({'path': str(target.relative_to(out)), 'sha256': expected})
        campaign_id = pair + '__' + arm
        observation = observe_capture(capture, {'campaign_id': campaign_id,
            'source_ip': item['source_ip'], 'capture_sha256': item['sha256'],
            'started_at': first, 'ended_at': last + 0.000002}, directory / 'wire')
        campaigns.append({'campaign_id': campaign_id, 'parent_campaign_id': pair,
            'ancestor_group_id': source_pair,
            'technique': spec['activity_id'], 'arm': arm, 'dataset_role': role,
            'path': str(capture), 'sha256': item['sha256'], 'packets': count,
            'source_start': first, 'duration': last - first, 'source_ip': item['source_ip'],
            'template_moscow_date': datetime.fromtimestamp(first, ZoneInfo('Europe/Moscow')).date().isoformat(),
            'generated': True, 'training_eligible': False, 'timing_training_eligible': False,
            'timing_fidelity': 'original_capture_unqualified',
            'source_fidelity': 'external_observed_capture',
            'source_capture_sha256': item['sha256'],
            'membership': 'whole_client_initiated_flows_in_operator_declared_isolated_capture',
            'semantic_verification': 'operator_asserted_with_retained_receipts',
            'description': item['description'], 'evidence': receipts,
            'path_conformance': conformance,
            'observation_sha256': observation['sha256']})
    result = {'version': 'activity-catalog-v1', 'role': 'challenge_only',
              'activity_spec_sha256': sha256(out / 'activity.json'), 'campaigns': campaigns}
    (out / 'catalog.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--spec', type=Path, required=True, help='activity JSON; paths relative to this file')
    p.add_argument('--out', type=Path, required=True, help='new local directory for verified captures/catalog')
    args = p.parse_args()
    result = prepare_activity(args.spec, args.out)
    print(json.dumps({'catalog': str(args.out / 'catalog.json'), 'campaigns': len(result['campaigns']),
                      'training_eligible': False}, ensure_ascii=False))


if __name__ == '__main__':
    main()
