"""Explicit model input policy; analytical tables retain their full schema.

These are session-completion features, not an early-detection contract.
Campaign and decrypted-content contracts require their own serving source.
"""
import hashlib
import json
from pathlib import Path
from .feature_contract import is_feature

VERSION = 'cover-separability-v2'
SESSION_FEATURES = tuple('''
pkt_count up_pkt_count down_pkt_count total_bytes up_bytes down_bytes flow_duration
up_down_pkt_ratio up_down_bytes_ratio pkt_rate byte_rate pkt_len_mean pkt_len_std
pkt_len_min pkt_len_max pkt_len_median pkt_len_p10 pkt_len_p90 pkt_len_p95 pkt_len_entropy
iat_mean iat_std iat_min iat_max iat_p50 iat_p90 iat_p99 iat_entropy iat_cv iat_regularity
burst_count idle_ratio direction_changes syn_count fin_count rst_count psh_count ack_count
len_entropy_up len_entropy_down len_unique_up len_unique_down small_pkt_share low_rate_long
dir_entropy idle_gt60_count up_bytes_per_pkt down_bytes_per_pkt const_len_share_up
burst_len_mean burst_len_max dir_burst_count dir_burst_len_mean dir_burst_len_max
ra_small_up_count ra_small_up_share ra_keystroke_iat_p50 ra_echo_ratio ra_echo_latency_p50
ra_interactive_score ra_burst_after_idle tcp_handshake_rtt_ms data_pkt_up data_pkt_down
small_data_up_bytes pay_entropy_up pay_entropy_down pay_printable_up pay_printable_down
pay_null_share_up pay_b64_share_up pay_bytes_sampled_up pay_bytes_sampled_down
tcp_retx_pkts_up tcp_retx_pkts_down tcp_retx_bytes_up tcp_retx_bytes_down
tls_sni_len tls_version tls_cipher_count tls_ext_count tls_group_count tls_sigalg_count
tls_alpn_h2 tls_alpn_h3 tls_alpn_http11 tls_alpn_other tls_resumed tls_early_data
'''.split())


def is_training_feature(name):
    return name in SESSION_FEATURES and is_feature(name)


def validate_training_contract(feature_names, target_name='label_binary', name='network_session_v1'):
    names = list(feature_names)
    if name != 'network_session_v1':raise ValueError('serving contract not implemented: ' + name)
    if target_name != 'label_binary':raise ValueError('target must be label_binary; y_presumed is not ground truth')
    if not names or len(names) != len(set(names)):raise ValueError('nonempty, unique feature order required')
    bad = [n for n in names if not is_training_feature(n)]
    if bad:raise ValueError('forbidden or unavailable training features: ' + ', '.join(bad))
    body = {'version': VERSION, 'name': name, 'features': names, 'target': target_name,
            'grain': 'completed_transport_session', 'serving_source': 'office_session_extractor'}
    return {**body, 'sha256': hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()}


def label_for_memberships(memberships):
    if not memberships:return None, 'office_unlabelled'
    roles={r.get('dataset_role','scenario_and_matched_control') for r in memberships}
    if len(roles)!=1:raise ValueError('conflicting session dataset roles')
    arms = {r.get('arm') for r in memberships}
    if not arms <= {'scenario', 'control'} or len(arms) != 1:
        raise ValueError('unknown or conflicting session arms')
    if roles=={'hard_negative'}:return 0,'hard_negative'
    if roles!={'scenario_and_matched_control'}:raise ValueError('unknown session dataset role')
    return (1, 'observed_positive') if arms == {'scenario'} else (0, 'matched_control')


def candidate_status(report):
    """Exploratory candidate, never a production transfer claim."""
    statuses = [report.get(k, 'not_measured') for k in
                ('integrity_status', 'domain_status', 'technique_status')]
    return 'passed' if all(s == 'passed' for s in statuses) else 'not_passed'


def training_authorized(report):
    if report.get('evaluation_version') != VERSION or candidate_status(report) != 'passed':
        return False
    contract = report.get('training_contract') or {}
    try:expected = validate_training_contract(report.get('admitted_features', []))
    except ValueError:return False
    return (contract == expected and report.get('gate') == 'passed'
            and bool(report.get('source_identity')) and report.get('source_split_status') == 'planned'
            and report.get('source_split_applied') is True and bool(report.get('source_split_sha256')))


def source_identity(run):
    """Bind a measurement to the exact rows, labels and lineage it evaluated."""
    run = Path(run); digest = hashlib.sha256()
    paths = [run / n for n in ('request.json','validated.json','positive_registry.json','schedule.json','source_split_manifest.json',
                               'runtime_manifest.json','mapping_manifest.json','cover_registry.json','source_lock.json','observation_manifest.json','full_campaign_registry.json','coverage.json','mechanic_evidence.json','source_prerequisites.json','pipeline_code_manifest.json')]
    for pattern in ('batches/*/office_sessions.csv','batches/*/office_sessions.csv.gz','batches/*/segment_gt.jsonl',
                    'batches/*/parquet/office_sessions.parquet','batches/*/parquet/segment_gt.parquet','wire_evidence/*/*'):
        paths.extend(run.glob(pattern))
    for p in sorted(set(paths)):
        if not p.is_file():continue
        digest.update(str(p.relative_to(run)).encode())
        with p.open('rb') as f:
            for block in iter(lambda:f.read(1<<20), b''):digest.update(block)
    return digest.hexdigest()


def measurement_status(report, run, scope):
    """A failed experiment and a missing independent experiment differ."""
    run=Path(run)
    if not report:return 'not_measured'
    if (report.get('evaluation_version')!=VERSION or report.get('source_identity')!=source_identity(run)
            or sorted(report.get('evaluated_campaign_ids',[]))!=sorted(scope)):
        return 'stale_measurement'
    path=run/'source_split_manifest.json'
    split=json.loads(path.read_text()) if path.exists() else {}
    if split.get('component_count',0)<3 or split.get('status')!='planned':return 'insufficient_data'
    if report.get('source_split_applied') is not True:return 'insufficient_data'
    if candidate_status(report)=='passed':return 'passed'
    confirmation=report.get('confirmation') or {}
    if confirmation.get('technique_measurement_complete') is True and report.get('technique_status')=='not_passed':
        return 'no_signal_detected'
    return 'not_passed'


def training_authorized_for_run(report, run, technique=None):
    """Every eligibility consumer verifies the current source and evaluated scope."""
    if not training_authorized(report):return False
    run = Path(run)
    if report.get('source_identity') != source_identity(run):return False
    manifest_path = run / 'source_split_manifest.json'
    if not manifest_path.exists():return False
    split = json.loads(manifest_path.read_text())
    if report.get('source_split_sha256') != split.get('sha256'):return False
    registry = json.loads((run / 'positive_registry.json').read_text())
    scope = sorted({r['campaign_id'] for r in registry if technique is None or r.get('technique') == technique})
    return bool(scope) and scope == sorted(report.get('evaluated_campaign_ids', []))
