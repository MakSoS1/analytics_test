"""Strict upload evidence and a single immutable publication commit manifest."""
from .cover_registry import digest


def validate_upload_evidence(info, expected_sha256, expected_bytes):
    actual=info.get('checksum_actual');expected=info.get('checksum_expected')
    if info.get('status')!='completed':raise ValueError('upload not completed')
    if actual!=expected_sha256 or expected not in (None,expected_sha256):raise ValueError('missing or contradictory actual checksum')
    if info.get('s3_verified') is not True:raise ValueError('missing positive S3 verification')
    if info.get('total_size')!=expected_bytes:raise ValueError('uploaded byte size differs')
    if not info.get('s3_key') or not info.get('upload_id'):raise ValueError('missing upload identity')
    return {'upload_id':info['upload_id'],'s3_key':info['s3_key'],'bytes':expected_bytes,'sha256':actual,'verified':True}


def build_revision_manifest(bundle, uploads, checks):
    tables={r['path']:r for r in bundle['files'] if r['path'].endswith('.parquet')}
    actual={u['path']:u for u in uploads}
    if len(actual)!=len(uploads) or not tables or set(actual)!=set(tables):raise ValueError('incomplete or duplicated revision table uploads')
    for key,row in tables.items():
        u=actual[key]
        if u.get('verified') is not True or u.get('sha256')!=row['sha256'] or u.get('bytes')!=row['bytes']:
            raise ValueError('upload evidence differs from sealed table')
    expected_ids=checks.get('campaign_ids_expected',[]);actual_ids=checks.get('campaign_ids_actual',[])
    if (not expected_ids or len(set(expected_ids))!=len(expected_ids) or len(set(actual_ids))!=len(actual_ids)
            or set(expected_ids)!=set(actual_ids)):raise ValueError('campaign ID sets differ or duplicate')
    required=('schema_verified','arrays_verified','packet_accounting_verified','coverage_complete')
    if not all(checks.get(k) is True for k in required):raise ValueError('revision read-back or scope incomplete')
    body={'version':'cover-publication-v1','status':'committed','bundle_sha256':bundle['sha256'],
          'source_identity':bundle['source_identity'],'uploads':uploads,'checks':checks,'production_ready':False}
    return {**body,'sha256':digest(body)}


def require_committed_revision(manifest, expected_identity):
    if manifest.get('status')!='committed' or manifest.get('version')!='cover-publication-v1':raise ValueError('committed revision required')
    if manifest.get('source_identity')!=expected_identity:raise ValueError('publication source identity mismatch')
    if manifest.get('sha256')!=digest({k:v for k,v in manifest.items() if k!='sha256'}):raise ValueError('revision manifest was modified')
    if not manifest.get('uploads') or not all(u.get('verified') is True for u in manifest['uploads']):raise ValueError('unverified table upload')
    return manifest
