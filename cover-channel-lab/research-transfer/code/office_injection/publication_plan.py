"""Prepare an immutable object plan only. No network or publication capabilities."""
import json
from pathlib import Path
from .full_review import verify_seal
from .cover_registry import digest


def prepare(seal,bucket='cosmolake-dev'):
    root=Path(seal);bundle=json.loads((root/'bundle.json').read_text());verify_seal(root,bundle)
    checks=json.loads((root/'offline_checks.json').read_text())
    if not all(checks.get(k) is True for k in ('schema_verified','arrays_verified','packet_accounting_verified')) or not checks.get('coverage',{}).get('scope_reports_verified'):raise ValueError('offline checks incomplete')
    objects=[{**r,'bucket':bucket,'s3_key':'bronze/cover_revision/'+bundle['sha256']+'/'+r['path'],'status':'not_uploaded'} for r in bundle['files'] if r['path'].endswith('.parquet')]
    body={'version':'cover-publication-plan-v1','status':'prepared_user_hold','bundle_sha256':bundle['sha256'],'source_identity':bundle['source_identity'],
          'objects':objects,'uploads':[],'commit_allowed':False,'production_ready':False,
          'required_before_commit':['explicit user release of publication hold','actual checksum/size and positive S3 verification per object','exact schema/row/array/campaign-ID readback','one immutable committed manifest only after every check','pinned notebook execution on committed revision'],
          'no_network_calls':True}
    return {**body,'sha256':digest(body)}
