from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
from typing import Any


def _parse_ts(value: Any) -> float:
    if isinstance(value,(int,float)):
        return float(value)
    return datetime.fromisoformat(str(value)).timestamp()


def _canonical_eve(path: str | Path) -> list[dict[str,Any]]:
    by_flow: dict[Any,dict[str,dict]] = {}
    with Path(path).open(encoding='utf-8', errors='replace') as f:
        for line in f:
            try:
                e=json.loads(line)
            except Exception:
                continue
            if e.get('event_type') not in {'tls','flow'} or e.get('flow_id') is None:
                continue
            by_flow.setdefault(e['flow_id'],{})[e['event_type']]=e
    out=[]
    for fid,pair in by_flow.items():
        tls=pair.get('tls'); fe=pair.get('flow')
        if not tls or not fe: continue
        flow=fe.get('flow') or {}
        start=_parse_ts(flow.get('start') or fe.get('timestamp'))
        end=_parse_ts(flow.get('end') or fe.get('timestamp'))
        out.append({
            'flow_id':fid,
            'src_ip':str(fe.get('src_ip') or tls.get('src_ip') or ''),
            'src_port':int(fe.get('src_port') or tls.get('src_port') or 0),
            'dst_ip':str(fe.get('dest_ip') or tls.get('dest_ip') or ''),
            'dst_port':int(fe.get('dest_port') or tls.get('dest_port') or 0),
            'proto':str(fe.get('proto') or tls.get('proto') or '').lower(),
            'sni':str((tls.get('tls') or {}).get('sni') or '').lower(),
            'start_ts':start,
            'duration':max(0.0,end-start),
            'bytes_up':int(flow.get('bytes_toserver') or 0),
            'bytes_down':int(flow.get('bytes_toclient') or 0),
        })
    return out


def _matches(a: dict, f: dict) -> bool:
    return (
        str(a.get('src_ip'))==f['src_ip']
        and int(a.get('src_port') or 0)==f['src_port']
        and str(a.get('dst_ip'))==f['dst_ip']
        and int(a.get('dst_port') or 0)==f['dst_port']
        and str(a.get('proto') or '').lower()==f['proto']
        and str(a.get('expected_sni') or '').lower()==f['sni']
    )


def extract_observed_flows(manifest_path: str | Path, eve_path: str | Path) -> tuple[list[dict],dict]:
    manifest=json.loads(Path(manifest_path).read_text(encoding='utf-8'))
    flows=_canonical_eve(eve_path)
    accepted=[a for a in manifest.get('actions') or [] if a.get('accepted_attempt') and a.get('actual_outcome')=='success']
    observed=[]; unmatched=[]; ambiguous=[]; used=set()
    for action in accepted:
        candidates=[f for f in flows if f['flow_id'] not in used and _matches(action,f)]
        if not candidates:
            unmatched.append(action.get('action_id')); continue
        if len(candidates)!=1:
            ambiguous.append(action.get('action_id')); continue
        f=dict(candidates[0]); used.add(f['flow_id'])
        row={
            **f,
            'action_id':action.get('action_id'),
            'domain_pattern':action.get('domain_pattern'),
            'probe_host':action.get('probe_host') or action.get('expected_sni'),
            'provider':action.get('provider',''),
            'catalog_tags':action.get('catalog_tags') or [],
            'wildcard_proxy':bool(action.get('wildcard_proxy')),
            'http_status':action.get('http_status'),
            'tls_version':action.get('tls_version',''),
            'tls_cipher':action.get('tls_cipher',''),
            'app_bytes_up':int(action.get('app_bytes_up') or 0),
            'app_bytes_down':int(action.get('app_bytes_down') or 0),
        }
        observed.append(row)
    n=len(accepted)
    summary={
        'accepted_actions':n,
        'matched_actions':len(observed),
        'unmatched_action_ids':unmatched,
        'ambiguous_action_ids':ambiguous,
        'match_fraction':len(observed)/n if n else 0.0,
        'complete_tls_flow_pairs':len(flows),
    }
    return observed,summary


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--manifest',required=True); ap.add_argument('--eve',required=True)
    ap.add_argument('--out',required=True); ap.add_argument('--summary',required=True)
    ap.add_argument('--min-match-fraction',type=float,default=0.95)
    args=ap.parse_args()
    rows,summary=extract_observed_flows(args.manifest,args.eve)
    out=Path(args.out); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(''.join(json.dumps(r,sort_keys=True)+'\n' for r in rows),encoding='utf-8')
    sp=Path(args.summary); sp.parent.mkdir(parents=True,exist_ok=True)
    sp.write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps(summary,indent=2,sort_keys=True))
    return 0 if (not summary['accepted_actions'] or summary['match_fraction']>=args.min_match_fraction) else 3


if __name__=='__main__':
    raise SystemExit(main())
