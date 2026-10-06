"""Local host context with explicit observed-span coverage, without loading packet arrays."""
import argparse
import json
from pathlib import Path
import pandas as pd
import pyarrow.parquet as pq
import build_context_tables as baseline
from .pipeline import dump

COLUMNS=['session_uid','segment_index','host_key','server_key','dest_port','proto','session_start_epoch',
         'admin_service_by_port','ra_off_hours','pay_entropy_up','pay_printable_up','pay_b64_share_up',
         'pay_bytes_sampled_up','ssh_client_fp_key','conn_state','pkt_count','up_bytes','down_bytes',
         'direction_changes','ra_small_up_count','data_pkt_up','small_data_up_bytes',
         'tcp_retx_pkts_up','tcp_retx_pkts_down','seq_first_dir','seq_last_dir']

def build(run,out):
    run=Path(run);out=Path(out)
    json.loads((run/'validated.json').read_text())
    out.mkdir(parents=True,exist_ok=False)
    pieces=[pq.ParquetFile(p).read(columns=COLUMNS).to_pandas() for p in sorted(run.glob('batches/*/parquet/office_sessions.parquet'))]
    df=pd.concat(pieces,ignore_index=True)
    # The baseline only reads sequence edges to recover direction switches
    # between segments; these pinned Parquet columns preserve exactly those edges.
    df['seq_signed_len']=[[int(a),int(b)] for a,b in zip(df.seq_first_dir,df.seq_last_dir)]
    s=baseline.sessions_view(df);pairs=baseline.pairs_table(s,None)
    seen_pairs={}
    for r in pairs.itertuples():
        k=(r.host_key,r.server_key);seen_pairs[k]=min(seen_pairs.get(k,float('inf')),r.first_seen_epoch)
    seen_ports={(r.host_key,r.server_key,r.dest_port,r.proto):r.first_seen_epoch for r in pairs.itertuples()}
    fp=(s[s.ssh_client_fp_key.fillna('')!=''].groupby(['host_key','ssh_client_fp_key'])
        .agg(first_seen_epoch=('session_start_epoch','min'),sessions=('session_uid','count')).reset_index())
    seen_fp={(r.host_key,r.ssh_client_fp_key):r.first_seen_epoch for r in fp.itertuples()}
    profile=json.loads((run/'office_profile.json').read_text())
    spans=pd.DataFrame([{'status':'ok','interval_start_epoch':x['observed_first'],
                         'interval_seconds':x['observed_last']-x['observed_first']} for x in profile])
    windows=baseline.host_windows(s,seen_pairs,seen_ports,seen_fp,
                                 min(x['observed_first'] for x in profile),max(x['observed_last'] for x in profile),spans)
    for name,table in [('office_host_windows',windows),('office_pairs',pairs),('office_ssh_fingerprints',fp)]:
        table.to_parquet(out/(name+'.parquet'),compression='zstd',index=False)
    report={'sessions':len(s),'segments':len(df),'host_windows':len(windows),'pairs':len(pairs),
            'ssh_fingerprints':len(fp),'coverage_basis':'observed packet spans; no capture journal; proxy only',
            'office_host_mapping':False,'production_training_ready':False,
            'novelty_history':'this experiment only; first observed window has no earlier office history',
            'window_policy':'baseline session-start attribution; not overlap attribution'}
    dump(out/'manifest.json',report);return report

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',required=True);p.add_argument('--out',required=True)
    a=p.parse_args();print(json.dumps(build(a.run,a.out),indent=2))

if __name__=='__main__':main()
