from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _runtime():
    try:
        import zstandard as zstd
        from coverlab.pipeline_v3 import _packet_sequence_features
        return zstd,_packet_sequence_features
    except (ImportError,ModuleNotFoundError):
        root=Path(__file__).resolve().parents[1]
        req=root/'requirements.txt'
        print(f'packet backfill runtime missing; installing pinned base requirements from {req}',file=sys.stderr)
        subprocess.check_call([sys.executable,'-m','pip','install','-r',str(req)])
        import zstandard as zstd
        from coverlab.pipeline_v3 import _packet_sequence_features
        return zstd,_packet_sequence_features


def decompress(src:Path,dst:Path,zstd):
    with src.open('rb') as f,dst.open('wb') as o:zstd.ZstdDecompressor().copy_stream(f,o)


def run(root:Path)->dict:
    zstd,packet_sequence_features=_runtime();built=0;skipped=0;errors=[];rows=0
    for pcap_zst in root.rglob('*.pcap.zst'):
        try:
            shard=pcap_zst.parent.parent.name;bronze=pcap_zst.parent.parent.parent
            if bronze.name!='bronze':continue
            release=bronze.parent;campaigns=bronze/shard/'manifests'/'campaigns.jsonl';target=release/'gold'/shard/'packet_sequence_features.parquet'
            if target.exists() and target.stat().st_size>0:skipped+=1;continue
            if not campaigns.exists():raise RuntimeError(f'missing campaigns manifest for {shard}')
            target.parent.mkdir(parents=True,exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='coverlab-packet-backfill-') as td:
                td=Path(td);pcap=td/f'{shard}.pcap';stage=td/'stage';stage.mkdir();shutil.copy2(campaigns,stage/'campaigns.jsonl');decompress(pcap_zst,pcap,zstd)
                frame=packet_sequence_features(stage,pcap)
                if frame.empty:raise RuntimeError(f'packet mapping produced zero rows for {shard}')
                frame.to_parquet(target,index=False);rows+=len(frame);built+=1
        except Exception as e:errors.append(f'{pcap_zst}: {e}')
    report={'root':str(root),'built':built,'skipped':skipped,'packet_rows':rows,'errors':errors,'passed':not errors and (built+skipped)>0,'feature_revision':4,'source':'retained_raw_pcap_only'}
    if not report['passed']:raise SystemExit(str(report))
    print(report);return report


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--dataset-root',required=True);a=ap.parse_args();run(Path(a.dataset_root))

if __name__=='__main__':main()
