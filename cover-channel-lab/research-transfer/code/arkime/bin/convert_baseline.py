"""Local baseline Parquet. An intermediate batch may legitimately have no closed sessions."""
import json,os
from pathlib import Path
from pipeline import hash_file,fsync_dir,compact

def convert(batch_dir,out_dir,run_id,batch_id,journals,rotate,batch_seconds):
 import office_to_parquet as original
 import pyarrow as pa
 import pyarrow.parquet as pq
 report=json.loads((Path(batch_dir)/'batch.json').read_text())
 if report.get('sessions_written',0):
  manifest=original.convert(batch_dir,out_dir,run_id,batch_id,journals,rotate,batch_seconds)
 else:
  # Check the CSV header against the same pinned train/serve schema. No schema
  # guessing, sentinel rows, or fake zero-length sessions.
  if any(True for _ in original.iter_sessions(Path(batch_dir)/'office_sessions.csv',original.pinned_schema())):raise RuntimeError('empty batch report contradicts CSV')
  out_dir=Path(out_dir);out_dir.mkdir(parents=True,exist_ok=False)
  table=original.add_keys(pa.Table.from_batches([],schema=original.pinned_schema()),run_id,batch_id)
  path=out_dir/'office_sessions.parquet';pq.write_table(table,path,compression='zstd')
  manifest=dict(run_id=run_id,batch_id=batch_id,empty=True,office_sessions=dict(rows=0,packets=0,bad_rows=0),files={'office_sessions.parquet':dict(rows=0,bytes=path.stat().st_size,sha256=hash_file(path))})
  import office_batches
  start=office_batches.stamp_epoch(batch_id)
  quality=original.capture_quality(journals,rotate,start,start+batch_seconds)
  if quality is not None:
   quality=quality.append_column('run_id',pa.array([run_id]*quality.num_rows,pa.string())).append_column('batch_id',pa.array([batch_id]*quality.num_rows,pa.string()))
   path=out_dir/'office_capture_quality.parquet';pq.write_table(quality,path,compression='zstd');manifest['files'][path.name]=dict(rows=quality.num_rows,bytes=path.stat().st_size,sha256=hash_file(path))
  hm_csv=Path(batch_dir)/'office_host_minutes.csv'
  if hm_csv.exists():
   hm=original.host_minutes_table(hm_csv,run_id,batch_id);path=out_dir/'office_host_minutes.parquet'
   pq.write_table(hm,path,compression='zstd');manifest['files'][path.name]=dict(rows=hm.num_rows,bytes=path.stat().st_size,sha256=hash_file(path))
  (out_dir/'manifest.json').write_text(compact(manifest)+'\n')
 for name,info in manifest['files'].items():
  path=Path(out_dir)/name
  if hash_file(path)!=info['sha256'] or pq.read_metadata(path).num_rows!=info['rows']:raise RuntimeError('baseline Parquet verification mismatch')
  with path.open('rb') as f:os.fsync(f.fileno())
 with (Path(out_dir)/'manifest.json').open('rb') as f:os.fsync(f.fileno())
 fsync_dir(out_dir);return manifest
