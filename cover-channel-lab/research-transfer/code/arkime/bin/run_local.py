"""Process closed pcaps in ONE parser process. Durable local tables, no upload.
Input order is caller supplied; do not put an actively written file in this list.
Failures preserve all inputs. Restart uses a new node epoch; no silent continuity claim.
"""
import argparse,fcntl,json,os,shlex,shutil,socket,struct,subprocess,sys,time,uuid
from pathlib import Path
from pipeline import Store,OpenSearch,compact,hash_file,export_tables,fsync_dir
R=Path(__file__).resolve().parents[1]

def guard(root,minimum=40*1024**3):
 if shutil.disk_usage(root).free<minimum:raise RuntimeError('disk reserve reached; stop capture, retain uncommitted inputs')

def pcap_count(path):
 with Path(path).open('rb') as f:
  h=f.read(24)
  if len(h)!=24 or h[:4] not in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\xa1\xb2\x3c\x4d'):raise ValueError('only validated classic pcap supported')
  endian='<' if h[:4] in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1') else '>'
  count=0;remaining=Path(path).stat().st_size-24
  while remaining:
   if remaining<16:raise ValueError('truncated pcap record')
   h=f.read(16);sec,usec,cap,wire=struct.unpack(endian+'IIII',h)
   if cap!=wire or cap>remaining-16:raise ValueError('truncated pcap payload')
   f.seek(cap,1);remaining-=16+cap;count+=1
 return count

class Capture:
 def __init__(self,run,node):
  self.sockpath=run/'capture.sock';self.log=(run/'capture.log').open('ab',buffering=0)
  self.proc=subprocess.Popen([str(R/'downloads/arkime-6.8.0/capture/capture'),'-c',str(R/'config/office.ini'),'-n',node,'-t',node,'--host','localhost','--scheme','--command-wait','--command-socket',str(self.sockpath)],stdout=self.log,stderr=self.log)
  for _ in range(200):
   if self.proc.poll() is not None:raise RuntimeError('capture startup failed; see capture.log')
   if self.sockpath.exists():break
   time.sleep(.1)
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.connect(str(self.sockpath));self.sock.settimeout(300);self.buf=b''
 def line(self):
  while b'\n' not in self.buf:
   block=self.sock.recv(65536)
   if not block:raise RuntimeError('capture socket closed')
   self.buf+=block
  raw,self.buf=self.buf.split(b'\n',1);return raw.decode()
 def add(self,path):
  self.sock.sendall(('add-file --notify --nodelete --noskip '+shlex.quote(str(path))+'\n').encode())
  while True:
   line=self.line()
   if line.startswith('file-error'):raise RuntimeError(line)
   if line.startswith('file-done '):return line
 def close(self):
  if self.proc.poll() is None:
   self.sock.sendall(b'shutdown\n')
   try:self.proc.wait(timeout=120)
   except subprocess.TimeoutExpired:self.proc.terminate();self.proc.wait(timeout=30)
  self.sock.close();self.log.close()
  if self.proc.returncode:raise RuntimeError('capture exit '+str(self.proc.returncode))

def sync(api,store,node):
 api.call('POST','/office_arkime_sessions3-*/_refresh')
 # Seq is immutable and includes file checkpoints. Retry the last page safely.
 maximum=store.contiguous_sequence()
 query={'bool':{'filter':[{'term':{'tags':node}},{'range':{'office.seq':{'gt':maximum}}}]}}
 batch=[]
 for hit in api.hits('office_arkime_sessions3-*',query):
  batch.append(hit)
  if len(batch)>=128:
   with store.db:
    for item in batch:store.put_fragment(item,commit=False)
   batch=[]
 if batch:
  with store.db:
   for item in batch:store.put_fragment(item,commit=False)

def final_barrier(api,store,node,expected_packets,attempts=60):
 for attempt in range(attempts):
  sync(api,store,node)
  open_sessions=store.db.execute('select count(*) from session_totals where ended=0').fetchone()[0]
  maximum=store.db.execute("select coalesce(max(json_extract(source_json,'$.office.seq')),0) from fragments").fetchone()[0]
  if not open_sessions and store.packet_total()==expected_packets and store.contiguous_sequence()==maximum:return
  if attempt+1<attempts:time.sleep(1)
 raise RuntimeError('final SPI indexing/completion barrier failed; no successful final report')

def run(files,out,on_chunk=None):
 guard(R);out.mkdir(parents=True,exist_ok=False)
 lock=(out/'lock').open('w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 node='office-'+uuid.uuid4().hex;store=Store(out/'state.db');store.new_generation();api=OpenSearch();cap=None;frames=0;watermark=0;processed_files=0
 journal=(out/'journal.jsonl').open('a',buffering=1)
 try:
  cap=Capture(out,node)
  for i,path in enumerate(files):
   guard(R);path=Path(path).resolve();expected=pcap_count(path);sha=hash_file(path);store.register_chunk(path,sha,path.stat().st_size)
   start=time.monotonic();notice=cap.add(path);frames+=expected;parsed=time.monotonic()
   metrics={k:int(v) for k,v in (token.split('=',1) for token in notice.split() if '=' in token) if k!='filename'}
   if metrics.get('errors',1) or metrics.get('droppedFragments',1):raise RuntimeError('capture disposition errors; retain all inputs')
   if frames!=metrics['processed']+metrics['fragmentPackets']-metrics['reassembled']:raise RuntimeError('raw frame disposition mismatch')
   # Search-visible accounting barrier; file-done alone is NOT an indexing ACK.
   for attempt in range(60):
    sync(api,store,node)
    total=store.packet_total()
    if total==metrics['processed'] and store.contiguous_sequence()==metrics['spiSeq']:break
    if total>metrics['processed']:raise RuntimeError('packet accounting exceeded input; retain pcap')
    time.sleep(1)
   else:raise RuntimeError(f'packet accounting mismatch: logical input {metrics['processed']}, durable SPI {total}; no deletion permitted')
   synced=time.monotonic()
   manifest=export_tables(store,out/f'part-{i:06d}',export_id=node,after_rowid=watermark)
   exported=time.monotonic()
   watermark=store.db.execute('select coalesce(max(rowid),0) from fragments').fetchone()[0]
   # Only Arkime side is acknowledged here. Existing baseline rows remain mandatory.
   store.commit_chunk(path,expected,False,False)
   store.acknowledge_fragments_before(path,metrics['fileOrdinal'],metrics['holdFrom'])
   if on_chunk is not None:on_chunk(path,store)
   processed_files+=1
   journal.write(compact(dict(path=str(path),sha256=sha,frames=expected,notice=notice,seconds=time.monotonic()-start,manifest=manifest))+'\n');journal.flush();os.fsync(journal.fileno())
   print(compact(dict(file=path.name,frames=expected,seconds=round(time.monotonic()-start,3),parse_seconds=round(parsed-start,3),sync_seconds=round(synced-parsed,3),export_seconds=round(exported-synced,3),baseline_seconds=round(time.monotonic()-exported,3))),flush=True)
  cap.close();cap=None;final_barrier(api,store,node,metrics['processed'] if processed_files else 0)
  export_tables(store,out/'final',True,node,after_rowid=watermark)
  summary=dict(node=node,files=processed_files,frames=frames,status='local_arkime_verified',pcaps_deleted=sum(not Path(row[0]).exists() for row in store.db.execute('select path from chunks')),cosmolake_uploads=0)
  (out/'result.json').write_text(compact(summary)+'\n');fsync_dir(out)
  return summary
 finally:
  if cap is not None:cap.close()
  store.close();journal.close();lock.close()

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--files',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 files=[Path(s) for s in a.files.read_text().splitlines() if s]
 if not files:raise SystemExit('empty manifest')
 print(compact(run(files,a.out)))
