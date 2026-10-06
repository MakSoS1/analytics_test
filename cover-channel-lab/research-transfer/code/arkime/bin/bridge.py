"""Join session INSTANCES by the original hashed tuple and packet-time interval.
Never joins by a bare five tuple. Ambiguous and unmatched instances remain explicit.
"""
import csv,hashlib,ipaddress,json,sqlite3
from pathlib import Path
from pipeline import write_table,reduce_fragments,compact

def flow_key(a,ap,b,bp,proto):
 return compact([*sorted([(a,int(ap)),(b,int(bp))]),proto])

def build_bridge(store,baseline,out,index_paths=None):
 import pyarrow as pa
 baseline=Path(baseline);packet_salt=(baseline/'packet-salt').read_bytes().strip()
 mapping=sqlite3.connect(baseline/'bridge-index.db')
 mapping.executescript('drop table if exists canonical; create table if not exists canonical(flow text,uid text,begin real,end real); create index if not exists canonical_flow on canonical(flow,begin,end);')
 with mapping:
  def index_rows():
   for p in index_paths or [baseline/'session_index.csv']:
    with Path(p).open() as f:yield from csv.DictReader(f)
  for row in index_rows():
   uid=row['segment_uid'].rsplit('.',1)[0]
   mapping.execute('insert into canonical values(?,?,?,?)',(flow_key(row['ip_a'],row['port_a'],row['ip_b'],row['port_b'],row['proto']),uid,float(row['t_start'])*1000,float(row['t_end'])*1000))
 counts=dict(exact=0,ambiguous=0,unmatched=0,other_protocol=0)
 schema=pa.schema([('arkime_session_key',pa.string()),('office_session_uid',pa.string()),('status',pa.string()),('first_packet_ms',pa.int64()),('last_packet_ms',pa.int64()),('packets',pa.int64())])
 def rows():
  for (key,) in store.db.execute('select distinct session_key from fragments order by session_key'):
   fragments=store.db.execute('select source_json from fragments where session_key=?',(key,));first=json.loads(next(fragments)[0]);summary=reduce_fragments([first,*()])
   # Iterator avoids loading a long session into memory.
   summary=reduce_fragments(json.loads(x[0]) for x in store.db.execute('select source_json from fragments where session_key=?',(key,)))
   proto={6:'tcp',17:'udp'}.get(first.get('ipProtocol'));uid=None
   if proto is None:status='other_protocol'
   else:
    def hashed(addr):return hashlib.blake2s(ipaddress.ip_address(addr).packed,key=packet_salt,digest_size=8).hexdigest()
    src=first['source'];dst=first['destination'];flow=flow_key(hashed(src['ip']),src['port'],hashed(dst['ip']),dst['port'],proto)
    begin=summary['first_packet_ms'];end=summary['last_packet_ms']
    # Match the original beginning, then require the same ending. A capture
    # edge or unsupported IP fragmentation remains unmatched, not a false join.
    matches=mapping.execute('select uid from canonical where flow=? group by uid having abs(min(begin)-?)<=2 and abs(max(end)-?)<=2',(flow,begin,end)).fetchall()
    status='exact' if len(matches)==1 else 'ambiguous' if matches else 'unmatched'
    if status=='exact':uid=matches[0][0]
   counts[status]+=1
   yield dict(arkime_session_key=key,office_session_uid=uid,status=status,first_packet_ms=summary['first_packet_ms'],last_packet_ms=summary['last_packet_ms'],packets=summary['packets'])
 info=write_table(out,schema,rows());mapping.close();return dict(counts=counts,table=info)
