import unittest,sys,tempfile,socket,struct,json
from pathlib import Path
R=Path(__file__).resolve().parents[1];sys.path[:0]=[str(R/'tests'),str(R/'bin'),str(R.parent)]
from fixtures import HEADER,record,tcp,checksum
from test_capture import capture
class LifecycleReview(unittest.TestCase):
 def test_icmp_does_not_advance_canonical_sweep(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'mixed.pcap';a=socket.inet_aton('192.0.2.3');b=socket.inet_aton('198.51.100.3');icmp=b'\x08\x00\x00\x00'+b'fixture';ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(icmp),0,0,64,1,0,a,b);ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:];frame=bytes.fromhex('00112233445566778899aabb0800')+ip+icmp
   p.write_bytes(HEADER+record(1700000000,tcp('192.0.2.1','198.51.100.1',40000,443,100,0,2))+record(1700000061,frame)+record(1700000070,tcp('198.51.100.1','192.0.2.1',443,40000,200,101,18)))
   hits=capture(['-r',str(p)],'review-icmp')
   self.assertEqual(len({h['_source']['office']['instance'] for h in hits if h['_source'].get('ipProtocol')==6}),1)
 def test_eof_timeout_is_classified_between_sweeps(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'eof.pcap';p.write_bytes(HEADER+b''.join(record(1700000000+t,tcp('192.0.2.1','198.51.100.1',40000+flow,443,100,0,2)) for t,flow in [(0,0),(60,1),(65,1)]))
   hits=capture(['-r',str(p)],'review-eof')
   ended=[h['_source']['office'] for h in hits if h['_source']['source']['port']==40000 and h['_source']['office']['final']]
   self.assertTrue(ended);self.assertEqual(ended[-1]['endReason'],1)
class EmptyHostMinutes(unittest.TestCase):
 def test_empty_sessions_keep_nonempty_host_minutes(self):
  from convert_baseline import convert
  import office_to_parquet as original
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);batch=d/'batch';batch.mkdir();(batch/'batch.json').write_text(json.dumps({'sessions_written':0}));(batch/'office_sessions.csv').write_text(','.join(original.pinned_schema().names)+'\n');j=d/'journal';j.write_text('')
   values=['1700000000' if name=='minute_epoch' else 'fixture' if str(kind)=='string' else '1' for name,kind in original.HM_TYPES.items()]
   (batch/'office_host_minutes.csv').write_text(','.join(original.HM_TYPES)+'\n'+','.join(values)+'\n')
   manifest=convert(batch,d/'out','run','20261004T000000Z',[j],5,20)
   self.assertEqual(manifest['files']['office_host_minutes.parquet']['rows'],1)
class DurabilityReview(unittest.TestCase):
 def test_checkpoint_directory_is_fsynced_after_files(self):
  from durability import durable_directory
  import os
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);(d/'state.pkl').write_bytes(b'fixture');(d/'child').mkdir();(d/'child/carry.json').write_text('{}');order=[];real=os.fsync
   def observe(fd):
    order.append(Path('/proc/self/fd/'+str(fd)).resolve());real(fd)
   with patch('os.fsync',side_effect=observe):durable_directory(d)
   self.assertLess(order.index(d/'state.pkl'),order.index(d));self.assertLess(order.index(d/'child/carry.json'),order.index(d/'child'));self.assertLess(order.index(d/'child'),order.index(d))
