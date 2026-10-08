import unittest,sys,tempfile,socket,struct,json
from pathlib import Path
R=Path(__file__).resolve().parents[1];sys.path[:0]=[str(R/'bin'),str(R/'tests')]
from pipeline import Store
from run_local import Capture
from fixtures import HEADER,record,checksum
class FragmentHold(unittest.TestCase):
 def test_pending_fragment_file_cannot_be_acknowledged_early(self):
  with tempfile.TemporaryDirectory() as d:
   s=Store(Path(d)/'db');a=Path(d)/'a';b=Path(d)/'b'
   for p in [a,b]:p.write_bytes(b'x');s.register_chunk(p,'x',1);s.commit_chunk(p,1,True,False)
   s.acknowledge_fragments_before(a,1,1);self.assertFalse(s.can_delete(a))
   s.acknowledge_fragments_before(b,2,3);self.assertTrue(s.can_delete(a));self.assertTrue(s.can_delete(b))
 def test_native_reassembly_barrier_across_two_files(self):
  with tempfile.TemporaryDirectory(dir=R/'tests') as d:
   d=Path(d);src=socket.inet_aton('192.0.2.1');dst=socket.inet_aton('198.51.100.1');data=struct.pack('!HHHH',41000,41001,72,0)+b'x'*64;paths=[]
   for i,(body,offset) in enumerate([(data[:24],0x2000),(data[24:],3)]):
    ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(body),77,offset,64,17,0,src,dst);ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    frame=bytes.fromhex('00112233445566778899aabb0800')+ip+body;p=d/f'{i}.pcap';p.write_bytes(HEADER+record(1700000000+i*.001,frame));paths.append(p)
   cap=Capture(d,'frag-hold-test')
   try:
    notices=[cap.add(p) for p in paths]
    metrics=[{k:int(v) for k,v in (x.split('=',1) for x in line.split() if '=' in x) if k!='filename'} for line in notices]
    self.assertEqual(metrics[0]['holdFrom'],1);self.assertEqual(metrics[0]['processed'],0)
    self.assertEqual(metrics[1]['holdFrom'],3);self.assertEqual(metrics[1]['processed'],1);self.assertEqual(metrics[1]['fragmentPackets'],2);self.assertEqual(metrics[1]['reassembled'],1)
   finally:cap.close()
