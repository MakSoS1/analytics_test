import sys,tempfile,unittest,socket,struct
from pathlib import Path
from collections import Counter
from unittest.mock import patch
R=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(R/'tests'),str(R.parent),str(R/'bin')]
from fixtures import tcp,HEADER,record,checksum
from test_capture import capture
from pipeline import reduce_fragments
import extract_office_sessions as office

def udp(src,dst,sp,dp,payload=b'hello'):
 a=socket.inet_aton(src);b=socket.inet_aton(dst);h=struct.pack('!HHHH',sp,dp,8+len(payload),0)
 ip=struct.pack('!BBHHHBBH4s4s',69,0,28+len(payload),0,0,64,17,0,a,b);ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
 return bytes.fromhex('00112233445566778899aabb0800')+ip+h+payload

class Lifecycle(unittest.TestCase):
 def compare(self,events):
  parsed=[]
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'cases.pcap'
   with p.open('wb') as f:
    f.write(HEADER)
    for t,rev,flags,proto,flow in events:
     src,dst=('192.0.2.1','198.51.100.1') if not rev else ('198.51.100.1','192.0.2.1')
     sp,dp=(40000+flow,443) if not rev else (443,40000+flow)
     frame=tcp(src,dst,sp,dp,100,0,flags) if proto=='tcp' else udp(src,dst,sp,dp)
     f.write(record(1700000000+t,frame))
     fl=''.join(c for mask,c in [(1,'F'),(2,'S'),(4,'R'),(16,'.')] if flags&mask) if proto=='tcp' else ''
     parsed.append(dict(ts=1700000000+t,src=src,dst=dst,sport=sp,dport=dp,length=len(frame),payload=0,flags=fl,proto=proto))
   with patch.object(office,'iter_parsed',return_value=iter(parsed)),patch.object(office,'_build_row',side_effect=lambda s,*args:len(s.ts)):
    expected=sorted(office.session_rows([p],b'test',0,1,Counter(),None))
   hits=capture(['-r',str(p)],'lifecycle')
   groups={}
   for h in hits:
    key=h['_source']['office']['instance'];groups.setdefault(key,[]).append(h['_source'])
   actual=sorted(reduce_fragments(fs)['packets'] for fs in groups.values())
   self.assertEqual(actual,expected)
 def test_tcp_thresholds(self):
  for gap in [60,60.000001,70,600,600.000001]:
   with self.subTest(gap=gap):self.compare([(0,False,2,'tcp',0),(gap,False,2,'tcp',0)])
 def test_bidirection_promotion_before_timeout(self):
  self.compare([(0,False,2,'tcp',0),(70,True,18,'tcp',0),(71,False,16,'tcp',0)])
 def test_tcp_both_fin_and_reopen(self):
  self.compare([(0,False,2,'tcp',0),(1,True,18,'tcp',0),(2,False,17,'tcp',0),(3,False,17,'tcp',0),(4,False,2,'tcp',0),(5,True,17,'tcp',0),(6,False,2,'tcp',0)])
 def test_rst_closed_timeout(self):
  self.compare([(0,False,2,'tcp',0),(1,True,20,'tcp',0),(11,False,16,'tcp',0),(22,False,16,'tcp',0)])
 def test_sweep_other_tuple(self):
  self.compare([(0,False,2,'tcp',0),(61,False,2,'tcp',1),(62,False,2,'tcp',0)])
 def test_udp_thresholds_and_promotion(self):
  for gap,reverse in [(30,False),(30.000001,False),(50,True),(300,True),(300.000001,True)]:
   with self.subTest(gap=gap,reverse=reverse):self.compare([(0,False,0,'udp',0),(gap,reverse,0,'udp',0)])
