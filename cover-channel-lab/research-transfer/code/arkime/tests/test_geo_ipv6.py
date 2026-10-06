import unittest,sys,tempfile,socket,struct
from pathlib import Path
R=Path(__file__).resolve().parents[1];sys.path[:0]=[str(R/'tests'),str(R/'bin')]
from fixtures import HEADER,record,checksum
from test_capture import capture
from test_lifecycle import udp
from pipeline import value_at,reduce_fragments

def tcp6(src,dst,sp,dp,flags,seq=100):
 a=socket.inet_pton(socket.AF_INET6,src);b=socket.inet_pton(socket.AF_INET6,dst);tcp=struct.pack('!HHIIBBHHH',sp,dp,seq,0,80,flags,65535,0,0)
 check=checksum(a+b+struct.pack('!I3xB',len(tcp),6)+tcp);tcp=tcp[:16]+struct.pack('!H',check)+tcp[18:]
 ip=struct.pack('!IHBB16s16s',6<<28,len(tcp),6,64,a,b)
 return bytes.fromhex('00112233445566778899aabb86dd')+ip+tcp
class GeoIPv6(unittest.TestCase):
 def test_city_asn_databases_are_used_offline(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'geo.pcap';p.write_bytes(HEADER+record(1700000000,udp('8.8.8.8','9.9.9.9',43000,43001)))
   hits=capture(['-r',str(p)],'test-geo')
   sources=[h['_source']['source'] for h in hits]
   self.assertTrue(any(value_at(s,'geo.country_iso_code',None) for s in sources));self.assertTrue(any(value_at(s,'as.number',None) for s in sources))
 def test_ipv6_bidirectional_session_across_files(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);a='2001:db8::1';b='2001:db8::2';paths=[]
   for i,(src,dst,sp,dp,flags,t) in enumerate([(a,b,45000,443,2,0),(b,a,443,45000,18,70),(a,b,45000,443,16,71)]):
    p=d/f'{i}.pcap';p.write_bytes(HEADER+record(1700000000+t,tcp6(src,dst,sp,dp,flags)));paths.append(str(p))
   listing=d/'files.txt';listing.write_text('\n'.join(paths)+'\n');hits=capture(['-F',str(listing)],'test-ipv6')
   self.assertEqual(len({h['_source']['office']['instance'] for h in hits}),1);self.assertEqual(reduce_fragments(h['_source'] for h in hits)['packets'],3)
