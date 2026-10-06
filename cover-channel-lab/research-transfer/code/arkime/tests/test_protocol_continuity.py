import sys,json,tempfile,unittest
from pathlib import Path
R=Path(__file__).resolve().parents[1];sys.path[:0]=[str(R/'tests'),str(R/'bin')]
from fixtures import tcp,record,HEADER,long_session
from test_capture import capture
from pipeline import flatten,reduce_fragments
class ProtocolContinuity(unittest.TestCase):
 maxDiff=None
 def test_http_header_body_split_and_entropy_are_preserved(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);a='192.0.2.2';b='198.51.100.2';request=b'GET /split?x=one HTTP/1.1\r\nHost: allfields.example\r\nX-Custom: preserved\r\nCookie: token=sample\r\n\r\n'
   events=[tcp(a,b,41000,80,1000,0,2),tcp(b,a,80,41000,2000,1001,18),tcp(a,b,41000,80,1001,2001,16),tcp(a,b,41000,80,1001,2001,24,request[:35]),tcp(a,b,41000,80,1036,2001,24,request[35:]),tcp(b,a,80,41000,2001,1001+len(request),24,b'HTTP/1.1 200 OK\r\nX-Reply: intact\r\nContent-Length: 5\r\n\r\nhello')]
   chunks=[events[:4],events[4:]];whole=d/'whole.pcap'
   with whole.open('wb') as f:
    f.write(HEADER)
    for i,p in enumerate(events):f.write(record(1700000000+i*.001,p))
   paths=[];offset=0
   for i,ps in enumerate(chunks):
    path=d/f'{i}.pcap';paths.append(str(path))
    with path.open('wb') as f:
     f.write(HEADER)
     for j,p in enumerate(ps):f.write(record(1700000000+(offset+j)*.001,p))
    offset+=len(ps)
   listing=d/'files.txt';listing.write_text('\n'.join(paths)+'\n')
   split=capture(['-F',str(listing)],'test-http-split');single=capture(['-r',str(whole)],'test-http-whole')
   def fields(hits):
    values={}
    for h in hits:
     for key,value in flatten(h['_source']):
      if key.startswith(('http.','httpRequest.','httpResponse.')) and not key.endswith('Cnt'):
       if isinstance(value,list):
        values.setdefault(key,set()).update(json.dumps(x,sort_keys=True) for x in value)
       else:values.setdefault(key,set()).add(json.dumps(value,sort_keys=True))
    return values
   self.assertEqual(fields(split),fields(single));self.assertIn('allfields.example',json.dumps(fields(split),default=list))
   rs=reduce_fragments(h['_source'] for h in split);rw=reduce_fragments(h['_source'] for h in single)
   self.assertAlmostEqual(rs['entropy_src'],rw['entropy_src'],places=5);self.assertAlmostEqual(rs['entropy_dst'],rw['entropy_dst'],places=5)
 def test_two_hour_more_than_original_segment_cap(self):
  root=R/'tests/generated/two-hour'
  if not (root/'expected.json').exists():long_session(root,180000,7200)
  hits=capture(['-F',str(root/'files.txt')],'test-two-hour')
  self.assertEqual(len({h['_source']['office']['instance'] for h in hits}),1)
  summary=reduce_fragments(h['_source'] for h in hits)
  self.assertEqual(summary['packets'],360005);self.assertEqual(summary['duration_ms'],7200001)

 def test_seven_day_packet_clock_session(self):
  root=R/'tests/generated/seven-day'
  if not (root/'expected.json').exists():long_session(root,2016,604800,bucket_seconds=900)
  hits=capture(['-F',str(root/'files.txt')],'test-seven-day')
  self.assertEqual(len({h['_source']['office']['instance'] for h in hits}),1)
  summary=reduce_fragments(h['_source'] for h in hits)
  self.assertEqual(summary['packets'],4037);self.assertEqual(summary['duration_ms'],604800001)
