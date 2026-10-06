import unittest,tempfile,sys,csv,subprocess,os
from pathlib import Path
R=Path(__file__).resolve().parents[1];sys.path[:0]=[str(R/'bin'),str(R/'tests'),str(R.parent)]
from fixtures import HEADER,record
from test_lifecycle import udp
from export_full_packets import export_with_payload
class RawIndex(unittest.TestCase):
 def test_coalesced_feature_times_do_not_change_raw_join_times(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);p=d/'fixture.pcap';p.write_bytes(HEADER+record(1700000000,udp('192.0.2.1','198.51.100.1',40000,443,b'x'*9000)))
   salt=b'fixture';rows=d/'fixture.pkts';pay=d/'fixture.pay'
   with rows.open('wb') as a,pay.open('wb') as b:export_with_payload(p,a,b,salt)
   index=d/'_session_index-0.csv'
   args=[sys.executable,str(R.parent/'extract_office_sessions.py'),'--pcap-dir',str(d),'--glob','*.pkts','--min-packets','1','--out-sessions',str(d/'sessions.csv'),'--out-lots-conns',str(d/'lots.csv'),'--session-index',str(index),'--finalize']
   result=subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
   self.assertEqual(result.returncode,0,result.stderr)
   with index.open() as f:published=list(csv.DictReader(f))[0]
   self.assertEqual(float(published['t_start']),1700000000);self.assertEqual(float(published['t_end']),1700000000)
   import extract_office_sessions as original
   split=original.split_coalesced_frames([dict(ts=1700000000,length=9042)])
   self.assertGreater(len(split),1);self.assertEqual({p['ts'] for p in split},{1700000000})
