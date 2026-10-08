import sys,tempfile,unittest,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
from pipeline import Store,export_tables
class Cached(unittest.TestCase):
 def test_revision_replaces_counters_and_preserves_cumulative_entropy(self):
  import pyarrow.parquet as pq
  with tempfile.TemporaryDirectory() as d:
   s=Store(Path(d)/'db')
   def hit(n,p,final=False):return {'_index':'i','_id':str(n),'_source':{'node':'n','office':{'instance':1,'seq':n,'final':final,'startObserved':True,'endReason':int(final)},'network':{'packets':p},'firstPacket':n*10,'lastPacket':n*10+5,'officeEntropy':{'src':n/10}}}
   s.put_fragment(hit(1,2));s.put_fragment(hit(2,3,True));s.put_fragment(hit(1,4))
   export_tables(s,Path(d)/'out')
   row=pq.read_table(Path(d)/'out/arkime_sessions.parquet').to_pylist()[0]
   self.assertEqual(row['packets'],7);self.assertEqual(row['fragments'],2);self.assertEqual(row['entropy_src'],.2);self.assertTrue(row['complete'])
   self.assertEqual(s.packet_total(),7)
   self.assertFalse(s.put_fragment(hit(1,4)));self.assertEqual(s.packet_total(),7)
