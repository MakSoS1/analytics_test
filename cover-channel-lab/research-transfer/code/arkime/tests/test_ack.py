import sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
from pipeline import Store
class Ack(unittest.TestCase):
 def test_bulk_out_of_order_never_skips_hole(self):
  with tempfile.TemporaryDirectory() as d:
   s=Store(Path(d)/'db')
   for seq in [1,3]:s.put_fragment({'_index':'x','_id':str(seq),'_source':{'office':{'seq':seq,'instance':1},'node':'n'}})
   self.assertEqual(s.contiguous_sequence(),1)
   s.put_fragment({'_index':'x','_id':'2','_source':{'office':{'seq':2,'instance':1},'node':'n'}})
   self.assertEqual(s.contiguous_sequence(),3)
