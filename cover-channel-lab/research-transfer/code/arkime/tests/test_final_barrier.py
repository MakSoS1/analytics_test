import unittest,sys,tempfile
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parents[1];sys.path.insert(0,str(R/'bin'))
from pipeline import Store
import run_local
class FinalBarrier(unittest.TestCase):
 def test_missing_final_marker_is_not_a_success(self):
  with tempfile.TemporaryDirectory() as d:
   s=Store(Path(d)/'db');s.put_fragment({'_index':'x','_id':'a','_source':{'node':'n','office':{'instance':1,'seq':1,'final':False},'network':{'packets':1}}})
   with patch.object(run_local,'sync'):
    with self.assertRaises(RuntimeError):run_local.final_barrier(None,s,'n',1,attempts=1)
   s.put_fragment({'_index':'x','_id':'b','_source':{'node':'n','office':{'instance':1,'seq':2,'final':True},'network':{'packets':0}}})
   with patch.object(run_local,'sync'):run_local.final_barrier(None,s,'n',1,attempts=1)
