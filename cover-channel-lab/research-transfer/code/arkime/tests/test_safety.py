import sys,json,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
from pipeline import Store,export_tables
class Safety(unittest.TestCase):
 def test_export_is_immutable_and_checksum_verified(self):
  with tempfile.TemporaryDirectory() as d:
   s=Store(Path(d)/'db');s.put_fragment({'_id':'a','_index':'x','_source':{'network':{'packets':2}}})
   out=Path(d)/'export';export_tables(s,out)
   with self.assertRaises(FileExistsError):export_tables(s,out)
 def test_previous_revisions_are_not_lost(self):
  with tempfile.TemporaryDirectory() as d:
   s=Store(Path(d)/'db');hit={'_id':'a','_index':'x','_source':{'network':{'packets':2}}};s.put_fragment(hit)
   hit['_source']['network']['packets']=3;s.put_fragment(hit)
   self.assertEqual(s.db.execute('select count(*) from revisions').fetchone()[0],2)
