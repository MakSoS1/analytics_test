import unittest,sys,tempfile,json
from pathlib import Path
R=Path(__file__).resolve().parents[1];sys.path[:0]=[str(R/'bin'),str(R.parent)]
from convert_baseline import convert
import office_to_parquet
class EmptyBaseline(unittest.TestCase):
 def test_valid_empty_checkpoint_batch_produces_typed_zero_rows(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);batch=d/'batch';batch.mkdir();(batch/'batch.json').write_text(json.dumps({'sessions_written':0}))
   (batch/'office_sessions.csv').write_text(','.join(office_to_parquet.pinned_schema().names)+'\n')
   journal=d/'journal';journal.write_text('')
   manifest=convert(batch,d/'out','run','20261004T000000Z',[journal],5,20)
   self.assertEqual(manifest['office_sessions']['rows'],0)
