import sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
from run_local import guard,pcap_count
from pipeline import Store,export_tables
class Guards(unittest.TestCase):
 def test_disk_reserve_stops_before_consumption(self):
  with patch('run_local.shutil.disk_usage',return_value=type('Usage',(),{'free':1})()):
   with self.assertRaises(RuntimeError):guard(Path('/tmp'))
 def test_truncated_pcap_is_rejected(self):
  import struct
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'bad.pcap';p.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+struct.pack('<IIII',1,0,80,80)+b'not enough')
   with self.assertRaises(ValueError):pcap_count(p)
 def test_failed_export_does_not_publish_directory_or_ack_pcap(self):
  with tempfile.TemporaryDirectory() as d:
   s=Store(Path(d)/'state');p=Path(d)/'input.pcap';p.write_bytes(b'fixture');s.register_chunk(p,'x',7)
   with patch('pipeline.write_table',side_effect=OSError('simulated disk full')):
    with self.assertRaises(OSError):export_tables(s,Path(d)/'out')
   self.assertFalse((Path(d)/'out').exists());self.assertFalse(s.can_delete(p));self.assertTrue(p.exists())
