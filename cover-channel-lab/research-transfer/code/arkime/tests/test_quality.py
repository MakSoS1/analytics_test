import unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
from quality import capture_quality
class Quality(unittest.TestCase):
 def test_missing_counters_are_not_loss_free(self):self.assertFalse(capture_quality('','duration',124)['loss_free'])
 def test_kernel_loss_and_early_stop_are_visible(self):
  log='100 packets captured\n102 packets received by filter\n2 packets dropped by kernel\n'
  q=capture_quality(log,'sensor_disk_reserve',0);self.assertFalse(q['loss_free']);self.assertFalse(q['duration_completed'])
 def test_normal_timeout_is_valid(self):
  q=capture_quality('100 packets captured\n100 packets received by filter\n0 packets dropped by kernel\n','duration',124)
  self.assertTrue(q['loss_free']);self.assertTrue(q['duration_completed'])

 def test_source_count_must_match_processed_frames(self):
  q=capture_quality('100 packets captured\n100 packets received by filter\n0 packets dropped by kernel\n','duration',124,expected_frames=99)
  self.assertFalse(q['frames_reconciled'])
