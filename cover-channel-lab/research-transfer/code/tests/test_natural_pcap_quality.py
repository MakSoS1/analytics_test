import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from natural_traffic.pcap_quality import audit_pcap, filter_cover_captures_by_quality
from office_injection.source import write_pcap


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class PcapQualityTests(unittest.TestCase):
    def _capture(self, path, name):
        return SimpleNamespace(
            ancestor_id=name,
            bundle=SimpleNamespace(pcap_path=Path(path)),
        )

    def test_monotonic_capture_is_accepted_without_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"good.pcap"
            write_pcap(path, [(1.0,b"x"*60),(1.001,b"y"*60)])
            before=digest(path)
            report=audit_pcap(path)
            self.assertTrue(report.accepted)
            self.assertEqual(report.status,"accepted")
            self.assertEqual(report.max_timestamp_regression_us,0.0)
            self.assertEqual(before,digest(path))

    def test_bounded_33us_writer_jitter_is_accepted_but_reported(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"jitter.pcap"
            write_pcap(path,[
                (1.000000,b"a"*60),
                (1.001000,b"b"*60),
                (1.000967,b"c"*60),
                (1.002000,b"d"*60),
            ])
            report=audit_pcap(path,max_timestamp_regression_us=50)
            self.assertTrue(report.accepted)
            self.assertEqual(report.status,"accepted_with_writer_jitter")
            self.assertGreaterEqual(report.max_timestamp_regression_us,32.0)
            self.assertLessEqual(report.max_timestamp_regression_us,50.0)

    def test_56us_regression_is_rejected_not_normalized(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"bad56.pcap"
            write_pcap(path,[
                (1.000000,b"a"*60),
                (1.001000,b"b"*60),
                (1.000944,b"c"*60),
            ])
            before=path.read_bytes()
            report=audit_pcap(path,max_timestamp_regression_us=50)
            self.assertFalse(report.accepted)
            self.assertEqual(report.status,"rejected")
            self.assertGreater(report.max_timestamp_regression_us,50.0)
            self.assertEqual(before,path.read_bytes())

    def test_truncated_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"truncated.pcap"
            header=struct.pack("<IHHiIII",0xA1B2C3D4,2,4,0,0,262144,1)
            record=struct.pack("<IIII",1,0,60,80)+b"x"*60
            path.write_bytes(header+record)
            report=audit_pcap(path)
            self.assertFalse(report.accepted)
            self.assertGreater(report.truncated_record_count,0)

    def test_filter_keeps_order_and_rejects_bad_capture_before_downstream(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            good=root/"good.pcap"; bad=root/"bad.pcap"
            write_pcap(good,[(1.0,b"a"*60),(1.1,b"b"*60)])
            write_pcap(bad,[(1.0,b"a"*60),(1.1,b"b"*60),(1.099944,b"c"*60)])
            captures=[self._capture(good,"good"),self._capture(bad,"bad")]
            accepted,rejected=filter_cover_captures_by_quality(
                captures,max_timestamp_regression_us=50
            )
            self.assertEqual([c.ancestor_id for c in accepted],["good"])
            self.assertEqual([r["ancestor_id"] for r in rejected],["bad"])
            self.assertFalse(rejected[0]["quality"]["accepted"])


if __name__=="__main__":
    unittest.main()
