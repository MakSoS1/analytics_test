import importlib.util
from pathlib import Path
import unittest


class SessionComparison(unittest.TestCase):
    def load(self):
        path = Path(__file__).resolve().parents[1] / 'compare_arkime_pipeline.py'
        spec = importlib.util.spec_from_file_location('comparison', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_segments_use_full_span_not_sum_of_durations(self):
        module = self.load()
        rows = [{'pkt_count': 2, 'total_bytes': 100, 'session_start_epoch': 1,
                 'flow_duration': 1, 'up_pkt_count': 1, 'down_pkt_count': 1,
                 'up_bytes': 50, 'down_bytes': 50},
                {'pkt_count': 3, 'total_bytes': 150, 'session_start_epoch': 10,
                 'flow_duration': 2, 'up_pkt_count': 2, 'down_pkt_count': 1,
                 'up_bytes': 100, 'down_bytes': 50}]
        summary = module.summarize(rows)
        self.assertEqual(summary['pkt_count'], 5)
        self.assertEqual(summary['duration_ms'], 11000)
        self.assertEqual(summary['segments'], 2)

    def test_direction_and_native_syn_ack_are_aligned(self):
        module = self.load()
        data = {'network.packets': 3, 'network.bytes': 180,
                'source.packets': 1, 'destination.packets': 2,
                'source.bytes': 60, 'destination.bytes': 120,
                'firstPacket': 1000, 'lastPacket': 2000,
                'tcpflags.syn': 1, 'tcpflags.syn-ack': 1, 'tcpflags.ack': 1}
        aligned = module.native_common(data, same_direction=False)
        self.assertEqual(aligned['up_pkt_count'], 2)
        self.assertEqual(aligned['down_pkt_count'], 1)
        self.assertEqual(aligned['syn_count'], 1)
        self.assertEqual(aligned['ack_count'], 1)
        self.assertEqual(aligned['duration_ms'], 1000)


if __name__ == '__main__':
    unittest.main()
