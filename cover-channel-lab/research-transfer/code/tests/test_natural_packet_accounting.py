import unittest

from natural_traffic.packet_accounting import reconcile


class PacketAccountingTests(unittest.TestCase):
    def test_oversized_ethernet_frame_expands_without_faking_packets(self):
        out = reconcile(
            [1514, 1800, 2800], [5],
            {key: [5] for key in ("seq_signed_len", "seq_iat_us", "seq_flags")},
        )
        self.assertTrue(out["passed"])
        self.assertEqual(out["physical_frames"], 3)
        self.assertEqual(out["virtual_segments"], 5)
        self.assertEqual(out["added_segments"], 2)

    def test_wrong_packet_total_fails(self):
        out = reconcile(
            [200, 2800], [2],
            {key: [2] for key in ("seq_signed_len", "seq_iat_us", "seq_flags")},
        )
        self.assertFalse(out["passed"])

    def test_wrong_sequence_length_fails(self):
        out = reconcile(
            [100, 200], [2],
            {"seq_signed_len": [2], "seq_iat_us": [1], "seq_flags": [2]},
        )
        self.assertFalse(out["passed"])

    def test_missing_sequence_fails(self):
        out = reconcile([100], [1], {"seq_signed_len": [1]})
        self.assertFalse(out["passed"])

    def test_empty_capture_rejected(self):
        with self.assertRaises(ValueError):
            reconcile([], [1], {})


if __name__ == "__main__":
    unittest.main()
