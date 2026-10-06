import json
import tempfile
import unittest
from pathlib import Path

import pyarrow.parquet as pq

import office_to_parquet as otp

COLS = [["session_uid", "string"], ["segment_uid", "string"], ["session_start_epoch", "double"],
        ["flow_duration", "double"], ["pkt_count", "int64"], ["tls_ja4", "string"],
        ["seq_signed_len", "list<int32>"], ["seq_iat_us", "list<int64>"]]


class OfficeToParquetTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "schema.json").write_text(json.dumps({"columns": COLS}))
        (self.d / "b").mkdir()

    def write(self, rows, header=None):
        header = header or [c for c, _ in COLS]
        (self.d / "b" / "office_sessions.csv").write_text(
            ",".join(header) + "\n" + "\n".join(",".join(r) for r in rows) + "\n")

    def convert(self):
        return otp.convert(self.d / "b", self.d / "out", "run1", "20260923T161000Z", [], 20, None,
                           self.d / "schema.json")

    def test_types_keys_and_arrays(self):
        self.write([["s1", "s1#0", "1790000000.25", "2.5", "3", "", "60 -40 52", "0 100 2000"],
                    ["s2", "s2#0", "1790086400.0", "0.0", "1", "t13d", "70", "0"]])
        r = self.convert()
        self.assertEqual(r["office_sessions"]["rows"], 2)
        self.assertEqual(r["office_sessions"]["packets"], 4)
        t = pq.read_table(self.d / "out" / "office_sessions.parquet")
        row = t.to_pylist()[0]
        self.assertEqual(row["seq_signed_len"], [60, -40, 52])
        self.assertEqual(row["seq_iat_us"], [0, 100, 2000])
        self.assertIsNone(row["tls_ja4"])
        self.assertEqual(row["global_segment_uid"], "run1:s1#0")
        self.assertEqual(str(row["event_date"]), "2026-09-21")
        self.assertEqual(row["segment_end_ts"].timestamp() - row["segment_start_ts"].timestamp(), 2.5)
        self.assertEqual(str(t.to_pylist()[1]["event_date"]), "2026-09-22")
        self.assertEqual((row["seq_first_dir"], row["seq_last_dir"]), (1, 1))
        self.assertEqual(t.to_pylist()[1]["seq_last_dir"], 1)
        m = json.loads((self.d / "out" / "manifest.json").read_text())
        self.assertEqual(m["files"]["office_sessions.parquet"]["rows"], 2)

    def test_a_column_outside_the_schema_stops_the_batch(self):
        self.write([["s1", "s1#0", "1.0", "1.0", "1", "", "60", "0", "7"]],
                   header=[c for c, _ in COLS] + ["new_feature"])
        with self.assertRaisesRegex(ValueError, "new_feature"):
            self.convert()

    def test_a_fraction_in_an_integer_column_stops_the_batch(self):
        self.write([["s1", "s1#0", "1.0", "1.0", "1.5", "", "60", "0"]])
        with self.assertRaisesRegex(ValueError, "pkt_count"):
            self.convert()

    def test_duplicate_segments_stop_the_batch(self):
        self.write([["s1", "s1#0", "1.0", "1.0", "1", "", "60", "0"],
                    ["s1", "s1#0", "1.0", "1.0", "1", "", "60", "0"]])
        with self.assertRaisesRegex(ValueError, "own checks"):
            self.convert()

    def test_csv_is_read_in_multiple_bounded_batches(self):
        rows = [[f"s{i}", f"s{i}#0", str(1790000000 + i), "1.0", "2", "",
                 "60 -40", "0 100"] for i in range(30)]
        self.write(rows)
        chunks = list(otp.iter_sessions(self.d / "b" / "office_sessions.csv",
                                        otp.pinned_schema(self.d / "schema.json"),
                                        block_bytes=256))
        self.assertGreater(len(chunks), 1)
        self.assertEqual(sum(t.num_rows for t in chunks), 30)
        self.assertEqual(chunks[0]["seq_signed_len"][0].as_py(), [60, -40])


if __name__ == "__main__":
    unittest.main()
