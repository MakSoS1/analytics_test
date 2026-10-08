"""Black-box checks for authorized, fixture-only office actions."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from natural_traffic.office_workload import run_benign_office_workload


class BenignOfficeWorkloadTests(unittest.TestCase):
    def test_real_tls_tasks_preserve_application_causality(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            report = run_benign_office_workload(
                out, sessions=2, seed=13, action_pause_seconds=0,
            )
            self.assertEqual(report["sessions_completed"], 2)
            self.assertEqual(report["tasks_completed"], 8)
            self.assertEqual(report["actions_completed"], 16)
            self.assertTrue(report["tls_peer_verified"])
            self.assertTrue(report["document_versions_verified"])
            self.assertTrue(report["download_integrity_verified"])
            self.assertEqual(report["capture_status"], "not_requested")
            self.assertEqual(report["naturalness_status"], "not_passed")
            self.assertFalse(report["production_ready"])
            self.assertEqual(report["client_stack"], "python_stdlib_https")
            receipt = json.loads((out / "workload_receipt.json").read_text())
            self.assertEqual(receipt, report)
            self.assertFalse(any(
                name.endswith((".pem", ".key", ".crt")) for name in
                (p.name for p in out.rglob("*"))
            ))

    def test_refuses_unbounded_or_invalid_sessions(self):
        with TemporaryDirectory() as tmp:
            for count in (0, -1, 10001):
                with self.subTest(count=count):
                    with self.assertRaisesRegex(ValueError, "sessions"):
                        run_benign_office_workload(Path(tmp) / "bad", sessions=count)

    def test_refuses_overwrite_of_existing_corpus(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "existing"
            out.mkdir()
            (out / "workload_receipt.json").write_text("untouched")
            with self.assertRaises(FileExistsError):
                run_benign_office_workload(out)
            self.assertEqual((out / "workload_receipt.json").read_text(), "untouched")


if __name__ == "__main__":
    unittest.main()
