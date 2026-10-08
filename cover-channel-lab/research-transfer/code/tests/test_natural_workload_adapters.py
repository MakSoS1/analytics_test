"""Application activity adapters are vetted local functions, not manifest commands."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from natural_traffic.workload_adapters import register_benign_adapter, run_benign_adapter


class BenignWorkloadAdaptersTests(unittest.TestCase):
    def test_verified_local_https_adapter_executes_real_semantic_tasks(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "fixture"
            result = run_benign_adapter("verified_local_https", out, sessions=2, seed=12)
            self.assertEqual(result["tasks_completed"], 8)
            self.assertEqual(result["client_stack"], "python_stdlib_https")
            self.assertTrue(result["tls_peer_verified"])
            self.assertEqual(result["capabilities"]["real_browser_verified"], False)
            self.assertEqual(result["capabilities"]["cloud_sync_verified"], False)
            self.assertEqual(result["capabilities"]["verified_document_read_edit"], True)
            self.assertFalse(result["production_ready"])
            self.assertEqual(result["naturalness_status"], "not_passed")
            self.assertEqual(json.loads((out / "adapter_receipt.json").read_text()), result)

    def test_unknown_or_injected_entrypoint_is_refused_without_executing(self):
        with TemporaryDirectory() as tmp:
            for name in ("unknown_adapter", "os.system", "python -c 'print(123)'", "../unsafe"):
                with self.subTest(name=name):
                    with self.assertRaisesRegex(ValueError, "adapter"):
                        run_benign_adapter(name, Path(tmp) / "not-created", sessions=1, seed=1)
            self.assertFalse((Path(tmp) / "not-created").exists())

    def test_existing_fixture_is_never_overwritten(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "fixture"
            out.mkdir()
            marker = out / "readme.txt"
            marker.write_text("user data")
            with self.assertRaises(FileExistsError):
                run_benign_adapter("verified_local_https", out, sessions=1, seed=1)
            self.assertEqual(marker.read_text(), "user data")

    def test_registration_is_explicit_local_code_and_cannot_override_builtin(self):
        def safe_runner(out, *, sessions, seed):
            out.mkdir()
            return {"client_stack": "local_test_only", "tasks_completed": 1,
                    "tls_peer_verified": True, "source": "isolated_disposable_local_fixture",
                    "naturalness_status": "not_passed", "training_eligible": False,
                    "production_ready": False}

        register_benign_adapter("test_local_callable", safe_runner)
        with TemporaryDirectory() as tmp:
            result = run_benign_adapter("test_local_callable", Path(tmp) / "out",
                                        sessions=1, seed=1)
            self.assertEqual(result["adapter_name"], "test_local_callable")
            self.assertFalse(result["production_ready"])
        with self.assertRaisesRegex(ValueError, "registered"):
            register_benign_adapter("verified_local_https", safe_runner)
        with self.assertRaisesRegex(ValueError, "adapter"):
            register_benign_adapter("__import__('os')", safe_runner)


if __name__ == "__main__":
    unittest.main()
