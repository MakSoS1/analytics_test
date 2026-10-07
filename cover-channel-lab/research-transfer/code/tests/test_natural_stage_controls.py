import importlib.util
import inspect
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGE_CONTROLS = ROOT / "cover_runtime" / "stage_controls.py"
ENTRYPOINT = ROOT / "cover_runtime" / "entrypoint.py"
spec = importlib.util.spec_from_file_location("natural_stage_controls", STAGE_CONTROLS)
stage_controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage_controls)


class StageControlBehaviorTests(unittest.TestCase):
    def test_behavior_targets_are_normalized_from_job_profile(self):
        job = {"profile": {
            "benign_request_bytes": 469,
            "benign_response_bytes": 445,
            "benign_sni_len": 23,
            "behavior_profile_sha256": "a" * 64,
            "target_clean_close": False,
        }}
        target = stage_controls.behavior_targets(job)
        self.assertEqual(target["request_bytes"], 469)
        self.assertEqual(target["response_bytes"], 445)
        self.assertEqual(target["sni_len"], 23)
        self.assertEqual(target["behavior_profile_sha256"], "a" * 64)
        self.assertFalse(target["target_clean_close"])

    def test_business_payload_uses_requested_application_size(self):
        import random
        for mode in ("high_entropy", "low_entropy", "fragment_2_6"):
            body = stage_controls.business_payload(
                random.Random(7), mode, 2, target_size=469
            )
            self.assertEqual(len(body), 469)
            self.assertIn(b"ok", body.lower())

    def test_install_accepts_job_and_entrypoint_passes_it(self):
        self.assertIn("job", inspect.signature(stage_controls.install).parameters)
        source = ENTRYPOINT.read_text()
        self.assertIn("control=install(sm,job)", source)
        self.assertIn("benign_response_bytes", source)
        self.assertIn("behavior_profile_sha256", source)


if __name__ == "__main__":
    unittest.main()
