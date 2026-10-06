import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[4]
WORKFLOW = ROOT / ".github" / "workflows" / "natural-office-traffic-v2.yml"
TDD_WORKFLOW = ROOT / ".github" / "workflows" / "natural-traffic-tdd.yml"


class NaturalWorkflowContractTests(unittest.TestCase):
    def test_workflow_has_full_manual_pipeline_and_distinct_probes(self):
        self.assertTrue(WORKFLOW.is_file(), str(WORKFLOW))
        raw = WORKFLOW.read_text()
        body = yaml.safe_load(raw)
        jobs = body["jobs"]
        required = {
            "validate-reference-data", "unit-tests", "capture-probe-linux",
            "capture-probe-windows", "generate-benign-matrix",
            "calibrate-profile-mixture", "confirm-naturalness",
            "generate-cover-scenarios", "evaluate-technique-signal",
            "package-release",
        }
        self.assertEqual(set(jobs), required)
        self.assertIn("workflow_dispatch:", raw)
        self.assertIn("pull_request:", raw)
        self.assertEqual(jobs["capture-probe-linux"]["runs-on"], "ubuntu-latest")
        self.assertEqual(jobs["capture-probe-windows"]["runs-on"], "windows-latest")

    def test_expensive_jobs_are_manual_only_and_scenarios_depend_on_confirmation(self):
        raw = WORKFLOW.read_text()
        body = yaml.safe_load(raw)
        jobs = body["jobs"]
        expensive = {
            "capture-probe-linux", "capture-probe-windows", "generate-benign-matrix",
            "calibrate-profile-mixture", "confirm-naturalness",
            "generate-cover-scenarios", "evaluate-technique-signal", "package-release",
        }
        for name in expensive:
            condition = str(jobs[name].get("if", ""))
            self.assertIn("workflow_dispatch", condition, name)
        needs = jobs["generate-cover-scenarios"]["needs"]
        if isinstance(needs, str):
            needs = [needs]
        self.assertIn("confirm-naturalness", needs)
        self.assertIn("calibrate-profile-mixture", needs)

    def test_capture_jobs_guard_resources_and_upload_before_cleanup(self):
        raw = WORKFLOW.read_text()
        body = yaml.safe_load(raw)
        for name in ("generate-benign-matrix", "generate-cover-scenarios"):
            steps = body["jobs"][name]["steps"]
            labels = [step.get("name", "") for step in steps]
            joined = "\n".join(step.get("run", "") for step in steps)
            self.assertIn("Guard runner disk", labels, name)
            self.assertIn("ensure_resource_budget", joined, name)
            upload_index = next(i for i,s in enumerate(steps) if str(s.get("uses", "")).startswith("actions/upload-artifact"))
            cleanup_index = next(i for i,s in enumerate(steps) if s.get("name") == "Cleanup scratch")
            self.assertLess(upload_index, cleanup_index, name)

    def test_real_capture_flag_is_isolated_to_real_capture_job(self):
        body = yaml.safe_load(TDD_WORKFLOW.read_text())
        natural_steps = body["jobs"]["natural-unit"]["steps"]
        real_steps = body["jobs"]["real-capture-smoke"]["steps"]
        natural_env = {
            key: value
            for step in natural_steps
            for key, value in (step.get("env") or {}).items()
        }
        real_env = {
            key: value
            for step in real_steps
            for key, value in (step.get("env") or {}).items()
        }
        self.assertNotIn("NATURAL_TRAFFIC_REAL_CAPTURE", natural_env)
        self.assertEqual(str(real_env.get("NATURAL_TRAFFIC_REAL_CAPTURE")), "1")

    def test_pr_path_only_runs_reference_validation_and_unit_tests(self):
        raw = WORKFLOW.read_text()
        body = yaml.safe_load(raw)
        for name in ("validate-reference-data", "unit-tests"):
            condition = str(body["jobs"][name].get("if", ""))
            self.assertTrue("pull_request" in condition or condition == "", name)
        for name in set(body["jobs"]) - {"validate-reference-data", "unit-tests"}:
            self.assertIn("workflow_dispatch", str(body["jobs"][name].get("if", "")), name)


if __name__ == "__main__":
    unittest.main()