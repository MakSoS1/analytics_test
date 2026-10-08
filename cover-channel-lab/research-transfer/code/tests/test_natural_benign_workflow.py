"""A physical benign office fixture must feed independent, cautious reports."""

from pathlib import Path
import unittest

import yaml


WORKFLOW = Path(__file__).parents[4] / ".github/workflows/natural-traffic-tdd.yml"


class BenignWorkflowTests(unittest.TestCase):
    def test_new_research_branch_triggers_workflow(self):
        data = yaml.safe_load(WORKFLOW.read_text())
        self.assertIn("office-benign-adaptix-transfer-2026-10-09",
                      str(data.get("on", data.get(True, {}))))

    def test_real_extractor_gates_office_comparison_and_safe_artifacts(self):
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["verified-benign-office-workload"]["steps"]
        extraction = next(i for i, step in enumerate(steps)
                          if "Verify PCAP integrity and production feature extraction"
                          in step.get("name", ""))
        transfer = next(i for i, step in enumerate(steps)
                        if "Run office-profile and benign transfer audits" in step.get("name", ""))
        self.assertLess(extraction, transfer)
        code = steps[transfer]["run"]
        self.assertIn("natural_traffic.office_profile_audit", code)
        self.assertIn("evaluate_benign_transfer", code)
        self.assertIn("OFFICE_COMPARABLE_TRANSPORT_FEATURES", code)
        self.assertIn("single_verified_local_python_fixture", code)
        self.assertIn("insufficient_support", code)
        upload = next(step for step in steps if step.get("uses", "").startswith("actions/upload-artifact"))
        paths = str(upload["with"]["path"])
        self.assertIn("office-profile-report.json", paths)
        self.assertIn("benign-transfer-report.json", paths)
        self.assertNotIn(".pcap", paths)
        self.assertNotIn("*.key", paths)

    def test_legacy_benign_matrix_must_not_publish_raw_captures(self):
        jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
        steps = jobs["generated-benign-e2e"]["steps"]
        upload = next(step for step in steps
                      if step.get("name", "") == "Upload generated benign E2E evidence")
        paths = str(upload["with"]["path"])
        for forbidden in ("capture.pcap", "natural-control-run", "controls.parquet",
                          "${{ runner.temp }}/natural-e2e\n", "*.log", "/retimed/"):
            self.assertNotIn(forbidden, paths)
        for required in ("/naturalness.json", "/additional_day_control_transfer.json",
                         "/release_gate.json"):
            self.assertIn(required, paths)


if __name__ == "__main__":
    unittest.main()
