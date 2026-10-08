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
        self.assertIn("single_verified_local_python_fixture", code)
        self.assertIn("insufficient_support", code)
        upload = next(step for step in steps if step.get("uses", "").startswith("actions/upload-artifact"))
        paths = str(upload["with"]["path"])
        self.assertIn("office-profile-report.json", paths)
        self.assertIn("benign-transfer-report.json", paths)
        self.assertNotIn(".pcap", paths)
        self.assertNotIn("*.key", paths)


if __name__ == "__main__":
    unittest.main()
