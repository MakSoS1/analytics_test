"""The defensive training research must have a consistent, honest index."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).parents[2]
DOCS = ROOT / "docs"


class ProjectDocumentationTests(unittest.TestCase):
    def test_status_index_references_existing_docs(self):
        text = (DOCS / "CURRENT_PROJECT_STATUS.md").read_text()
        for name in ("ADAPTIX_PAIRED_DETECTION_RESEARCH.md",
                     "VERIFIED_BENIGN_OFFICE_WORKLOAD.md",
                     "OFFICE_NATURALNESS_FEASIBILITY_2026-10-08.md",
                     "RESEARCH_CHANGELOG_2026.md",
                     "OFFICE_BENIGN_AND_TECHNIQUE_TRANSFER_RESULTS.md"):
            self.assertIn(name, text)
            self.assertTrue((DOCS / name).is_file(), name)
        self.assertIn("CURRENT_PROJECT_STATUS.md", (ROOT / "README.md").read_text())
        self.assertIn("CURRENT_PROJECT_STATUS.md", (ROOT.parents[1] / "README.md").read_text())

    def test_research_history_distinguishes_measured_from_unproven(self):
        text = (DOCS / "RESEARCH_CHANGELOG_2026.md").read_text()
        for run in ("37744156387", "37746123564", "37799244290", "37844041216"):
            self.assertIn(run, text)
        self.assertIn("naturalness_status=not_passed", text)
        self.assertIn("2026-10-09", text)
        self.assertIn("не доказ", text.lower())

    def test_no_production_claim_without_blind_labels(self):
        for name in ("CURRENT_PROJECT_STATUS.md", "OFFICE_BENIGN_AND_TECHNIQUE_TRANSFER_RESULTS.md"):
            text = (DOCS / name).read_text()
            self.assertIn("production_ready=false", text)
            self.assertIn("office_labels=unverified", text)
            self.assertRegex(text, r"(?i)неизвестн|неразмечен|unknown")
        self.assertIn("benign-transfer-report.json",
                      (DOCS / "VERIFIED_BENIGN_OFFICE_WORKLOAD.md").read_text())
        self.assertIn("extra_trees",
                      (DOCS / "ADAPTIX_PAIRED_DETECTION_RESEARCH.md").read_text())

    def test_current_project_links_resolve_locally(self):
        for document in (DOCS / "CURRENT_PROJECT_STATUS.md",
                         DOCS / "RESEARCH_CHANGELOG_2026.md",
                         DOCS / "OFFICE_BENIGN_AND_TECHNIQUE_TRANSFER_RESULTS.md"):
            for target in re.findall(r"\]\(([^)]+)\)", document.read_text()):
                if target.startswith(("http://", "https://", "#")):
                    continue
                self.assertTrue((document.parent / target.split("#", 1)[0]).is_file(),
                                f"{document.name}: broken link {target}")


if __name__ == "__main__":
    unittest.main()
