import unittest
from pathlib import Path

from natural_traffic.cli import COMMANDS


ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"


class NaturalTrafficDocumentationTests(unittest.TestCase):
    def test_v2_guide_exists_and_documents_every_public_command(self):
        guide = DOCS / "NATURAL_TRAFFIC_GENERATOR_V2.md"
        self.assertTrue(guide.is_file())
        text = guide.read_text()
        for command in COMMANDS:
            self.assertIn(f"natural_traffic.cli {command}", text)

    def test_readme_links_v2_guide_and_never_claims_production_ready(self):
        text = (ROOT / "README.md").read_text()
        self.assertIn("NATURAL_TRAFFIC_GENERATOR_V2.md", text)
        self.assertIn("production_ready=false", text)
        self.assertNotIn("production_ready=true", text)

    def test_running_uses_spec_disk_floor_and_mentions_real_capture_gate(self):
        text = (DOCS / "RUNNING.md").read_text()
        self.assertIn("15 ГиБ", text)
        self.assertIn("real-capture", text.lower())
        self.assertNotIn("проверяет свободное место (20 ГиБ)", text)

    def test_universal_import_distinguishes_external_from_managed_generation(self):
        text = (DOCS / "UNIVERSAL_IMPORT.md").read_text()
        self.assertIn("ExternalActivityAdapter", text)
        self.assertIn("CoverChannelAdapter", text)
        self.assertIn("frozen_profile_manifest", text)
        self.assertIn("passed_candidate", text)
        self.assertIn("production", text.lower())

    def test_docs_do_not_label_all_office_rows_benign(self):
        for path in [
            ROOT / "README.md",
            DOCS / "RUNNING.md",
            DOCS / "UNIVERSAL_IMPORT.md",
        ]:
            text = path.read_text().lower()
            self.assertNotIn("весь офис считается benign", text)
            self.assertNotIn("all office traffic is benign", text)


if __name__ == "__main__":
    unittest.main()
