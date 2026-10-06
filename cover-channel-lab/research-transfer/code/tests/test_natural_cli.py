import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from natural_traffic.cli import COMMANDS, load_frozen_manifest
from natural_traffic.contracts import FrozenProfileManifest
from natural_traffic.evaluation import ManifestIntegrityError
from natural_traffic.reporting import package_release, write_report


class NaturalCliTests(unittest.TestCase):
    def test_every_public_command_has_help(self):
        expected = {
            "validate-reference", "probe", "generate-benign", "calibrate",
            "confirm", "generate-scenarios", "evaluate-techniques",
            "compose", "package",
        }
        self.assertEqual(set(COMMANDS), expected)
        for command in sorted(expected):
            proc = subprocess.run(
                [sys.executable, "-m", "natural_traffic.cli", command, "--help"],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, (command, proc.stderr))
            self.assertIn("usage:", proc.stdout.lower())

    def test_report_json_is_deterministic_and_has_contract_fields(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a.json", Path(d) / "b.json"
            one = write_report(
                a, kind="naturalness", status="insufficient_data",
                support={"office_groups": 7, "control_groups": 6},
                payload={"z": 1, "a": {"y": 2}},
            )
            two = write_report(
                b, kind="naturalness", status="insufficient_data",
                support={"control_groups": 6, "office_groups": 7},
                payload={"a": {"y": 2}, "z": 1},
            )
            self.assertEqual(a.read_bytes(), b.read_bytes())
            body = json.loads(a.read_text())
            self.assertEqual(body["version"], "natural-report-v2")
            self.assertEqual(body["kind"], "naturalness")
            self.assertEqual(body["status"], "insufficient_data")
            self.assertEqual(body["support"]["office_groups"], 7)
            self.assertEqual(one, two)

    def test_release_package_excludes_plaintext_and_private_material(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            safe = root / "naturalness.json"; safe.write_text("{}")
            cipher = root / "dictionary.json.gpg"; cipher.write_text("cipher")
            public = root / "recipient-public-key.asc"; public.write_text("public")
            private = root / "PRIVATE-KEY.asc"; private.write_text("secret")
            plain = root / "dictionary.json"; plain.write_text("plaintext")
            hmac = root / "hmac-key.txt"; hmac.write_text("secret")
            report = package_release([safe, cipher, public, private, plain, hmac], root / "release")
            names = set(report["files"])
            self.assertEqual(names, {"dictionary.json.gpg", "naturalness.json", "recipient-public-key.asc"})
            self.assertFalse((root / "release" / "PRIVATE-KEY.asc").exists())
            self.assertFalse((root / "release" / "dictionary.json").exists())

    def test_frozen_manifest_hash_is_required_and_verified(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "frozen.json"
            manifest = FrozenProfileManifest(
                seed=7, profile_weights=(("linux-curl", 1.0),), reference_id="r",
            )
            path.write_text(manifest.to_json())
            loaded = load_frozen_manifest(path, expected_sha=manifest.sha256)
            self.assertEqual(loaded.sha256, manifest.sha256)
            with self.assertRaises(ManifestIntegrityError):
                load_frozen_manifest(path, expected_sha="0" * 64)
            with self.assertRaises(FileNotFoundError):
                load_frozen_manifest(Path(d) / "missing.json", expected_sha=manifest.sha256)


if __name__ == "__main__":
    unittest.main()
