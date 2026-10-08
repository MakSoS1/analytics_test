import tempfile
import unittest
from pathlib import Path

from natural_traffic.contracts import ActivityDescriptor, GenerationContext
from natural_traffic.profiles import ProfileRegistry


class NaturalTrafficContractTests(unittest.TestCase):
    def test_manifest_is_deterministic_for_same_profiles_and_seed(self):
        registry = ProfileRegistry.default()
        first = registry.manifest(["linux-curl", "linux-python-ssl"], seed=17)
        second = registry.manifest(["linux-curl", "linux-python-ssl"], seed=17)
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(first.to_json(), second.to_json())

    def test_pair_contexts_share_environment_identity(self):
        registry = ProfileRegistry.default()
        profile = registry.resolve("linux-curl")
        with tempfile.TemporaryDirectory() as d:
            scenario = GenerationContext("pair-1", "scenario", profile, 9, Path(d) / "s")
            control = GenerationContext("pair-1", "control", profile, 9, Path(d) / "c")
        self.assertEqual(scenario.environment_identity(), control.environment_identity())

    def test_unknown_profile_is_rejected(self):
        with self.assertRaises(KeyError):
            ProfileRegistry.default().resolve("does-not-exist")

    def test_managed_descriptor_has_no_arbitrary_command_surface(self):
        fields = set(ActivityDescriptor.__dataclass_fields__)
        for forbidden in {"command", "shell", "exec", "argv", "script"}:
            self.assertNotIn(forbidden, fields)

    def test_initial_registry_contains_required_real_stack_families(self):
        registry = ProfileRegistry.default()
        expected = {
            "linux-python-ssl",
            "linux-curl",
            "linux-chromium",
            "linux-protocol-native",
            "windows-native-http",
        }
        self.assertTrue(expected.issubset(set(registry.ids())))


if __name__ == "__main__":
    unittest.main()
