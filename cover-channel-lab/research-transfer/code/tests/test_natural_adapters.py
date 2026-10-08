import hashlib
import ipaddress
import json
import struct
import tempfile
import unittest
from pathlib import Path

from natural_traffic.adapters import (
    AdapterRegistry,
    CoverChannelAdapter,
    ExternalActivityAdapter,
)
from natural_traffic.profiles import ProfileRegistry
from office_injection.source import write_pcap


RUNTIME = Path(__file__).resolve().parents[1] / "cover_runtime"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _udp_frame(src: str, dst: str, payload: bytes, sport=41000, dport=443) -> bytes:
    src_raw = ipaddress.ip_address(src).packed
    dst_raw = ipaddress.ip_address(dst).packed
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    total = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17, 0, src_raw, dst_raw)
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + udp


def _external_spec(root: Path, *, inject_command=False) -> Path:
    src, dst = "10.40.0.11", "10.40.0.20"
    evidence = root / "receipt.json"
    evidence.write_text('{"observed": true}\n')
    arms = {}
    for role, offset in (("scenario", 0), ("control", 1)):
        pcap = root / f"{role}.pcap"
        write_pcap(
            pcap,
            [
                (10.0 + offset, _udp_frame(src, dst, b"a")),
                (10.1 + offset, _udp_frame(src, dst, b"b")),
            ],
        )
        arms[role] = {
            "pcap": pcap.name,
            "sha256": _sha(pcap),
            "source_ip": src,
            "description": f"{role} fixture",
            "evidence": [{"path": evidence.name, "sha256": _sha(evidence)}],
        }
    spec = {
        "activity_id": "external_https_like",
        "pair_id": "pair1",
        "capture_environment": "isolated",
        "arms": arms,
    }
    if inject_command:
        spec["command"] = "curl https://example.invalid"
    path = root / "activity.json"
    path.write_text(json.dumps(spec))
    return path


class AdapterRegistryTests(unittest.TestCase):
    def test_registry_is_explicit_and_unknown_adapter_is_rejected(self):
        registry = AdapterRegistry.default(runtime_root=RUNTIME)
        self.assertEqual(set(registry.names()), {"cover-channel", "external"})
        with self.assertRaises(KeyError):
            registry.get("does-not-exist")


class ExternalActivityAdapterTests(unittest.TestCase):
    def test_dataset_metadata_cannot_inject_executable_commands(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            spec = _external_spec(root, inject_command=True)
            with self.assertRaisesRegex(ValueError, "executable"):
                ExternalActivityAdapter().import_pair(spec, root / "out")

    def test_import_validates_hashes_and_preserves_external_origin(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            spec = _external_spec(root)
            bundles = ExternalActivityAdapter().import_pair(spec, root / "out")
            self.assertEqual({b.role for b in bundles}, {"scenario", "control"})
            self.assertEqual({b.fidelity for b in bundles}, {"external-observed-capture"})
            for bundle in bundles:
                meta = json.loads(bundle.runtime_metadata_path.read_text())
                self.assertEqual(meta["origin"], "external")
                self.assertEqual(meta["source_fidelity"], "external_observed_capture")
                self.assertEqual(meta["pair_id"], "external_https_like__pair1")

    def test_hash_mismatch_is_rejected_before_bundle_creation(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            spec = _external_spec(root)
            body = json.loads(spec.read_text())
            (root / body["arms"]["scenario"]["pcap"]).write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                ExternalActivityAdapter().import_pair(spec, root / "out")


class CoverChannelAdapterTests(unittest.TestCase):
    def setUp(self):
        self.profiles = ProfileRegistry.default()
        self.adapter = CoverChannelAdapter(RUNTIME, self.profiles)

    def test_current_scenario_id_and_source_pin_are_preserved(self):
        mapping = self.adapter.resolve("CC_BODY_01", "linux-curl")
        self.assertTrue(mapping.supported, mapping.reason)
        self.assertEqual(mapping.entry_id, "CC_BODY_01")
        self.assertTrue(mapping.source_path.endswith("scenarios.py"))
        self.assertRegex(mapping.source_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(mapping.protocol, "https")

    def test_semantic_fixture_remains_semantic_fixture(self):
        mapping = self.adapter.resolve("CC_CONNECT_02", "linux-curl")
        self.assertEqual(mapping.fidelity, "semantic_fixture")

    def test_real_protocol_families_require_declared_runtime_capability(self):
        cases = {
            "M-H3-QUIC": ("http3", "linux-protocol-native"),
            "M-GRPC-BIDI": ("grpc", "linux-protocol-native"),
            "M-WSS-LONG": ("wss", "linux-protocol-native"),
            "M-PUBSUB-MQTT": ("mqtt-wss", "linux-protocol-native"),
        }
        for entry_id, (protocol, profile_id) in cases.items():
            with self.subTest(entry_id=entry_id):
                supported = self.adapter.resolve(entry_id, profile_id)
                self.assertTrue(supported.supported, supported.reason)
                self.assertEqual(supported.protocol, protocol)
                self.assertTrue(self.profiles.resolve(profile_id).supports(protocol))
        unsupported = self.adapter.resolve("M-H3-QUIC", "linux-python-ssl")
        self.assertFalse(unsupported.supported)
        self.assertIn("does not support", unsupported.reason)

    def test_role_contexts_use_same_runtime_profile_identity(self):
        scenario = self.adapter.contexts("CC_BODY_01", "linux-curl", "pair-x", 4, Path("/tmp/x"))[0]
        control = self.adapter.contexts("CC_BODY_01", "linux-curl", "pair-x", 4, Path("/tmp/x"))[1]
        self.assertEqual({scenario.role, control.role}, {"scenario", "control"})
        self.assertEqual(scenario.environment_identity(), control.environment_identity())


if __name__ == "__main__":
    unittest.main()
