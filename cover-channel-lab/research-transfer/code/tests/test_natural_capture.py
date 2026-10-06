import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from natural_traffic.capture import (
    CapabilityReport,
    CaptureIntegrityError,
    CaptureSpec,
    ResourceBudgetError,
    assert_extraction_input,
    ensure_resource_budget,
    ensure_scratch_budget,
    probe_capability,
    run_capture,
    verify_capture_bundle,
)
from natural_traffic.contracts import GenerationContext
from natural_traffic.profiles import ProfileRegistry
from office_injection.source import read_pcap, write_pcap


class FixtureAdapter:
    adapter_id = "fixture"

    def capture_spec(self, context):
        return CaptureSpec(interface="lo", transport="tcp", port=443)

    def execute(self, context):
        return {"ok": True, "role": context.role}


class FixtureBackend:
    def capture(self, profile, adapter, context, output_dir):
        pcap = output_dir / "capture.pcap"
        write_pcap(
            pcap,
            [
                (1.0, b"\x00" * 12 + b"\x08\x00" + b"x" * 46),
                (1.1, b"\x00" * 12 + b"\x08\x00" + b"y" * 46),
            ],
        )
        evidence = output_dir / "execution.json"
        evidence.write_text(json.dumps(adapter.execute(context), sort_keys=True))
        return pcap, (evidence,), {"backend": "fixture"}


class FailingBackend:
    def capture(self, profile, adapter, context, output_dir):
        raise RuntimeError("intentional fixture failure")


class NaturalCaptureUnitTests(unittest.TestCase):
    def setUp(self):
        self.registry = ProfileRegistry.default()
        self.profile = self.registry.resolve("linux-curl")
        self.capability = CapabilityReport(
            profile_id=self.profile.profile_id,
            supported=True,
            capture_type="fixture",
            reason="unit fixture",
            details={"test": True},
        )

    def context(self, root, role="control"):
        return GenerationContext("pair-1", role, self.profile, 7, Path(root) / role)

    def test_resource_guard_refuses_less_than_fifteen_gib_free(self):
        fake = lambda _: SimpleNamespace(free=14 * 2**30)
        with self.assertRaises(ResourceBudgetError):
            ensure_resource_budget(Path("."), min_free_gib=15, disk_usage_fn=fake)

    def test_scratch_cap_is_enforced_per_shard(self):
        with self.assertRaises(ResourceBudgetError):
            ensure_scratch_budget(Path("."), cap_gib=2, usage_bytes_fn=lambda _: 2 * 2**30 + 1)
        ensure_scratch_budget(Path("."), cap_gib=2, usage_bytes_fn=lambda _: 1024)

    def test_windows_profile_never_falls_back_to_linux(self):
        windows = self.registry.resolve("windows-native-http")
        report = probe_capability(windows, system_name="Linux")
        self.assertFalse(report.supported)
        self.assertEqual(report.profile_id, "windows-native-http")
        self.assertIn("Windows", report.reason)

    def test_failed_run_retains_machine_readable_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self.context(d)
            with self.assertRaisesRegex(RuntimeError, "intentional fixture"):
                run_capture(
                    self.profile, FixtureAdapter(), ctx,
                    backend=FailingBackend(), capability=self.capability,
                    min_free_gib=0,
                )
            manifest = json.loads((ctx.output_dir / "run_manifest.json").read_text())
            self.assertEqual(manifest["status"], "failed")
            self.assertIn("intentional fixture failure", manifest["error"])
            self.assertEqual(manifest["profile_id"], "linux-curl")

    def test_capture_bytes_are_pinned_and_modified_bytes_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self.context(d)
            bundle = run_capture(
                self.profile, FixtureAdapter(), ctx,
                backend=FixtureBackend(), capability=self.capability,
                min_free_gib=0,
            )
            self.assertTrue(verify_capture_bundle(bundle))
            with bundle.pcap_path.open("ab") as fh:
                fh.write(b"tamper")
            with self.assertRaises(CaptureIntegrityError):
                verify_capture_bundle(bundle)

    def test_extraction_input_must_match_pinned_capture_hash(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self.context(d)
            bundle = run_capture(
                self.profile, FixtureAdapter(), ctx,
                backend=FixtureBackend(), capability=self.capability,
                min_free_gib=0,
            )
            clone = Path(d) / "clone.pcap"
            shutil.copyfile(bundle.pcap_path, clone)
            self.assertTrue(assert_extraction_input(bundle, clone))
            with clone.open("ab") as fh:
                fh.write(b"changed")
            with self.assertRaises(CaptureIntegrityError):
                assert_extraction_input(bundle, clone)

    def test_scenario_and_control_manifests_share_environment_identity(self):
        with tempfile.TemporaryDirectory() as d:
            bundles = []
            for role in ("scenario", "control"):
                ctx = self.context(d, role)
                bundles.append(
                    run_capture(
                        self.profile, FixtureAdapter(), ctx,
                        backend=FixtureBackend(), capability=self.capability,
                        min_free_gib=0,
                    )
                )
            metas = [json.loads(b.runtime_metadata_path.read_text()) for b in bundles]
            self.assertEqual(metas[0]["environment_identity_sha256"], metas[1]["environment_identity_sha256"])
            self.assertEqual(metas[0]["profile_id"], metas[1]["profile_id"])

    def test_capture_is_nonempty_and_parseable(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self.context(d)
            bundle = run_capture(
                self.profile, FixtureAdapter(), ctx,
                backend=FixtureBackend(), capability=self.capability,
                min_free_gib=0,
            )
            frames = list(read_pcap(bundle.pcap_path))
            self.assertGreaterEqual(len(frames), 2)

    def test_windows_probe_script_is_machine_readable_capability_probe(self):
        script = Path(__file__).resolve().parents[1] / "natural_traffic" / "windows_probe.ps1"
        text = script.read_text()
        self.assertIn("pktmon", text.lower())
        self.assertIn("ConvertTo-Json", text)
        self.assertIn("supported", text)


@unittest.skipUnless(os.environ.get("NATURAL_TRAFFIC_REAL_CAPTURE") == "1", "real capture smoke is CI-gated")
class NaturalCaptureIntegrationTests(unittest.TestCase):
    class LocalHttpsAdapter:
        adapter_id = "local-https-fixture"

        def __init__(self, cert, key):
            self.cert = Path(cert)
            self.key = Path(key)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("127.0.0.1", 0))
            self.sock.listen(1)
            self.port = self.sock.getsockname()[1]

        def capture_spec(self, context):
            return CaptureSpec(interface="lo", transport="tcp", port=self.port)

        def execute(self, context):
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(str(self.cert), str(self.key))
            state = {}

            def serve():
                conn, _ = self.sock.accept()
                try:
                    with server_ctx.wrap_socket(conn, server_side=True) as tls:
                        request = tls.recv(4096)
                        state["request_bytes"] = len(request)
                        body = b"office-control"
                        tls.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: "
                            + str(len(body)).encode()
                            + b"\r\nConnection: close\r\n\r\n"
                            + body
                        )
                finally:
                    self.sock.close()

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            client_ctx = ssl.create_default_context()
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
                with client_ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                    tls.sendall(b"GET /control HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    response = bytearray()
                    while True:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        response.extend(chunk)
            thread.join(timeout=5)
            if thread.is_alive():
                raise RuntimeError("TLS fixture server did not stop")
            return {"status": 200, "response_bytes": len(response), **state}

    def test_real_linux_python_tls_capture_is_pinned_and_parseable(self):
        if shutil.which("openssl") is None:
            self.skipTest("openssl unavailable")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                    "-days", "1",
                ],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            profile = ProfileRegistry.default().resolve("linux-python-ssl")
            adapter = self.LocalHttpsAdapter(cert, key)
            context = GenerationContext("ci-real-tls", "control", profile, 42, root / "capture")
            capability = probe_capability(profile)
            self.assertTrue(capability.supported, capability.reason)
            bundle = run_capture(profile, adapter, context, capability=capability)
            frames = list(read_pcap(bundle.pcap_path))
            self.assertGreaterEqual(len(frames), 4)
            self.assertTrue(verify_capture_bundle(bundle))


if __name__ == "__main__":
    unittest.main()
