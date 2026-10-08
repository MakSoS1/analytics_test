"""CI may run real research traffic only inside an ephemeral isolated VM."""

from pathlib import Path
import ast
import subprocess
import unittest
from unittest.mock import patch

import yaml

from framework_runtime.adaptix.capture import apply_path, runtime_command
from cover_runtime.entrypoint import bounded_server_response_patch, patch_lab_services


WORKFLOW = Path(__file__).parents[4] / ".github/workflows/isolated-cover-adaptix-research.yml"


class IsolatedLabWorkflowTests(unittest.TestCase):
    def test_adaptix_uses_readback_without_mount_when_lab_tcp_timestamps_already_match(self):
        commands = []

        def fake_run(*args):
            commands.append(args)
            if "-j" in args and "link" in args:
                return b'[{"mtu": 1500}]'
            if "sysctl" in args and "-n" in args:
                return b'1\n'
            return b''

        with patch("framework_runtime.adaptix.capture.run", side_effect=fake_run):
            measured = apply_path({"path_profile": "lab_fixed_v1", "client_mtu": 1500,
                                   "path_rtt_ms": 8, "client_tcp_timestamps": True})
        self.assertTrue(measured["tcp_timestamps_readback_verified"])
        self.assertFalse(any(cmd[0] == "mount" for cmd in commands))

    def test_adaptix_timestamp_mismatch_does_not_silently_accept_restricted_mount(self):
        def fake_run(*args):
            if "-j" in args and "link" in args:
                return b'[{"mtu": 1500}]'
            if "sysctl" in args and "-n" in args:
                return b'0\n'
            if args[0] == "mount":
                raise subprocess.CalledProcessError(32, args)
            return b''

        with patch("framework_runtime.adaptix.capture.run", side_effect=fake_run):
            with self.assertRaises(subprocess.CalledProcessError):
                apply_path({"path_profile": "lab_fixed_v1", "client_mtu": 1500,
                            "path_rtt_ms": 8, "client_tcp_timestamps": True})

    def test_broker_uses_loopback_mqtt_socket_before_namespaced_websocket_listener(self):
        original = "listener 9443 10.20.0.20\nprotocol websockets\nallow_anonymous true\npersistence false\n"
        patched = patch_lab_services(original)
        self.assertIn("listener 1883 127.0.0.1\nprotocol mqtt\nlistener 9443 10.20.0.20\nprotocol websockets", patched)
        self.assertIn("user root", patched)

    def test_adaptix_offline_build_disables_unneeded_upstream_workspace_modules(self):
        dockerfile = (Path(__file__).parents[1] / "framework_runtime" / "adaptix" / "Dockerfile").read_text()
        self.assertIn("GOWORK=off", dockerfile)

    def test_bounded_control_decoding_is_dispatched_before_benign_filler(self):
        """Both pair arms must produce verifiable bounded response receipts."""
        snippet = bounded_server_response_patch()
        syntax = ast.parse("async def handle(path, suspicious, st, req_body, request):\n" +
                           snippet + "\n")
        first_branch = syntax.body[0].body[0]
        self.assertIsInstance(first_branch, ast.If)
        self.assertEqual(ast.unparse(first_branch.test), "path.startswith('bounded/')")
        self.assertIsInstance(first_branch.orelse[0], ast.If)
        self.assertIn("not suspicious", ast.unparse(first_branch.orelse[0].test))

    def test_workflow_has_bounded_gh_actions_experiment_and_no_public_capture_uploads(self):
        body = WORKFLOW.read_text()
        data = yaml.safe_load(body)
        self.assertEqual(data["permissions"], {"contents": "read"})
        self.assertEqual(set(data["jobs"]), {"isolated-research", "adaptix-research"})
        self.assertNotIn("needs", data["jobs"]["adaptix-research"])
        cover_steps = [step.get("name", "") for step in data["jobs"]["isolated-research"]["steps"]]
        adaptix_steps = [step.get("name", "") for step in data["jobs"]["adaptix-research"]["steps"]]
        self.assertTrue(any("Cover PCAPs" in step for step in cover_steps))
        self.assertFalse(any("Adaptix" in step for step in cover_steps))
        self.assertTrue(any("Adaptix" in step for step in adaptix_steps))
        self.assertFalse(any("Cover PCAPs" in step for step in adaptix_steps))
        self.assertNotIn("cover-report.json", str(data["jobs"]["adaptix-research"]))
        self.assertIn("workflow_dispatch:", body)
        self.assertIn("natural-traffic-generator-v2-2026-10-06", body)
        self.assertIn("ubuntu-24.04", body)
        self.assertIn("cover-complete-wire:20261002", body)
        self.assertIn("isolated_lab_evidence select-cover", body)
        self.assertIn("isolated_lab_evidence audit-cover", body)
        self.assertIn("isolated_lab_evidence audit-adaptix", body)
        self.assertIn("--arm both", body)
        self.assertIn("--timing native", body)
        self.assertIn("--mechanics", body)
        self.assertIn("e99535c9ef4642190f7ea125c2983d1611f1a3f3", body)
        self.assertIn("go1.25.4", body)
        self.assertIn("go mod download all", body)
        self.assertIn("extenders/gopher_agent/src_gopher", body)
        self.assertIn("GOPROXY=off GOWORK=off GOMODCACHE=", body)
        self.assertNotIn("--network host", body)
        self.assertNotIn("--publish", body)
        self.assertNotIn("docker run --privileged", body)
        self.assertNotIn("continue-on-error: true", body)
        artifact_section = body.split("uses: actions/upload-artifact@v4")[-1]
        self.assertIn("safe-evidence", artifact_section)
        self.assertNotIn("capture.pcap", artifact_section)
        self.assertNotIn("*.pcap", artifact_section)
        self.assertNotIn("receipt.json", artifact_section)
        self.assertNotIn("agent", artifact_section.lower())

    def test_research_adaptix_runtime_refuses_public_listener_or_user_command(self):
        command = runtime_command(
            Path("/tmp/isolated-test"), Path("/tmp/capture.py"), "isolated-lab"
        )
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertNotIn("-p", command)
        self.assertNotIn("--privileged", command)
        self.assertNotIn("--network=host", command)
        self.assertNotIn("--command", command)

    def test_adaptix_detector_runs_after_extraction_and_uploads_aggregates_only(self):
        data = yaml.safe_load(WORKFLOW.read_text())
        adaptix = data["jobs"]["adaptix-research"]["steps"]
        extraction = next(i for i, step in enumerate(adaptix)
                          if "Extract every Adaptix PCAP" in step.get("name", ""))
        detection = next(i for i, step in enumerate(adaptix)
                         if "group-held-out Adaptix detector" in step.get("name", ""))
        self.assertLess(extraction, detection)
        self.assertIn("natural_traffic.adaptix_detector_research", adaptix[detection]["run"])
        self.assertIn("adaptix-detector-report.json", adaptix[detection]["run"])
        self.assertIn("scikit-learn", adaptix[2]["run"] if "run" in adaptix[2] else
                      " ".join(str(step.get("run", "")) for step in adaptix))
        upload = next(step for step in adaptix if step.get("uses", "").startswith("actions/upload-artifact"))
        self.assertIn("safe-evidence", str(upload["with"]["path"]))
        self.assertNotIn("capture.pcap", str(upload["with"]["path"]))

    def test_new_research_branch_runs_only_adaptix_capture_job(self):
        raw = WORKFLOW.read_text()
        data = yaml.safe_load(raw)
        branch = "office-benign-adaptix-transfer-2026-10-09"
        self.assertIn(branch, str(data.get("on", data.get(True, {}))))
        self.assertIn("refs/heads/" + branch, data["jobs"]["isolated-research"]["if"])
        self.assertNotIn("if", data["jobs"]["adaptix-research"])


if __name__ == "__main__":
    unittest.main()
