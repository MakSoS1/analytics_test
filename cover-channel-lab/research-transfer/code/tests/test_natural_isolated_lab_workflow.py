"""CI may run real research traffic only inside an ephemeral isolated VM."""

from pathlib import Path
import ast
import unittest

import yaml

from framework_runtime.adaptix.capture import runtime_command
from cover_runtime.entrypoint import bounded_server_response_patch


WORKFLOW = Path(__file__).parents[4] / ".github/workflows/isolated-cover-adaptix-research.yml"


class IsolatedLabWorkflowTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
