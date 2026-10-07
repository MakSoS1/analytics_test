import ast
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[4]
WORKFLOW = ROOT / ".github" / "workflows" / "natural-office-traffic-v2.yml"
TDD_WORKFLOW = ROOT / ".github" / "workflows" / "natural-traffic-tdd.yml"


class NaturalWorkflowContractTests(unittest.TestCase):
    def test_workflow_has_full_manual_pipeline_and_distinct_probes(self):
        self.assertTrue(WORKFLOW.is_file(), str(WORKFLOW))
        raw = WORKFLOW.read_text()
        body = yaml.safe_load(raw)
        jobs = body["jobs"]
        required = {
            "validate-reference-data", "unit-tests", "capture-probe-linux",
            "capture-probe-windows", "generate-benign-matrix",
            "calibrate-profile-mixture", "confirm-naturalness",
            "generate-cover-scenarios", "evaluate-technique-signal",
            "package-release",
        }
        self.assertEqual(set(jobs), required)
        self.assertIn("workflow_dispatch:", raw)
        self.assertIn("pull_request:", raw)
        self.assertEqual(jobs["capture-probe-linux"]["runs-on"], "ubuntu-latest")
        self.assertEqual(jobs["capture-probe-windows"]["runs-on"], "windows-latest")

    def test_expensive_jobs_are_manual_only_and_scenarios_depend_on_confirmation(self):
        raw = WORKFLOW.read_text()
        body = yaml.safe_load(raw)
        jobs = body["jobs"]
        expensive = {
            "capture-probe-linux", "capture-probe-windows", "generate-benign-matrix",
            "calibrate-profile-mixture", "confirm-naturalness",
            "generate-cover-scenarios", "evaluate-technique-signal", "package-release",
        }
        for name in expensive:
            condition = str(jobs[name].get("if", ""))
            self.assertIn("workflow_dispatch", condition, name)
        needs = jobs["generate-cover-scenarios"]["needs"]
        if isinstance(needs, str):
            needs = [needs]
        self.assertIn("confirm-naturalness", needs)
        self.assertIn("calibrate-profile-mixture", needs)

    def test_capture_jobs_guard_resources_and_upload_before_cleanup(self):
        raw = WORKFLOW.read_text()
        body = yaml.safe_load(raw)
        for name in ("generate-benign-matrix", "generate-cover-scenarios"):
            steps = body["jobs"][name]["steps"]
            labels = [step.get("name", "") for step in steps]
            joined = "\n".join(step.get("run", "") for step in steps)
            self.assertIn("Guard runner disk", labels, name)
            self.assertIn("ensure_resource_budget", joined, name)
            upload_index = next(i for i,s in enumerate(steps) if str(s.get("uses", "")).startswith("actions/upload-artifact"))
            cleanup_index = next(i for i,s in enumerate(steps) if s.get("name") == "Cleanup scratch")
            self.assertLess(upload_index, cleanup_index, name)

    def test_real_capture_flag_is_isolated_to_real_capture_job(self):
        body = yaml.safe_load(TDD_WORKFLOW.read_text())
        natural_steps = body["jobs"]["natural-unit"]["steps"]
        real_steps = body["jobs"]["real-capture-smoke"]["steps"]
        natural_env = {
            key: value
            for step in natural_steps
            for key, value in (step.get("env") or {}).items()
        }
        real_env = {
            key: value
            for step in real_steps
            for key, value in (step.get("env") or {}).items()
        }
        self.assertNotIn("NATURAL_TRAFFIC_REAL_CAPTURE", natural_env)
        self.assertEqual(str(real_env.get("NATURAL_TRAFFIC_REAL_CAPTURE")), "1")

    def test_embedded_python_heredocs_are_complete_and_parseable(self):
        body = yaml.safe_load(TDD_WORKFLOW.read_text())
        checked = 0
        for job in body["jobs"].values():
            for step in job.get("steps", []):
                script = step.get("run")
                if not isinstance(script, str) or "python - <<'PY'" not in script:
                    continue
                lines = script.splitlines()
                start = next(i for i, line in enumerate(lines) if "python - <<'PY'" in line)
                try:
                    end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == "PY")
                except StopIteration:
                    self.fail(f"unterminated Python heredoc in step {step.get('name')}")
                ast.parse("\n".join(lines[start + 1:end]))
                checked += 1
        self.assertGreaterEqual(checked, 1)

    def test_generated_e2e_artifact_excludes_runtime_private_scratch(self):
        body = yaml.safe_load(TDD_WORKFLOW.read_text())
        steps = body["jobs"]["generated-benign-e2e"]["steps"]
        upload = next(
            step for step in steps
            if str(step.get("uses", "")).startswith("actions/upload-artifact")
        )
        paths = str(upload["with"]["path"])
        whole_run = "$" + "{{ runner.temp }}/natural-control-run\n"
        self.assertNotIn(whole_run, paths)
        self.assertNotIn("coverlab-certs", paths)
        self.assertIn("natural-control-run/results.json", paths)
        self.assertIn("natural-control-run/*/client.log", paths)
        self.assertIn("natural-control-run/*/result.json", paths)

    def test_generated_benign_e2e_keeps_common_web_protocol_stratum_homogeneous(self):
        raw = TDD_WORKFLOW.read_text()
        allowed = (
            "M-CLOUD-API",
            "M-HTTPS-BEACON",
            "M-HTTPS-FRAG",
            "M-HTTPS-FRONT",
            "M-HTTPS-LOWENT",
            "M-RMM-SHAPE",
        )
        for entry_id in allowed:
            self.assertIn(entry_id, raw)
        self.assertNotIn("'M-GRPC-BIDI'", raw)
        self.assertNotIn("'M-PUBSUB-MQTT'", raw)
        self.assertIn("target_entries", raw)

    def test_generated_benign_e2e_uses_real_stack_matrix_native_time_and_frozen_retime(self):
        body = yaml.safe_load(TDD_WORKFLOW.read_text())
        steps = body["jobs"]["generated-benign-e2e"]["steps"]
        script = "\n".join(str(step.get("run", "")) for step in steps)
        for entry_id in (
            "M-CLOUD-API",
            "M-HTTPS-BEACON",
            "M-HTTPS-FRAG",
            "M-HTTPS-FRONT",
            "M-HTTPS-LOWENT",
            "M-RMM-SHAPE",
        ):
            self.assertIn(entry_id, script)
        self.assertNotIn("--profile original_dispatch", script)
        self.assertNotIn("runtime_events'] = 1", script)
        self.assertIn("--timing native", script)
        self.assertIn("derive_temporal_environment", script)
        self.assertIn("assign_temporal_starts", script)
        self.assertIn("retime_capture_bundle", script)
        self.assertIn("high_level_profile_id=None", script)


    def test_generated_benign_e2e_quality_gates_captures_before_retime(self):
        body = yaml.safe_load(TDD_WORKFLOW.read_text())
        steps = body["jobs"]["generated-benign-e2e"]["steps"]
        script = "\n".join(str(step.get("run", "")) for step in steps)
        self.assertIn("filter_cover_captures_by_quality", script)
        self.assertIn("pcap_quality.json", script)
        self.assertIn("max_timestamp_regression_us=50", script)
        self.assertLess(
            script.index("captures, rejected_quality = filter_cover_captures_by_quality"),
            script.index("retimed_bundle = retime_capture_bundle"),
        )
        self.assertNotIn("max_timestamp_regression_us=60", script)


    def test_office_behavior_profile_job_is_train_only_and_publishes_frozen_envelope(self):
        body = yaml.safe_load(TDD_WORKFLOW.read_text())
        self.assertIn("office-behavior-profile", body["jobs"])
        job = body["jobs"]["office-behavior-profile"]
        script = "\n".join(str(step.get("run", "")) for step in job["steps"])
        self.assertIn("derive_behavior_envelope", script)
        self.assertIn("select_office_web_slice", script)
        self.assertIn("train_hosts = set(hosts[::2])", script)
        self.assertNotIn("confirm_hosts", script)
        self.assertIn("office_behavior_profile.json", script)
        upload = next(
            step for step in job["steps"]
            if str(step.get("uses", "")).startswith("actions/upload-artifact")
        )
        self.assertEqual(upload["with"]["name"], "office-behavior-profile")
        self.assertIn("office_behavior_profile.json", str(upload["with"]["path"]))

    def test_external_reference_audit_is_pinned_and_never_training_input(self):
        raw = TDD_WORKFLOW.read_text()
        body = yaml.safe_load(raw)
        self.assertIn("external-reference-audit", body["jobs"])
        script = "\n".join(
            str(step.get("run", ""))
            for step in body["jobs"]["external-reference-audit"]["steps"]
        )
        self.assertIn("0b408bff41f04e2ecd198f4e78568686e3cdcc8d", script)
        self.assertIn("build-external-reference", script)
        self.assertIn("training_eligible", script)
        self.assertIn("naturalness_calibration_eligible", script)

    def test_generated_benign_e2e_confirms_only_frozen_profile_mixture(self):
        body = yaml.safe_load(TDD_WORKFLOW.read_text())
        steps = body["jobs"]["generated-benign-e2e"]["steps"]
        script = "\n".join(str(step.get("run", "")) for step in steps)
        self.assertIn("select_frozen_confirmation_groups", script)
        self.assertIn("frozen_confirmation_deficits", script)
        self.assertIn("control_confirm_frozen", script)
        self.assertLess(
            script.index("manifest = calibrate_profiles"),
            script.index("control_confirm_frozen = select_frozen_confirmation_groups"),
        )
        self.assertIn("'controls': control_confirm_frozen['capture_group']", script)
        self.assertIn("control_confirm_frozen,", script)

    def test_pr_path_only_runs_reference_validation_and_unit_tests(self):
        raw = WORKFLOW.read_text()
        body = yaml.safe_load(raw)
        for name in ("validate-reference-data", "unit-tests"):
            condition = str(body["jobs"][name].get("if", ""))
            self.assertTrue("pull_request" in condition or condition == "", name)
        for name in set(body["jobs"]) - {"validate-reference-data", "unit-tests"}:
            self.assertIn("workflow_dispatch", str(body["jobs"][name].get("if", "")), name)


if __name__ == "__main__":
    unittest.main()