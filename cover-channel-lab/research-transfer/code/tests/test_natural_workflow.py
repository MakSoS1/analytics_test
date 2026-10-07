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
            script.index("captures, rejected_quality = filter_cover_captures_by_quality("),
            script.index("retimed_bundle = retime_capture_bundle("),
        )
        self.assertNotIn("max_timestamp_regression_us=60", script)

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