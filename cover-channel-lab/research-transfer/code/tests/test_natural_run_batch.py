import json
import tempfile
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUN_BATCH = ROOT / "cover_runtime" / "run_batch.py"
ENTRYPOINT = ROOT / "cover_runtime" / "entrypoint.py"
spec = importlib.util.spec_from_file_location("natural_run_batch", RUN_BATCH)
run_batch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_batch)
entry_spec = importlib.util.spec_from_file_location("natural_entrypoint", ENTRYPOINT)
entrypoint = importlib.util.module_from_spec(entry_spec)
entry_spec.loader.exec_module(entrypoint)


class NaturalRunBatchArmTests(unittest.TestCase):
    def registry(self):
        return {
            "sha256": "registry-sha",
            "entries": [
                {
                    "entry_id": "E1",
                    "dataset_role": "scenario_and_matched_control",
                    "source_fidelity": "wire_real_network",
                    "profiles": [
                        {
                            "profile_id": "p1",
                            "runtime_events": 2,
                            "path_profile": "office_path_v1",
                            "client_mtu": 1290,
                            "client_tcp_timestamps": True,
                        }
                    ],
                }
            ],
        }

    def build(self, arm):
        return run_batch.build_jobs(
            self.registry(),
            requested_entries={"E1"},
            requested_profiles={"p1"},
            arm=arm,
            seed=17,
            timing="accelerated_smoke",
            default_events=3,
            native_interval=None,
            mechanics=False,
            adapter_identity="adapter-sha",
        )

    def test_control_only_never_materializes_scenario_job(self):
        jobs = self.build("control")
        self.assertEqual(len(jobs), 1)
        self.assertEqual({j["arm"] for j in jobs}, {"control"})

    def test_scenario_only_never_materializes_control_job(self):
        jobs = self.build("scenario")
        self.assertEqual(len(jobs), 1)
        self.assertEqual({j["arm"] for j in jobs}, {"scenario"})

    def test_both_keeps_matched_pair_and_job_ids_are_arm_specific(self):
        jobs = self.build("both")
        self.assertEqual([j["arm"] for j in jobs], ["scenario", "control"])
        self.assertEqual(len({j["job_id"] for j in jobs}), 2)

    def test_builder_is_deterministic(self):
        self.assertEqual(self.build("control"), self.build("control"))

    def test_resource_guard_uses_declared_disk_budget_not_transient_host_load(self):
        class Usage:
            free = 16 * 2**30

        run_batch.ensure_runner_resources(
            Path("."),
            min_free_gib=15,
            disk_usage_fn=lambda _: Usage(),
            loadavg_fn=lambda: (99.0, 99.0, 99.0),
        )

    def test_resource_guard_rejects_less_than_declared_disk_budget(self):
        class Usage:
            free = 14 * 2**30

        with self.assertRaises(SystemExit):
            run_batch.ensure_runner_resources(
                Path("."),
                min_free_gib=15,
                disk_usage_fn=lambda _: Usage(),
                loadavg_fn=lambda: (0.0, 0.0, 0.0),
            )

    def test_selected_web_batch_does_not_require_unrelated_protocol_services(self):
        jobs = [
            {"entry": {"namespace": "catalog", "transport": "https"}},
            {"entry": {"namespace": "catalog", "transport": "h2"}},
            {"entry": {"namespace": "catalog", "transport": "wss"}},
        ]
        self.assertEqual(run_batch.required_runtime_services(jobs), ("core",))

    def test_protocol_specific_batches_require_their_service(self):
        cases = {
            "h3": "h3",
            "grpc": "grpc",
            "mqtt-wss": "mqtt",
        }
        for transport, service in cases.items():
            jobs = [{"entry": {"namespace": "catalog", "transport": transport}}]
            self.assertIn(service, run_batch.required_runtime_services(jobs))
        stage = [{"entry": {"namespace": "stage_m", "transport": "https"}}]
        self.assertIn("stage_m", run_batch.required_runtime_services(stage))

    def test_mqtt_family_requires_broker_even_when_transport_is_wss(self):
        jobs = [{
            "entry": {
                "entry_id": "CC_MQTT_01",
                "namespace": "catalog",
                "family": "mqtt_ws",
                "carrier": "mqtt_topic",
                "transport": "wss",
            }
        }]
        self.assertIn("mqtt", run_batch.required_runtime_services(jobs))

    def test_mqtt_carrier_requires_broker_even_without_mqtt_transport_name(self):
        jobs = [{
            "entry": {
                "entry_id": "custom",
                "namespace": "catalog",
                "family": "websocket",
                "carrier": "mqtt_payload",
                "transport": "wss",
            }
        }]
        self.assertIn("mqtt", run_batch.required_runtime_services(jobs))

    def test_entrypoint_skips_only_unrequired_service_probes(self):
        sample = "\n".join([
            "required_probe h3-request /tmp/h3 cmd",
            "required_probe grpc /tmp/grpc cmd",
            "required_probe mqtt-wss /tmp/mqtt cmd",
            "required_probe stage-m-nginx /tmp/nginx cmd",
            "echo core",
        ]) + "\n"
        filtered = entrypoint.filter_required_service_probes(sample, {"core"})
        self.assertNotIn("required_probe h3-request", filtered)
        self.assertNotIn("required_probe grpc", filtered)
        self.assertNotIn("required_probe mqtt-wss", filtered)
        self.assertNotIn("required_probe stage-m-nginx", filtered)
        self.assertIn("echo core", filtered)
        mqtt = entrypoint.filter_required_service_probes(sample, {"core", "mqtt"})
        self.assertIn("required_probe mqtt-wss", mqtt)
        self.assertNotIn("required_probe grpc", mqtt)

    def test_runtime_results_fail_closed_when_any_job_failed(self):
        jobs = [{"job_id": "a"}, {"job_id": "b"}]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "results.json").write_text(json.dumps([
                {"job_id": "a", "status": "captured"},
                {"job_id": "b", "status": "failed", "reason": "client_exit:1"},
            ]))
            with self.assertRaisesRegex(RuntimeError, "b.*client_exit:1"):
                run_batch.validate_runtime_results(root, jobs)

    def test_runtime_results_require_one_result_per_expected_job(self):
        jobs = [{"job_id": "a"}, {"job_id": "b"}]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "results.json").write_text(json.dumps([
                {"job_id": "a", "status": "captured"},
            ]))
            with self.assertRaisesRegex(RuntimeError, "missing runtime result"):
                run_batch.validate_runtime_results(root, jobs)

    def test_runtime_results_accept_all_captured_jobs(self):
        jobs = [{"job_id": "a"}, {"job_id": "b"}]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "results.json").write_text(json.dumps([
                {"job_id": "a", "status": "captured"},
                {"job_id": "b", "status": "captured"},
            ]))
            summary = run_batch.validate_runtime_results(root, jobs)
            self.assertEqual(summary, {"expected": 2, "captured": 2, "failed": 0})


    def test_runtime_image_installs_nat_tooling_for_office_wire_translation(self):
        dockerfile = (ROOT / "cover_runtime" / "Dockerfile").read_text()
        self.assertIn("iptables", dockerfile)

    def test_office_wire_translation_maps_lab_tls_to_external_like_443_without_default_route(self):
        env_path = ROOT / "cover_runtime" / "environment.py"
        env_spec = importlib.util.spec_from_file_location("natural_environment", env_path)
        environment = importlib.util.module_from_spec(env_spec)
        env_spec.loader.exec_module(environment)
        plan = environment.office_wire_translation_plan()
        flat = [" ".join(map(str, row)) for row in plan["commands"]]
        self.assertEqual(plan["wire_core_ip"], "100.64.0.20")
        self.assertEqual(plan["wire_wss_ip"], "100.64.0.21")
        self.assertTrue(any("cc-dev" in row and "10.20.0.20" in row and "8443" in row and "100.64.0.20" in row and "443" in row for row in flat))
        self.assertTrue(any("cc-dev" in row and "10.20.0.21" in row and "8443" in row and "100.64.0.21" in row and "443" in row for row in flat))
        self.assertTrue(any("cc-c2" in row and "100.64.0.20" in row and "443" in row and "10.20.0.20" in row and "8443" in row for row in flat))
        self.assertFalse(any("default" in row for row in flat))

    def test_entrypoint_applies_office_wire_translation_before_services(self):
        source = ENTRYPOINT.read_text()
        apply_pos = source.index("apply_office_wire_translation")
        services_pos = source.index("start_services.container.sh")
        self.assertLess(apply_pos, services_pos)

    def test_runtime_image_installs_entrypoint_network_tools(self):
        dockerfile = (ROOT / "cover_runtime" / "Dockerfile").read_text()
        for package in ("iproute2", "tcpdump", "ethtool", "iputils-ping"):
            self.assertIn(package, dockerfile)

    def test_cli_help_exposes_arm_selection(self):
        proc = subprocess.run(
            [sys.executable, str(RUN_BATCH), "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--arm", proc.stdout)
        self.assertIn("control", proc.stdout)
        self.assertIn("scenario", proc.stdout)
        self.assertIn("both", proc.stdout)


if __name__ == "__main__":
    unittest.main()