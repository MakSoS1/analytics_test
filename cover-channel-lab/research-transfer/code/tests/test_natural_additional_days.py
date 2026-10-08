import unittest
import numpy as np
import pandas as pd

from natural_traffic.office_day_transfer import (
    analyze_additional_days,
    transport_columns,
    _audit_sequences,
)


def fixture(day, n=120, *, null_tls):
    rng = np.random.default_rng(20 + day)
    frame = pd.DataFrame({
        "independent_source_group": [f"day{day}:client{i}" for i in range(n)],
        "source_session_group": [f"day{day}:session{i}" for i in range(n)],
        "capture_day_id": [f"day{day}"] * n,
        "tls_version": [np.nan if null_tls else 772] * n,
        "seq_signed_len": [[80, -120, 66]] * n,
        "seq_iat_us": [[0, 200, 600]] * n,
        "seq_flags": [[2, 18, 16]] * n,
    })
    for i, name in enumerate(__import__(
        "natural_traffic.office_day_transfer", fromlist=["TRANSPORT_FEATURES"]
    ).TRANSPORT_FEATURES):
        frame[name] = rng.gamma(2 + i % 5, 4, size=n)
    # enforce arithmetic invariants in fixture
    frame["pkt_count"] = frame["up_pkt_count"] + frame["down_pkt_count"]
    frame["total_bytes"] = frame["up_bytes"] + frame["down_bytes"]
    return frame


class AdditionalDaysTests(unittest.TestCase):
    def test_tls_unmeasured_day_is_not_imputed(self):
        d2 = fixture(2, null_tls=True)
        d3 = fixture(3, null_tls=False)
        result = analyze_additional_days(
            d2, d3, rows_per_day=110, bootstrap_reps=3
        )
        self.assertEqual(result["tls_comparison"]["status"], "not_comparable_across_days")
        self.assertEqual(result["days"]["day_02"]["tls_version_observed_rows"], 0)
        self.assertEqual(result["days"]["day_03"]["tls_version_observed_rows"], 120)
        self.assertFalse(result["limitations"]["packet_level_naturalness"])

    def test_transport_policy_excludes_tls_and_metadata(self):
        d2 = fixture(2, null_tls=True)
        d3 = fixture(3, null_tls=False)
        cols = transport_columns(d2, d3)
        self.assertIn("pkt_count", cols)
        for forbidden in ("tls_version", "capture_day_id", "independent_source_group", "source_session_group", "start_dow_sin"):
            self.assertNotIn(forbidden, cols)

    def test_flags_misaligned_sequences_without_exposing_contents(self):
        frame = pd.DataFrame({
            "seq_signed_len": [[10,20]],
            "seq_iat_us": [[0]],
            "seq_flags": [[2,16]],
        })
        result = _audit_sequences(frame)
        self.assertEqual(result["sequence_length_mismatches"], 1)
        self.assertNotIn("10", str(result))

    def test_generated_control_transfer_keeps_frozen_policy(self):
        from natural_traffic.office_day_transfer import (
            compare_generated_controls_to_office_days,
        )
        d2 = fixture(2, n=120, null_tls=True)
        d3 = fixture(3, n=120, null_tls=False)
        controls = fixture(4, n=120, null_tls=False)
        controls["capture_group"] = [f"lab-capture-{i}" for i in range(120)]
        result = compare_generated_controls_to_office_days(
            d2, d3, controls, bootstrap_reps=3
        )
        self.assertEqual(result["status"], "diagnostic_only")
        self.assertEqual(set(result["evaluations"]), {"2026-09-22", "2026-09-28"})
        self.assertNotIn("tls_version", result["transport_columns"])
        self.assertFalse(result["measurement_policy"]["production_ready"])
        self.assertFalse(result["measurement_policy"]["attack_scenario_training_allowed"])

    def test_generated_control_transfer_rejects_missing_ancestry(self):
        from natural_traffic.office_day_transfer import (
            compare_generated_controls_to_office_days,
        )
        d2=fixture(2, null_tls=True)
        d3=fixture(3, null_tls=False)
        controls=fixture(4, null_tls=False)
        self.assertEqual(
            compare_generated_controls_to_office_days(d2,d3,controls)["status"],
            "missing_control_ancestry",
        )

    def test_transport_measurement_insufficient_is_fail_closed(self):
        d2 = fixture(2, null_tls=True)
        d3 = fixture(3, null_tls=False)
        for c in list(transport_columns(d2,d3))[5:]:
            d2[c] = np.nan
        res = analyze_additional_days(d2, d3, rows_per_day=110, bootstrap_reps=3)
        self.assertEqual(res["status"], "insufficient_comparable_features")
        self.assertFalse(res["production_ready"])


if __name__ == "__main__":
    unittest.main()