"""Independent, pseudonym-safe summaries of pinned office observations."""
from pathlib import Path
import json
import unittest

import numpy as np
import pandas as pd

from natural_traffic.office_profile_audit import profile_office_reference
from natural_traffic.office_reference import load_office_reference


class OfficeProfileAuditTests(unittest.TestCase):
    def test_missing_tls_stays_unavailable(self):
        frame = pd.DataFrame({
            "independent_source_group": ["opaque-a", "opaque-b"],
            "pkt_count": [12, 18], "flow_duration": [0.5, 1.5],
            "tls_version": [np.nan, np.nan],
        })
        report = profile_office_reference({"2026-09-22": frame},
                                          columns=["pkt_count", "flow_duration"])
        day = report["days"]["2026-09-22"]
        self.assertEqual(day["rows"], 2)
        self.assertEqual(day["independent_groups"], 2)
        self.assertEqual(day["unavailable_families"]["tls"], "unmeasured")
        self.assertEqual(day["robust_quantiles"]["pkt_count"]["p50"], 15.0)
        self.assertEqual(day["measured_feature_coverage"]["pkt_count"], 1.0)

    def test_older_day_never_cross_joins_identity(self):
        a = pd.DataFrame({"host_key": ["SAME", "SAME"], "pkt_count": [1, 2]})
        b = pd.DataFrame({"host_key": ["SAME", "OTHER"], "pkt_count": [3, 4]})
        report = profile_office_reference({"2026-09-23": a, "2026-09-28": b},
                                          columns=["pkt_count"])
        self.assertEqual(report["days"]["2026-09-23"]["grouping_basis"],
                         "within_day_host_key_only")
        self.assertEqual(report["days"]["2026-09-23"]["independent_groups"], 1)
        self.assertEqual(report["days"]["2026-09-28"]["independent_groups"], 2)
        self.assertFalse(report["cross_day_group_join_permitted"])
        self.assertNotIn("SAME", json.dumps(report))
        self.assertEqual(report["days"]["2026-09-23"]["comparison_scope"],
                         "historical_unmatched_view")

    def test_zero_tls_version_is_not_a_measurement(self):
        frame = pd.DataFrame({
            "independent_source_group": ["a", "b", "c"],
            "tls_version": [0, 772, 0], "pkt_count": [2, 4, 6],
        })
        result = profile_office_reference({"2026-09-28": frame}, columns=["pkt_count"])
        self.assertEqual(result["days"]["2026-09-28"]["unavailable_families"]["tls"],
                         "partially_measured")

    def test_profile_contains_only_numeric_aggregates(self):
        frame = pd.DataFrame({"independent_source_group": ["secret-host-42"],
                              "host_key": ["secret-host-42"],
                              "pkt_count": [float("inf")], "flow_duration": [2.0]})
        report = profile_office_reference({"2026-09-28": frame},
                                          columns=["pkt_count", "flow_duration"])
        day = report["days"]["2026-09-28"]
        self.assertEqual(day["measured_feature_coverage"]["pkt_count"], 0.0)
        self.assertIsNone(day["robust_quantiles"]["pkt_count"])
        self.assertNotIn("secret-host-42", json.dumps(report))
        with self.assertRaisesRegex(ValueError, "transport"):
            profile_office_reference({"2026-09-28": frame}, columns=["host_key"])

    def test_real_reference_counts_and_unverified_labels(self):
        root = Path(__file__).parents[2]
        days = load_office_reference(
            root / "datasets/office-additional-days-20261008",
            root / "datasets/office-cover-20261006",
        )
        report = profile_office_reference(days, columns=["pkt_count", "flow_duration"])
        self.assertEqual({d: v["rows"] for d, v in report["days"].items()}, {
            "2026-09-22": 4000, "2026-09-23": 5726, "2026-09-28": 4002,
        })
        self.assertEqual(report["office_labels"], "unknown_unverified")
        self.assertEqual(report["days"]["2026-09-22"]["unavailable_families"]["tls"],
                         "unmeasured")
        self.assertEqual(report["days"]["2026-09-23"]["comparison_scope"],
                         "historical_unmatched_view")
        self.assertFalse(report["production_ready"])

    def test_empty_reference_refused(self):
        with self.assertRaisesRegex(ValueError, "empty"):
            profile_office_reference({"2026-09-28": pd.DataFrame()}, columns=["pkt_count"])


if __name__ == "__main__":
    unittest.main()
