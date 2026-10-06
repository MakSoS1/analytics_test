import unittest

import numpy as np
import pandas as pd

from natural_traffic.calibration import (
    CalibrationLeakageError,
    GroupLeakageError,
    calibrate_profiles,
    validate_group_disjointness,
)
from natural_traffic.evaluation import ManifestIntegrityError, confirm_naturalness
from natural_traffic.profiles import ProfileRegistry


def office_frame(n=40):
    x = np.linspace(-1.0, 1.0, n)
    return pd.DataFrame({"x": x, "role": ["office"] * n})


def controls_frame(n=40):
    x = np.linspace(-1.0, 1.0, n)
    a = pd.DataFrame({
        "x": x,
        "role": ["control"] * n,
        "profile_id": ["linux-curl"] * n,
    })
    b = pd.DataFrame({
        "x": x + 4.0,
        "role": ["control"] * n,
        "profile_id": ["linux-python-ssl"] * n,
    })
    return pd.concat([a, b], ignore_index=True)


class NaturalCalibrationTests(unittest.TestCase):
    def test_scenario_rows_are_rejected_from_calibration(self):
        controls = controls_frame(40)
        controls.loc[0, "role"] = "scenario"
        groups = {
            "office": [f"o{i}" for i in range(40)],
            "controls": [f"c{i}" for i in range(80)],
        }
        with self.assertRaises(CalibrationLeakageError):
            calibrate_profiles(
                office_frame(40),
                controls,
                groups,
                ProfileRegistry.default(),
                seed=7,
                feature_columns=["x"],
            )

    def test_train_and_confirmation_ancestors_must_be_disjoint(self):
        with self.assertRaises(GroupLeakageError):
            validate_group_disjointness(["a", "b"], ["c", "b"])

    def test_calibration_is_deterministic_and_prefers_closest_simple_profile(self):
        controls = controls_frame(40)
        groups = {
            "office": [f"o{i}" for i in range(40)],
            "controls": [f"a{i}" for i in range(40)] + [f"b{i}" for i in range(40)],
        }
        kwargs = dict(
            office_train=office_frame(40),
            benign_controls_train=controls,
            groups=groups,
            registry=ProfileRegistry.default(),
            seed=11,
            feature_columns=["x"],
        )
        first = calibrate_profiles(**kwargs)
        second = calibrate_profiles(**kwargs)
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(first.profile_weights, (("linux-curl", 1.0),))

    def test_confirmation_rejects_wrong_frozen_manifest_hash(self):
        controls = controls_frame(40).query("profile_id == 'linux-curl'").reset_index(drop=True)
        groups = {
            "office": [f"o{i}" for i in range(40)],
            "controls": [f"c{i}" for i in range(40)],
        }
        manifest = calibrate_profiles(
            office_frame(40), controls, groups, ProfileRegistry.default(),
            seed=5, feature_columns=["x"],
        )
        with self.assertRaises(ManifestIntegrityError):
            confirm_naturalness(
                manifest,
                office_frame(40),
                controls,
                groups,
                expected_manifest_sha="0" * 64,
                feature_columns=["x"],
                bootstrap_reps=10,
            )

    def test_duplicate_placements_do_not_satisfy_minimum_support(self):
        controls = controls_frame(40).query("profile_id == 'linux-curl'").reset_index(drop=True)
        groups = {"office": ["same-office"] * 40, "controls": ["same-control"] * 40}
        manifest = ProfileRegistry.default().manifest(["linux-curl"], seed=1)
        report = confirm_naturalness(
            manifest,
            office_frame(40),
            controls,
            groups,
            expected_manifest_sha=manifest.sha256,
            feature_columns=["x"],
            bootstrap_reps=10,
        )
        self.assertEqual(report.status, "insufficient_data")
        self.assertEqual(report.support["office_groups"], 1)
        self.assertEqual(report.support["control_groups"], 1)


if __name__ == "__main__":
    unittest.main()
