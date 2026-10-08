import unittest

import numpy as np
import pandas as pd

from natural_traffic.calibration import (
    CalibrationLeakageError,
    GroupLeakageError,
    assign_temporal_starts,
    calibrate_profiles,
    select_frozen_confirmation_groups,
    frozen_confirmation_deficits,
    InsufficientFrozenMixtureSupport,
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

    def test_calibration_can_freeze_a_convex_profile_mixture(self):
        n = 40
        office = pd.DataFrame({"x": np.zeros(n), "role": ["office"] * n})
        left = pd.DataFrame({
            "x": np.full(n, -2.0),
            "role": ["control"] * n,
            "profile_id": ["linux-curl"] * n,
        })
        right = pd.DataFrame({
            "x": np.full(n, 2.0),
            "role": ["control"] * n,
            "profile_id": ["linux-python-ssl"] * n,
        })
        controls = pd.concat([left, right], ignore_index=True)
        groups = {
            "office": [f"o{i}" for i in range(n)],
            "controls": [f"l{i}" for i in range(n)] + [f"r{i}" for i in range(n)],
        }
        manifest = calibrate_profiles(
            office, controls, groups, ProfileRegistry.default(),
            seed=19, feature_columns=["x"],
        )
        weights = dict(manifest.profile_weights)
        self.assertEqual(set(weights), {"linux-curl", "linux-python-ssl"})
        self.assertAlmostEqual(sum(weights.values()), 1.0, places=6)
        self.assertGreater(weights["linux-curl"], 0.35)
        self.assertGreater(weights["linux-python-ssl"], 0.35)

    def test_temporal_profile_is_frozen_from_calibration_office_only(self):
        office = office_frame(40)
        office["session_start_epoch"] = 1_790_000_000.0 + np.arange(40) * 3600.0
        controls = controls_frame(40).query("profile_id == 'linux-curl'").reset_index(drop=True)
        groups = {
            "office": [f"o{i}" for i in range(40)],
            "controls": [f"c{i}" for i in range(40)],
        }
        manifest = calibrate_profiles(
            office, controls, groups, ProfileRegistry.default(),
            seed=23, feature_columns=["x"],
        )
        environment = manifest.environment
        pool = environment["temporal_start_epoch_pool"]
        self.assertGreaterEqual(len(pool), 24)
        self.assertTrue(set(pool).issubset(set(office["session_start_epoch"].astype(float))))
        assigned1 = assign_temporal_starts(manifest, [f"g{i}" for i in range(32)])
        assigned2 = assign_temporal_starts(manifest, [f"g{i}" for i in range(32)])
        self.assertEqual(assigned1, assigned2)
        self.assertTrue(set(assigned1.values()).issubset(set(pool)))


    def test_frozen_confirmation_selection_applies_weights_by_whole_capture_group(self):
        rows = []
        for profile, count in (
            ("linux-chromium", 12),
            ("linux-protocol-native", 20),
            ("linux-python-ssl", 16),
            ("linux-curl", 8),
        ):
            for i in range(count):
                rows.append({
                    "x": float(i),
                    "role": "control",
                    "profile_id": profile,
                    "capture_group": f"{profile}-{i:02d}",
                })
        controls = pd.DataFrame(rows)
        manifest = ProfileRegistry.default().manifest(
            ["linux-chromium", "linux-protocol-native", "linux-python-ssl"],
            seed=29,
        )
        # Override the equal registry manifest with an explicit frozen mixture.
        from natural_traffic.contracts import FrozenProfileManifest
        manifest = FrozenProfileManifest(
            seed=29,
            profile_weights=(
                ("linux-chromium", 0.30),
                ("linux-protocol-native", 0.50),
                ("linux-python-ssl", 0.20),
            ),
            reference_id="frozen:test-mixture",
        )
        selected = select_frozen_confirmation_groups(
            manifest, controls, min_groups=30, group_column="capture_group"
        )
        groups = selected[["capture_group", "profile_id"]].drop_duplicates()
        self.assertEqual(groups["capture_group"].nunique(), 30)
        self.assertNotIn("linux-curl", set(groups["profile_id"]))
        counts = groups["profile_id"].value_counts().to_dict()
        self.assertEqual(counts, {
            "linux-protocol-native": 15,
            "linux-chromium": 9,
            "linux-python-ssl": 6,
        })
        again = select_frozen_confirmation_groups(
            manifest, controls, min_groups=30, group_column="capture_group"
        )
        self.assertEqual(
            sorted(groups["capture_group"]),
            sorted(again["capture_group"].drop_duplicates()),
        )


    def test_frozen_confirmation_deficits_report_only_missing_positive_profile_groups(self):
        from natural_traffic.contracts import FrozenProfileManifest
        rows = []
        for profile, count in (
            ("linux-chromium", 3),
            ("linux-protocol-native", 12),
            ("linux-python-ssl", 14),
            ("linux-curl", 3),
        ):
            for i in range(count):
                rows.append({
                    "profile_id": profile,
                    "capture_group": f"{profile}-{i}",
                })
        controls = pd.DataFrame(rows)
        manifest = FrozenProfileManifest(
            seed=37,
            profile_weights=(
                ("linux-chromium", 0.11322746960017983),
                ("linux-protocol-native", 0.5262965032344724),
                ("linux-python-ssl", 0.3604760271653477),
            ),
            reference_id="frozen:deficits",
        )
        report = frozen_confirmation_deficits(
            manifest, controls, min_groups=30, group_column="capture_group"
        )
        self.assertEqual(report["quotas"], {
            "linux-chromium": 3,
            "linux-protocol-native": 16,
            "linux-python-ssl": 11,
        })
        self.assertEqual(report["available"], {
            "linux-chromium": 3,
            "linux-protocol-native": 12,
            "linux-python-ssl": 14,
        })
        self.assertEqual(report["deficits"], {"linux-protocol-native": 4})

    def test_frozen_confirmation_selection_fails_closed_when_profile_capacity_is_short(self):
        from natural_traffic.contracts import FrozenProfileManifest
        controls = pd.DataFrame([
            {
                "x": float(i),
                "role": "control",
                "profile_id": "linux-chromium" if i < 3 else "linux-protocol-native",
                "capture_group": f"g{i:02d}",
            }
            for i in range(40)
        ])
        manifest = FrozenProfileManifest(
            seed=31,
            profile_weights=(
                ("linux-chromium", 0.30),
                ("linux-protocol-native", 0.70),
            ),
            reference_id="frozen:capacity",
        )
        with self.assertRaises(InsufficientFrozenMixtureSupport):
            select_frozen_confirmation_groups(
                manifest, controls, min_groups=30, group_column="capture_group"
            )


    def test_calibration_respects_predeclared_confirmation_profile_capacities(self):
        n=40
        office=pd.DataFrame({"x":np.zeros(n),"role":["office"]*n})
        left=pd.DataFrame({
            "x":np.full(n,-2.0),
            "role":["control"]*n,
            "profile_id":["linux-curl"]*n,
        })
        right=pd.DataFrame({
            "x":np.full(n,2.0),
            "role":["control"]*n,
            "profile_id":["linux-python-ssl"]*n,
        })
        controls=pd.concat([left,right],ignore_index=True)
        groups={
            "office":[f"o{i}" for i in range(n)],
            "controls":[f"l{i}" for i in range(n)]+[f"r{i}" for i in range(n)],
        }
        manifest=calibrate_profiles(
            office,controls,groups,ProfileRegistry.default(),
            seed=41,feature_columns=["x"],
            confirmation_profile_capacity={
                "linux-curl":6,
                "linux-python-ssl":24,
            },
            min_confirmation_groups=30,
        )
        weights=dict(manifest.profile_weights)
        self.assertLessEqual(weights.get("linux-curl",0.0),0.20+1e-9)
        self.assertGreaterEqual(weights.get("linux-python-ssl",0.0),0.80-1e-9)
        confirm=pd.DataFrame([
            {"profile_id":"linux-curl","capture_group":f"lc-{i}"}
            for i in range(6)
        ]+[
            {"profile_id":"linux-python-ssl","capture_group":f"lp-{i}"}
            for i in range(24)
        ])
        report=frozen_confirmation_deficits(
            manifest,confirm,min_groups=30,group_column="capture_group"
        )
        self.assertEqual(report["deficits"],{})

    def test_calibration_rejects_declared_capacity_that_cannot_supply_support(self):
        controls=controls_frame(40)
        groups={
            "office":[f"o{i}" for i in range(40)],
            "controls":[f"a{i}" for i in range(40)]+[f"b{i}" for i in range(40)],
        }
        with self.assertRaises(ValueError):
            calibrate_profiles(
                office_frame(40),controls,groups,ProfileRegistry.default(),
                seed=43,feature_columns=["x"],
                confirmation_profile_capacity={
                    "linux-curl":5,
                    "linux-python-ssl":5,
                },
                min_confirmation_groups=30,
            )

    def test_capacity_contract_changes_frozen_manifest_identity(self):
        controls=controls_frame(40)
        groups={
            "office":[f"o{i}" for i in range(40)],
            "controls":[f"a{i}" for i in range(40)]+[f"b{i}" for i in range(40)],
        }
        common=dict(
            office_train=office_frame(40),
            benign_controls_train=controls,
            groups=groups,
            registry=ProfileRegistry.default(),
            seed=47,
            feature_columns=["x"],
            min_confirmation_groups=30,
        )
        one=calibrate_profiles(
            **common,
            confirmation_profile_capacity={
                "linux-curl":30,
                "linux-python-ssl":30,
            },
        )
        two=calibrate_profiles(
            **common,
            confirmation_profile_capacity={
                "linux-curl":6,
                "linux-python-ssl":24,
            },
        )
        self.assertNotEqual(one.sha256,two.sha256)

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