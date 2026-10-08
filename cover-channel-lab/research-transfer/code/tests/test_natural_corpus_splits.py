"""Independent units are connected campaigns/captures, not packet rows."""

import unittest

import pandas as pd

from natural_traffic.corpus_splits import (
    assign_connected_splits, assign_research_splits,
    assert_split_independence, connected_component_ids,
)


def sample_metadata(n=12):
    rows = []
    for i in range(n):
        for state in ("verified_positive", "matched_control"):
            rows.append({
                "source_id": f"source-{i}-{state}",
                "session_key": f"session-{i}-{state}",
                "source_sha256": f"sha256-{i}-{state}",
                "parent_campaign_id": f"campaign-{i}",
                "runtime_profile_id": f"independent-profile-{i}",
                "capture_group_id": f"capture-{i}-{state}",
                "pair_id": f"pair-{i}",
                "label_state": state,
                "label_binary": int(state == "verified_positive"),
            })
    return pd.DataFrame(rows)


class ConnectedGroupSplitsTests(unittest.TestCase):
    def test_never_splits_paired_capture_and_records_all_three_splits(self):
        meta = sample_metadata()
        splits = assign_connected_splits(meta, seed=7)
        self.assertEqual(set(splits), {"train", "validation", "test"})
        self.assertEqual(len(splits), len(meta))
        self.assertTrue(all(splits.iloc[i] == splits.iloc[i + 1]
                            for i in range(0, len(meta), 2)))
        assert_split_independence(meta, splits)

    def test_parent_and_runtime_profile_transitivity_cannot_leak(self):
        meta = sample_metadata()
        # Two different campaigns become one connected unit through a reused profile.
        meta.loc[2, "runtime_profile_id"] = meta.loc[0, "runtime_profile_id"]
        components = connected_component_ids(meta)
        self.assertEqual(components.iloc[0], components.iloc[1])
        self.assertEqual(components.iloc[0], components.iloc[2])
        self.assertEqual(components.iloc[2], components.iloc[3])
        splits = assign_connected_splits(meta, seed=7)
        self.assertEqual(splits.iloc[0], splits.iloc[3])
        assert_split_independence(meta, splits)

    def test_one_physical_capture_is_a_single_independent_unit(self):
        meta = sample_metadata()
        meta.loc[2, "source_sha256"] = meta.loc[0, "source_sha256"]
        self.assertEqual(connected_component_ids(meta).iloc[0],
                         connected_component_ids(meta).iloc[2])

    def test_split_mapping_does_not_depend_on_row_order(self):
        meta = sample_metadata()
        original = dict(zip(meta.session_key, assign_connected_splits(meta, seed=17)))
        randomized = meta.sample(frac=1, random_state=4).reset_index(drop=True)
        actual = dict(zip(randomized.session_key,
                          assign_connected_splits(randomized, seed=17)))
        self.assertEqual(original, actual)
        self.assertEqual(assign_connected_splits(meta, seed=17).tolist(),
                         assign_connected_splits(meta, seed=17).tolist())

    def test_cross_holdout_mutation_is_rejected_after_reload(self):
        meta = sample_metadata()
        splits = assign_connected_splits(meta, seed=7)
        splits.iloc[1] = "test" if splits.iloc[0] != "test" else "train"
        with self.assertRaisesRegex(ValueError, "leakage"):
            assert_split_independence(meta, splits)

    def test_missing_identity_and_insufficient_independent_groups_rejected(self):
        meta = sample_metadata()
        with self.assertRaisesRegex(ValueError, "runtime_profile_id"):
            assign_connected_splits(meta.drop(columns="runtime_profile_id"))
        meta.loc[0, "capture_group_id"] = ""
        with self.assertRaisesRegex(ValueError, "capture_group_id"):
            assign_connected_splits(meta)
        with self.assertRaisesRegex(ValueError, "10 independent"):
            assign_connected_splits(sample_metadata(9))

    def test_multitechnique_research_splits_preserve_two_classes_per_fold(self):
        left, right = sample_metadata(12), sample_metadata(12)
        right["source_id"] = "T1071-" + right["source_id"]
        right["parent_campaign_id"] = "T1071-" + right["parent_campaign_id"]
        right["runtime_profile_id"] = "T1071-" + right["runtime_profile_id"]
        right["capture_group_id"] = "T1071-" + right["capture_group_id"]
        right["pair_id"] = "T1071-" + right["pair_id"]
        right["source_sha256"] = "T1071-" + right["source_sha256"]
        left["technique_id"], right["technique_id"] = "T1001", "T1071.001"
        joined = pd.concat([left, right], ignore_index=True)
        splits = assign_research_splits(joined, seed=23)
        assert_split_independence(joined, splits)
        for technique in ("T1001", "T1071.001"):
            for fold in ("train", "validation", "test"):
                rows = joined[joined["technique_id"].eq(technique) & splits.eq(fold)]
                self.assertEqual(set(rows["label_binary"]), {0, 1})
                self.assertGreaterEqual(rows["pair_id"].nunique(), 2)


if __name__ == "__main__":
    unittest.main()
