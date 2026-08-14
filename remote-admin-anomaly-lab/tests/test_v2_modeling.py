import pandas as pd
import pytest

from adminlab.v2_modeling import assert_feature_frame_safe, training_mask


def test_training_mask_excludes_external_environments_and_nontrain_rows():
    labels = pd.DataFrame(
        {
            "environment_id": ["linux_v2", "linux_v2", "windows_native", "lanl_reference"],
            "split": ["train", "validation", "train", "train"],
        }
    )
    mask = training_mask(labels)
    assert mask.tolist() == [True, False, False, False]


def test_feature_safety_rejects_semantic_and_environment_leakage():
    safe = pd.DataFrame({"flow_count": [1], "prior_sessions_1h": [0]})
    assert_feature_frame_safe(safe)
    with pytest.raises(ValueError):
        assert_feature_frame_safe(pd.DataFrame({"flow_count": [1], "campaign_type": ["target_chain"]}))
    with pytest.raises(ValueError):
        assert_feature_frame_safe(pd.DataFrame({"flow_count": [1], "environment_id": ["linux_v2"]}))
