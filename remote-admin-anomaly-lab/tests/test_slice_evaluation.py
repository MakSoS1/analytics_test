import numpy as np
import pandas as pd

from adminlab.slice_evaluation import evaluate_slices


def test_slice_evaluation_reports_protocol_family_and_holdout_reason():
    labels = pd.DataFrame({
        "split": ["test"] * 8 + ["challenge"] * 8,
        "label_binary": [0, 0, 1, 1, 0, 0, 1, 1] * 2,
        "protocol": ["ssh", "ssh", "ssh", "ssh", "rdp", "rdp", "rdp", "rdp"] * 2,
        "label_family": ["benign", "benign", "cred", "cred", "benign", "benign", "fanout", "fanout"] * 2,
        "campaign_id": [f"c{i//2}" for i in range(16)],
        "challenge_reason": [""] * 8 + ["unseen_src_host"] * 4 + ["temporal_future"] * 4,
    })
    scores = np.array([0.1, 0.2, 0.8, 0.9, 0.1, 0.3, 0.7, 0.8] * 2)
    report = evaluate_slices(labels, scores, threshold=0.5, bootstrap_samples=50, seed=1)
    assert "test" in report["splits"]
    assert "challenge" in report["splits"]
    assert "ssh" in report["splits"]["test"]["per_protocol"]
    assert "fanout" in report["splits"]["challenge"]["per_attack_family"]
    assert "unseen_src_host" in report["splits"]["challenge"]["per_challenge_reason"]
    assert "temporal_future" in report["splits"]["challenge"]["per_challenge_reason"]
    assert "campaign_bootstrap_ci" in report["splits"]["challenge"]
