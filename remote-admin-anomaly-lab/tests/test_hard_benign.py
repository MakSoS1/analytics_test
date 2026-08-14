import numpy as np
import pandas as pd

from adminlab.hard_benign import evaluate_hard_benign, hard_benign_mask


def test_hard_benign_mask_uses_context_not_wire_volume():
    labels = pd.DataFrame({
        "label_binary": [0, 0, 0, 1],
        "task_id": ["backup", "monitoring", "approved_forwarding", "backup"],
        "historical_relation": ["known_pair", "novel_but_ticketed", "known_pair", "novel_but_ticketed"],
    })
    assert hard_benign_mask(labels).tolist() == [True, True, True, False]


def test_hard_benign_evaluation_reports_fp_per_10k():
    labels = pd.DataFrame({
        "label_binary": [0, 0, 0, 0],
        "task_id": ["backup", "approved_forwarding", "fix_incident", "monitoring"],
        "historical_relation": ["known_pair", "known_pair", "known_pair", "known_pair"],
    })
    scores = np.array([0.1, 0.8, 0.2, 0.9])
    report = evaluate_hard_benign(labels, scores, threshold=0.5)
    assert report["n"] == 3
    assert report["false_positives"] == 1
    assert report["fp_per_10k_hard_benign"] == 10000 / 3
