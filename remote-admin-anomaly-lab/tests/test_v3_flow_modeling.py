from __future__ import annotations

import numpy as np
import pandas as pd

from adminlab.v3_modeling import v3_flow_shortcut_audit


def _frame() -> pd.DataFrame:
    rng = np.random.default_rng(7)
    rows = []
    for split, count in (("train", 80), ("validation", 40)):
        for index in range(count):
            label = index % 2
            rows.append({
                "duration": float(rng.uniform(0.1, 20.0)),
                "src_bytes": float(rng.integers(50, 5000)),
                "dst_bytes": float(rng.integers(50, 5000)),
                "src_packets": float(rng.integers(2, 50)),
                "dst_packets": float(rng.integers(2, 50)),
                "bytes_total": float(rng.integers(100, 10000)),
                "packets_total": float(rng.integers(4, 100)),
                "bytes_ratio": float(rng.uniform(0.2, 5.0)),
                "packets_ratio": float(rng.uniform(0.2, 5.0)),
                "app_proto": "ssh" if index % 4 < 2 else "smb",
                "dst_port": 22 if index % 4 < 2 else 445,
                "hour_sin": float(rng.uniform(-1, 1)),
                "hour_cos": float(rng.uniform(-1, 1)),
                "is_weekend": index % 2,
                "connections_1h": 1 + 5 * label,
                "connections_24h": 2 + 8 * label,
                "unique_dst_ip_24h": 1 + 3 * label,
                "new_dst_for_src": label,
                "new_src_dst_pair": label,
                "pair_seen_count": 5 * (1 - label),
                "pair_recency_s": 300.0 if label == 0 else -1.0,
                "source_protocol_seen_count_prior": 5 * (1 - label),
                "source_protocol_novelty": label,
                "source_pair_protocol_seen_count_prior": 4 * (1 - label),
                "destination_seen_count_prior": 10,
                "new_edge_ratio_1h": 0.1 if label == 0 else 0.8,
                "recent_protocol_switch_count_1h": label,
                "protocol_entropy_1h": 0.0 if label == 0 else 1.0,
                "label_binary": label,
                "split": split,
            })
    return pd.DataFrame(rows)


def test_flow_shortcut_audit_uses_same_estimator_family_for_every_view():
    report = v3_flow_shortcut_audit(_frame(), full_model_pr_auc=0.90, seed=17)
    assert report["primary_unit"] == "suricata_eve_flow"
    assert "protocol_only" in report["baselines"]
    assert "history_only" in report["baselines"]
    estimators = {
        result["estimator"]
        for result in report["baselines"].values()
        if result.get("status") == "ok"
    }
    assert estimators == {"LightGBM"}
    assert report["prevalence_pr_auc"] == 0.5
    assert report["history_only_pr_auc"] > report["prevalence_pr_auc"]
