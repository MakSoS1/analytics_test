"""Flow-tier features: the subset an NGFW can actually export per flow.

The packet-level model in `train_lab_binary.py` reads the first-20 packet
sequence, which Suricata EVE does not carry. To measure FPR against the office
SPAN — the only source with enough negatives for the ≤1e-4 criterion (plan §47)
— the model has to run on what EVE `flow` records hold: packet and byte counts
per direction, duration, and the protocol. Everything here is computable both
from a lab pcap and from an EVE flow record, so one model scores both.

Inference is pure Python on an exported tree dump so the scoring host needs no
numpy/scikit-learn (the SPAN host has neither).
"""
from __future__ import annotations

import struct
from typing import Any

FLOW_TIER_FEATURES = [
    "pkt_count",
    "up_pkt_count",
    "down_pkt_count",
    "total_bytes",
    "up_bytes",
    "down_bytes",
    "flow_duration",
    "up_down_pkt_ratio",
    "up_down_bytes_ratio",
    "pkt_rate",
    "byte_rate",
    "mean_pkt_size",
    "up_mean_pkt_size",
    "down_mean_pkt_size",
    "is_udp",
    "is_tcp",
]


def flow_features(
    up_pkts: int,
    down_pkts: int,
    up_bytes: int,
    down_bytes: int,
    duration: float,
    proto: str,
) -> dict[str, float]:
    """Build the tier's feature dict from counters available on both sides."""
    pkt_count = up_pkts + down_pkts
    total_bytes = up_bytes + down_bytes
    dur = max(float(duration), 1e-6)
    proto = (proto or "").lower()
    return {
        "pkt_count": float(pkt_count),
        "up_pkt_count": float(up_pkts),
        "down_pkt_count": float(down_pkts),
        "total_bytes": float(total_bytes),
        "up_bytes": float(up_bytes),
        "down_bytes": float(down_bytes),
        "flow_duration": float(dur),
        "up_down_pkt_ratio": up_pkts / max(down_pkts, 1),
        "up_down_bytes_ratio": up_bytes / max(down_bytes, 1),
        "pkt_rate": pkt_count / dur,
        "byte_rate": total_bytes / dur,
        "mean_pkt_size": total_bytes / max(pkt_count, 1),
        "up_mean_pkt_size": up_bytes / max(up_pkts, 1),
        "down_mean_pkt_size": down_bytes / max(down_pkts, 1),
        "is_udp": 1.0 if proto in ("udp", "17") else 0.0,
        "is_tcp": 1.0 if proto in ("tcp", "6") else 0.0,
    }


def export_forest(clf: Any, feature_names: list[str]) -> dict[str, Any]:
    """Dump a fitted sklearn forest to plain JSON-able structures."""
    trees = []
    for est in clf.estimators_:
        t = est.tree_
        # value[i] is [[n_class0, n_class1]] for a classifier; store P(class=1).
        probs = []
        for i in range(t.node_count):
            v = t.value[i][0]
            total = float(v[0] + v[1]) or 1.0
            probs.append(float(v[1]) / total)
        trees.append(
            {
                "children_left": [int(x) for x in t.children_left],
                "children_right": [int(x) for x in t.children_right],
                "feature": [int(x) for x in t.feature],
                "threshold": [float(x) for x in t.threshold],
                "prob": probs,
            }
        )
    return {"features": list(feature_names), "trees": trees}


# sklearn's decision tree casts X to float32 before comparing it with a
# threshold. This walker compared in float64, so the deployed scorer was not the
# model the metrics were measured on: identical on random points, but 247
# disagreements among inputs at or beside a split threshold on a 40-tree forest,
# the largest 0.038 in probability. At an operating threshold near 0.2 that is
# enough to flip rows on the boundary — which is the whole population a
# false-positive bound is made of.
#
# Thresholds stay float64: sklearn keeps them in float64 too and compares
# float32(x) <= float64(threshold). Overflow becomes infinity rather than an
# exception, matching numpy's cast, because a sensor must not raise on a large
# feature value mid-stream.
_F32 = struct.Struct("<f")


def to_float32(value: float) -> float:
    """Round to float32 the way numpy's astype does, inf on overflow."""
    try:
        return _F32.unpack(_F32.pack(value))[0]
    except (OverflowError, struct.error):
        return float("inf") if value > 0 else float("-inf")


def _tree_prob(tree: dict[str, Any], x: list[float]) -> float:
    node = 0
    left = tree["children_left"]
    right = tree["children_right"]
    feat = tree["feature"]
    thr = tree["threshold"]
    while left[node] != -1:
        node = left[node] if x[feat[node]] <= thr[node] else right[node]
    return tree["prob"][node]


def predict_proba(model: dict[str, Any], row: dict[str, float]) -> float:
    """P(tunnel) for one feature dict, using an exported forest.

    The vector is rounded to float32 once, here, because that is what the model
    was fitted and measured against — see `to_float32`.
    """
    x = [to_float32(float(row.get(name, 0.0))) for name in model["features"]]
    trees = model["trees"]
    return sum(_tree_prob(t, x) for t in trees) / len(trees)
