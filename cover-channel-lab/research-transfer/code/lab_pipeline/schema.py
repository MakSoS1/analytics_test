"""Shared schema for the lab binary detector (plan v3 §8, §34–36).

Train and serve must use this list. Ports/IPs/JA3-int/magic bytes are never
model inputs — they leak the lab, not the tunnel.
"""
from __future__ import annotations

SEQ_N = 20

LEAKAGE_FEATURES = frozenset(
    {
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "outer_src",
        "outer_dst",
        "outer_src_port",
        "outer_dst_port",
        "ja3_hash_int",
        "ja3s_hash_int",
        "ja4_hash_int",
        "payload_first_4bytes_int",
        "sni",
        "server_name",
    }
)

LABEL_COLUMNS = frozenset(
    {
        "label_binary",
        "y",
        "label_family",
        "session_id",
        "campaign_id",
        "workload",
        "netem_profile",
        "pcap",
        "capture_source",
        "bind_spec",
        "split",
        "lane",
        "stack_variant",
        "server_endpoint",
        "server_baseline_delay_ms",
    }
)


def sequence_feature_names(n: int = SEQ_N) -> list[str]:
    names: list[str] = []
    for i in range(n):
        names.extend([f"signed_len_{i}", f"dir_{i}", f"iat_{i}", f"mask_{i}"])
    return names


FLOW_FEATURE_NAMES = [
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
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_min",
    "pkt_len_max",
    "pkt_len_median",
    "pkt_len_p10",
    "pkt_len_p90",
    "pkt_len_entropy",
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "iat_p90",
    "burst_count",
    "idle_ratio",
    "direction_changes",
    "udp_share",
    "tcp_share",
    "syn_count",
    "fin_count",
    "rst_count",
]

MODEL_FEATURE_NAMES = FLOW_FEATURE_NAMES + sequence_feature_names()

# Present in the old leaky CSV; never add these to MODEL_FEATURE_NAMES.
FORBIDDEN_SHORTCUTS = frozenset(
    {
        "payload_byte_freq_std",
        "payload_entropy_up",
        "payload_entropy_down",
        "payload_null_ratio",
        "has_tls_ports_heuristic",
    }
)
