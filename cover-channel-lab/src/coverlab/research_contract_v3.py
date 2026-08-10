from __future__ import annotations

"""Contract for the post-v2 research layers.

This module separates training from unseen evaluation and separates wire-real
network manipulations from evidence types that require a dedicated adapter.
No offensive framework launcher lives here; framework traffic is accepted only
as pre-captured isolated-lab evidence with explicit provenance.
"""

from dataclasses import dataclass, asdict
from typing import Iterable

FRAMEWORKS = ("sliver", "adaptix", "mythic_httpx", "mythic_websocket")
LEAVE_ONE_FAMILIES = ("header", "wss", "timing", "h3", "tunnel")
MISSINGNESS_REASONS = (
    "encrypted", "parser_unsupported", "parser_failed", "packet_loss",
    "truncated", "not_exported", "genuinely_absent",
)

BENIGN_SERVICE_PROFILES = (
    "browser_navigation", "rest_api", "oauth_oidc", "cdn_assets", "telemetry",
    "cloud_sync", "ci_cd", "package_manager", "ide_extension", "collaboration",
    "graphql", "grpc_otlp", "websocket_dashboard", "websocket_chat", "mqtt_telemetry",
    "software_update", "backup", "webhook", "browser_extension", "long_poll",
    "sse", "retry_backoff", "health_check",
)

CLIENT_STACKS = (
    "python_httpx", "python_httpx_h2", "python_stdlib", "curl_openssl", "go_nethttp",
    "node_fetch", "java_httpclient", "rust_reqwest", "chromium", "firefox",
    "windows_winhttp_schannel", "dotnet_httpclient_schannel", "edge_schannel",
)
SERVER_STACKS = ("hypercorn", "nginx", "caddy", "apache", "haproxy", "envoy", "iis")


@dataclass(frozen=True)
class NetemProfile:
    name: str
    delay_ms: int = 0
    jitter_ms: int = 0
    loss_pct: float = 0.0
    reorder_pct: float = 0.0
    rate_mbit: int = 0
    mtu: int = 1500


# These are applied by Linux tc/ip and are therefore real wire conditions.
NETEM_PROFILES = (
    NetemProfile("clean"),
    NetemProfile("wan_20ms", delay_ms=20, jitter_ms=3),
    NetemProfile("wan_80ms", delay_ms=80, jitter_ms=15),
    NetemProfile("lossy_wifi", delay_ms=35, jitter_ms=12, loss_pct=0.7, reorder_pct=0.2),
    NetemProfile("constrained", delay_ms=60, jitter_ms=10, rate_mbit=5, mtu=1280),
)

# These cannot honestly be represented by tc delay alone. Promotion evidence
# must come from dedicated adapters/captures.
NETWORK_EVIDENCE_TYPES = (
    "nat", "forward_proxy", "tls_inspection", "tls_bypass", "partial_capture",
    "capture_loss", "connection_migration",
)

LONG_TIMING_SECONDS = (5, 30, 120, 300, 1200, 3600)
ECH_MODES = (
    "grease", "accepted_h2", "accepted_h3", "rejected", "shared_frontend_benign",
    "shared_frontend_suspicious",
)


def netem_manifest() -> list[dict]:
    return [asdict(p) for p in NETEM_PROFILES]


def framework_record(framework: str, campaign_id: str, *, protocol: str, pcap_sha256: str,
                     lifecycle: Iterable[str], isolated: bool = True) -> dict:
    framework = framework.lower()
    if framework not in FRAMEWORKS:
        raise ValueError(f"unsupported framework: {framework}")
    stages = tuple(str(x) for x in lifecycle)
    allowed = {"registration", "idle", "poll", "synthetic_task", "synthetic_result", "sleep", "reconnect"}
    if not stages or not set(stages).issubset(allowed):
        raise ValueError("framework holdout lifecycle contains a non-safe stage")
    if not isolated:
        raise ValueError("external framework holdout must be captured in an isolated lab")
    if not pcap_sha256 or len(pcap_sha256) != 64:
        raise ValueError("pcap_sha256 is required")
    return {
        "campaign_id": campaign_id, "framework": framework, "protocol": protocol,
        "pcap_sha256": pcap_sha256, "lifecycle": list(stages), "isolated_lab": True,
        "experiment_stage": "J_framework_holdout", "dataset_role": "external_framework_holdout",
        "split": "challenge", "training_eligible": False, "post_exploitation": False,
    }


def validate_framework_records(records: Iterable[dict]) -> list[str]:
    errors: list[str] = []
    for i, rec in enumerate(records):
        if rec.get("framework") not in FRAMEWORKS: errors.append(f"row {i}: invalid framework")
        if rec.get("experiment_stage") != "J_framework_holdout": errors.append(f"row {i}: invalid experiment_stage")
        if rec.get("dataset_role") != "external_framework_holdout": errors.append(f"row {i}: invalid dataset_role")
        if rec.get("split") != "challenge" or rec.get("training_eligible") is not False:
            errors.append(f"row {i}: framework sample must be challenge-only and training-ineligible")
        if rec.get("isolated_lab") is not True or rec.get("post_exploitation") is not False:
            errors.append(f"row {i}: unsafe framework provenance")
    return errors


def validate_ech_record(rec: dict) -> list[str]:
    errors: list[str] = []
    mode = rec.get("ech_mode")
    if mode not in ECH_MODES: errors.append("unknown ECH mode")
    if rec.get("wire_real") is not True: errors.append("ECH challenge record is not wire-real")
    if mode in {"grease", "accepted_h2", "accepted_h3", "rejected", "shared_frontend_benign"} and rec.get("label_binary") != 0:
        errors.append("ECH itself must never imply attack")
    if mode == "shared_frontend_suspicious" and rec.get("label_binary") != 1:
        errors.append("suspicious ECH sample must be suspicious because of session behavior, not ECH presence")
    return errors


def validation_role(campaign_id: str) -> str:
    """Four disjoint validation roles: expert calibration, threshold, fusion fit/tune."""
    import hashlib
    bucket = int(hashlib.sha256(("v3-validation:" + str(campaign_id)).encode()).hexdigest()[:8], 16) % 4
    return ("expert_calibration", "expert_threshold", "fusion_train", "fusion_threshold")[bucket]
