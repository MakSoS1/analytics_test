"""Reject QUIC before the ML tunnel detector (plan v3 §3)."""

from __future__ import annotations

from typing import Any, Mapping

IETF_QUIC_LONG_HEADER_BIT = 0x80
GQUIC_VERSIONS = {0x51303433, 0x51303436, 0x51303530}  # Q043/Q046/Q050


def is_quic_udp_payload(payload: bytes | None) -> bool:
    if not payload or len(payload) < 5:
        return False
    first = payload[0]
    if first & IETF_QUIC_LONG_HEADER_BIT:
        version = int.from_bytes(payload[1:5], "big")
        if version == 0:
            return True
        if 0x00000001 <= version <= 0x000000FF:
            return True
        if version in GQUIC_VERSIONS:
            return True
        if version & 0xFF000000 == 0xFF000000:
            return True
        return True
    if (first & 0xC0) == 0x40:
        return True
    return False


def is_quic_flow(record: Mapping[str, Any]) -> bool:
    proto = str(record.get("protocol") or record.get("proto") or "").lower()
    app = str(record.get("app_proto") or record.get("alpn") or "").lower()
    if proto in {"quic", "gquic"} or app in {"quic", "http3", "h3"}:
        return True
    if record.get("quic") or record.get("is_quic"):
        return True
    udp_port = record.get("udp_dport") or record.get("dst_port")
    if proto == "udp" and record.get("quic_version"):
        return True
    payload = record.get("payload") or record.get("udp_payload")
    if proto == "udp" and isinstance(payload, (bytes, bytearray)) and is_quic_udp_payload(bytes(payload)):
        return True
    if proto == "udp" and udp_port in (443, "443") and record.get("tls_version_numeric") in (0x0304, 772):
        # TLS 1.3 over UDP 443 is treated as QUIC-like and dropped from this detector.
        if record.get("force_quic_udp443"):
            return True
    return False


def should_run_ml_detector(record: Mapping[str, Any]) -> bool:
    """NGFW policy: QUIC is blocked before ML."""
    return not is_quic_flow(record)
