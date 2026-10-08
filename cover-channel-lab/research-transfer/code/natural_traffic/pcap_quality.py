from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from pathlib import Path
import struct
from typing import Any, Iterable


@dataclass(frozen=True)
class PcapQualityReport:
    path: str
    accepted: bool
    status: str
    packet_count: int
    snaplen: int | None
    linktype: int | None
    timestamp_resolution: str | None
    timestamp_regression_count: int
    max_timestamp_regression_us: float
    truncated_record_count: int
    snaplen_violation_count: int
    standard_mtu_exceed_count: int
    reasons: tuple[str, ...]
    warnings: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        body = asdict(self)
        body["reasons"] = list(self.reasons)
        body["warnings"] = list(self.warnings)
        return body


def _rejected(path: Path, reason: str) -> PcapQualityReport:
    return PcapQualityReport(
        path=str(path), accepted=False, status="rejected", packet_count=0,
        snaplen=None, linktype=None, timestamp_resolution=None,
        timestamp_regression_count=0, max_timestamp_regression_us=0.0,
        truncated_record_count=0, snaplen_violation_count=0,
        standard_mtu_exceed_count=0, reasons=(reason,), warnings=(),
    )


def audit_pcap(path: Path, *, max_timestamp_regression_us: float = 50) -> PcapQualityReport:
    """Read-only structural audit for classic Ethernet PCAP."""
    target = Path(path)
    if not target.is_file():
        return _rejected(target, "missing_file")
    try:
        with target.open("rb") as fh:
            header = fh.read(24)
            if len(header) != 24:
                return _rejected(target, "truncated_global_header")
            magic = header[:4]
            if magic == b"\xd4\xc3\xb2\xa1":
                endian, scale, resolution = "<", 1e6, "microsecond"
            elif magic == b"\xa1\xb2\xc3\xd4":
                endian, scale, resolution = ">", 1e6, "microsecond"
            elif magic == b"\x4d\x3c\xb2\xa1":
                endian, scale, resolution = "<", 1e9, "nanosecond"
            elif magic == b"\xa1\xb2\x3c\x4d":
                endian, scale, resolution = ">", 1e9, "nanosecond"
            else:
                return _rejected(target, "classic_pcap_required")
            snaplen = int(struct.unpack(endian + "I", header[16:20])[0])
            linktype = int(struct.unpack(endian + "I", header[20:24])[0])
            reasons, warnings = [], []
            if snaplen <= 0 or snaplen > 262144:
                reasons.append("invalid_snaplen")
            if linktype != 1:
                reasons.append("ethernet_linktype_required")
            count = regressions = truncated = snap_violations = mtu_exceed = 0
            max_regression = 0.0
            last = -math.inf
            while True:
                rec = fh.read(16)
                if not rec:
                    break
                if len(rec) != 16:
                    reasons.append("truncated_record_header"); truncated += 1; break
                sec, frac, caplen, origlen = struct.unpack(endian + "IIII", rec)
                data = fh.read(caplen)
                if len(data) != caplen:
                    reasons.append("truncated_record_payload"); truncated += 1; break
                count += 1
                if caplen != origlen:
                    truncated += 1
                if snaplen > 0 and caplen > snaplen:
                    snap_violations += 1
                if caplen > 1518:
                    mtu_exceed += 1
                ts = float(sec) + float(frac) / scale
                if last != -math.inf and ts < last:
                    regression_us = (last - ts) * 1e6
                    regressions += 1
                    max_regression = max(max_regression, regression_us)
                last = max(last, ts)
            if count == 0:
                reasons.append("empty_capture")
            if truncated:
                reasons.append("captured_length_differs_from_original")
            if snap_violations:
                reasons.append("captured_length_exceeds_snaplen")
            if max_regression > float(max_timestamp_regression_us) + 1e-6:
                reasons.append("timestamp_regression_above_bound")
            elif regressions:
                warnings.append("bounded_capture_writer_timestamp_jitter")
            if mtu_exceed:
                warnings.append("frames_above_standard_ethernet_mtu_observed")
            accepted = not reasons
            status = "accepted_with_writer_jitter" if accepted and regressions else "accepted" if accepted else "rejected"
            return PcapQualityReport(
                path=str(target), accepted=accepted, status=status,
                packet_count=count, snaplen=snaplen, linktype=linktype,
                timestamp_resolution=resolution,
                timestamp_regression_count=regressions,
                max_timestamp_regression_us=round(max_regression, 6),
                truncated_record_count=truncated,
                snaplen_violation_count=snap_violations,
                standard_mtu_exceed_count=mtu_exceed,
                reasons=tuple(dict.fromkeys(reasons)),
                warnings=tuple(dict.fromkeys(warnings)),
            )
    except (OSError, struct.error, ValueError) as exc:
        return _rejected(target, f"parse_error:{type(exc).__name__}")


def filter_cover_captures_by_quality(
    captures: Iterable[Any], *, max_timestamp_regression_us: float = 50
) -> tuple[list[Any], list[dict[str, Any]]]:
    accepted, rejected = [], []
    for capture in captures:
        report = audit_pcap(
            Path(capture.bundle.pcap_path),
            max_timestamp_regression_us=max_timestamp_regression_us,
        )
        if report.accepted:
            accepted.append(capture)
        else:
            rejected.append({
                "ancestor_id": str(getattr(capture, "ancestor_id", "")),
                "quality": report.as_dict(),
            })
    return accepted, rejected
