from __future__ import annotations

"""V3 correctness overlay for the three tree experts.

Adds reason-aware telemetry availability and reserves disjoint validation
campaigns for the fusion model without changing the proven v2 feature logic.
"""

import pandas as pd

from . import train_baseline as _base
from . import train_baseline_v2 as _v2
from .research_contract_v3 import validation_role

# Keep immutable references before v3 patches the v2 module globals.
_V2_AVAILABILITY_FLAGS = _v2._availability_flags
_V2_VALIDATION_PARTS = _v2._validation_parts


def _col(df: pd.DataFrame, name: str, default=0) -> pd.Series:
    if name in df:
        return df[name]
    return pd.Series([default] * len(df), index=df.index)


def availability_flags_v3(session: pd.DataFrame) -> pd.DataFrame:
    s = _V2_AVAILABILITY_FLAGS(session)
    visibility = _col(s, "visibility_mode", "").astype(str).str.lower()
    protocol = _col(s, "protocol", "").astype(str).str.lower()
    inspection = _col(s, "inspection_policy", "").astype(str).str.lower()
    parser_any = _col(s, "availability_parser_any", 0).fillna(0).astype(int)
    packet_count = pd.to_numeric(_col(s, "packet_count", 0), errors="coerce").fillna(0)
    expected_packets = pd.to_numeric(_col(s, "expected_packet_count", 0), errors="coerce").fillna(0)
    capture_tail = pd.to_numeric(_col(s, "capture_tail_pass", 1), errors="coerce").fillna(1)
    suri_ok = pd.to_numeric(_col(s, "suricata_parser_ok", 1), errors="coerce").fillna(1)
    zeek_ok = pd.to_numeric(_col(s, "zeek_parser_ok", 1), errors="coerce").fillna(1)

    s["missing_reason_encrypted"] = (visibility.str.contains("opaque|encrypted|ech", regex=True) | inspection.eq("bypass")).astype(int)
    s["missing_reason_parser_unsupported"] = ((parser_any == 0) & protocol.isin(["h3", "http3", "quic", "webtransport", "masque"])).astype(int)
    s["missing_reason_parser_failed"] = ((suri_ok == 0) | (zeek_ok == 0)).astype(int)
    s["missing_reason_packet_loss"] = ((expected_packets > 0) & (packet_count < expected_packets * 0.98)).astype(int)
    s["missing_reason_truncated"] = (capture_tail == 0).astype(int)
    exported = pd.to_numeric(_col(s, "telemetry_exported", 1), errors="coerce").fillna(1)
    s["missing_reason_not_exported"] = (exported == 0).astype(int)
    reason_cols = [c for c in s.columns if c.startswith("missing_reason_") and c != "missing_reason_genuinely_absent"]
    s["missing_reason_genuinely_absent"] = (s[reason_cols].sum(axis=1) == 0).astype(int)
    return s


def validation_parts_v3(val: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    if val.empty:
        return val.copy(), val.copy()
    roles = val.campaign_id.astype(str).map(validation_role)
    return val[roles.eq("expert_calibration")].copy(), val[roles.eq("expert_threshold")].copy()


# build_frames() and fit_one() in v2 resolve these globals at call time.
_v2._availability_flags = availability_flags_v3
_v2._validation_parts = validation_parts_v3
_base.build_frames = _v2.build_frames
_base.numeric_matrix = _v2.numeric_matrix
_base.fit_one = _v2.fit_one


if __name__ == "__main__":
    _base.main()
