from __future__ import annotations

import importlib.util
from pathlib import Path

import numpy as np
import pandas as pd


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_v3_flow_external.py"
SPEC = importlib.util.spec_from_file_location("evaluate_v3_flow_external", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_external_event_sanitizes_optional_nan_numeric_values() -> None:
    row = pd.Series(
        {
            "time": 1_700_000_000.0,
            "src_device": "C100",
            "dst_device": "C200",
            "src_port": np.nan,
            "dst_port": 445,
            "duration": np.nan,
            "src_packets": np.nan,
            "dst_packets": np.nan,
            "src_bytes": np.nan,
            "dst_bytes": np.nan,
        }
    )

    event = MODULE._event(row, 7)

    assert event["flow_id"] == 7
    assert event["src_port"] == 0
    assert event["dest_port"] == 445
    assert event["app_proto"] == "smb"
    assert event["flow"]["end"] == event["flow"]["start"]
    assert event["flow"]["bytes_toserver"] == 0.0
    assert event["flow"]["bytes_toclient"] == 0.0
    assert event["flow"]["pkts_toserver"] == 0.0
    assert event["flow"]["pkts_toclient"] == 0.0
