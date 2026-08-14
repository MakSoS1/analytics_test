from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/run_scenarios_extended_v2.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("adminlab_extended_runner_v2_test", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _row(protocol: str, index: int):
    # First half benign / early, second half suspicious / late. A selector that
    # slices [:need] will therefore collapse both label and timeline diversity.
    day = index // 2
    label = 0 if index < 10 else 1
    return SimpleNamespace(
        protocol=protocol,
        simulated_day=day,
        label_binary=label,
        start_ts=f"2026-01-{day + 1:02d}T00:{index % 60:02d}:00+00:00",
        session_id=f"{protocol}-{index:03d}",
    )


def test_balanced_select_spans_timeline_and_preserves_label_mix_per_protocol():
    runner = _load_runner()
    protocols=("ssh", "smb", "rdp", "vnc")
    rows=[]
    for protocol in protocols:
        rows.extend(_row(protocol, i) for i in range(20))

    selected=runner.balanced_select(rows, 40, protocols)
    assert len(selected) == 40

    for protocol in protocols:
        part=[r for r in selected if r.protocol == protocol]
        assert len(part) == 10
        labels=[int(r.label_binary) for r in part]
        assert sum(labels) == 5, (protocol, labels)
        days=[int(r.simulated_day) for r in part]
        assert min(days) <= 1, (protocol, days)
        assert max(days) >= 8, (protocol, days)
