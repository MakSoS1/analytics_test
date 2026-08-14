from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_core_wire_runner_does_not_branch_on_label_for_size_or_attempts():
    text = (ROOT / "scripts/run_scenarios.py").read_text(encoding="utf-8")
    assert "record.wire_transfer_bytes" in text
    assert "record.wire_attempts" in text
    assert "if record.label_binary" not in text


def test_extended_wire_runner_does_not_branch_on_label_for_attempts():
    text = (ROOT / "src/adminlab/extended_wire_v2.py").read_text(encoding="utf-8")
    assert "record.wire_attempts" in text
    assert "if record.label_binary" not in text


def test_digital_twin_records_concrete_wire_controls():
    text = (ROOT / "src/adminlab/digital_twin.py").read_text(encoding="utf-8")
    assert "wire_attempts=" in text
    assert "wire_transfer_bytes=" in text
