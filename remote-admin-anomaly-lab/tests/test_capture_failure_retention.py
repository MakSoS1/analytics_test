from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "scripts/capture_shard_extended_v4.sh"


def test_cleanup_restores_output_ownership_even_when_scenario_runner_fails():
    text = CAPTURE.read_text(encoding="utf-8")
    assert 'restore_output_ownership()' in text
    assert 'chown -R "$OUTPUT_UID:$OUTPUT_GID" "$OUT_ROOT"' in text
    cleanup = text.split('cleanup(){', 1)[1].split('}', 1)[0]
    assert 'restore_output_ownership' in cleanup


def test_cleanup_stops_capture_before_restoring_ownership():
    text = CAPTURE.read_text(encoding="utf-8")
    cleanup = text.split('cleanup(){', 1)[1].split('}', 1)[0]
    assert cleanup.index('stop_capture') < cleanup.index('restore_output_ownership')
