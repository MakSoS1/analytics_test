from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_rule_baseline.sh"


def test_rule_baseline_creates_suricata_log_directory_before_run():
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'mkdir -p "$WORK/out"' in text
    assert '-l "$WORK/out"' in text
