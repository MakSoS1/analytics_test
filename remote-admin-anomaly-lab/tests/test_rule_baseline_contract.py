from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_rule_baseline.sh"


def test_rule_baseline_creates_suricata_log_directory_before_run():
    text = SCRIPT.read_text(encoding="utf-8")
    mkdir_lines = [line for line in text.splitlines() if line.lstrip().startswith("mkdir -p")]
    assert any('"$WORK/out"' in line for line in mkdir_lines)
    assert '-l "$WORK/out"' in text
    assert text.index('"$WORK/out"') < text.index('-l "$WORK/out"')
