from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/run_scenarios.py"
NETEM = ROOT / "configs/netem.yaml"


def test_smbclient_has_explicit_timeout_above_slowest_expected_bulk_transfer():
    text = RUNNER.read_text(encoding="utf-8")
    # The constrained profile is 3 Mbit/s and Digital Twin bulk transfers are
    # multi-megabyte. smbclient's default request timeout is too close to the
    # physical lower bound, so the wire runner must set an explicit budget.
    assert '"--timeout=120"' in text or '"-t", "120"' in text
    assert 'smbclient' in text
    assert 'constrained' in NETEM.read_text(encoding="utf-8")


def test_process_timeout_is_longer_than_smbclient_protocol_timeout():
    text = RUNNER.read_text(encoding="utf-8")
    assert 'SMBCLIENT_PROTOCOL_TIMEOUT = 120' in text
    assert 'SMBCLIENT_PROCESS_TIMEOUT = 150' in text
