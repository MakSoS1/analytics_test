from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def test_windows_native_capture_is_fail_closed_and_pktmon_based():
    text = (ROOT / "windows/capture_native.ps1").read_text(encoding="utf-8").lower()
    for marker in ("pktmon", "wire_observed", "session_completed", "native_windows_validated", "unavailable_hosted_runner"):
        assert marker in text
    assert "synthetic_fallback" not in text
    assert "cobalt strike" not in text


def test_windows_native_validator_requires_wire_and_completion():
    text = (ROOT / "windows/validate_native.py").read_text(encoding="utf-8")
    assert "tool_present" in text
    assert "wire_observed" in text
    assert "session_completed" in text
    assert "native_windows_validated" in text


def test_windows_native_workflow_uses_windows_runner_and_retains_artifact():
    text = (REPO / ".github/workflows/remote-admin-v2-windows-native.yml").read_text(encoding="utf-8")
    assert "windows-2025" in text
    assert "actions/upload-artifact@v4" in text
    assert "if: always()" in text
