from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts/probe_fidelity.py"
INSTALL = ROOT / "scripts/install_runner.sh"
DOC = ROOT / "docs/FIDELITY_MATRIX.md"


def test_extended_packages_are_best_effort_not_core_gate():
    text = INSTALL.read_text(encoding="utf-8")
    assert "tigervnc-standalone-server" in text
    assert "xrdp" in text
    assert "freerdp" in text.lower()
    assert "optional_extended_packages" in text


def test_fidelity_probe_uses_real_tools_and_explicit_partial_statuses():
    text = PROBE.read_text(encoding="utf-8").lower()
    assert "xtigervnc" in text
    assert "rpcclient" in text
    assert "xrdp" in text
    assert "xfreerdp" in text or "sdl-freerdp" in text
    assert "partial_dcom" in text
    assert "partial_winrm" in text
    assert "real_rfb" in text
    assert "unavailable" in text
    assert "validated" in text


def test_probe_never_promotes_tool_presence_to_validated_wire_fidelity():
    text = PROBE.read_text(encoding="utf-8")
    assert "tool_present" in text
    assert "wire_observed" in text
    assert "if result['tool_present'] and result['wire_observed']" in text


def test_fidelity_matrix_documents_no_c2_in_v1():
    text = DOC.read_text(encoding="utf-8").lower()
    assert "sliver" in text
    assert "excluded" in text
    assert "partial_dcom" in text
    assert "native windows" in text
