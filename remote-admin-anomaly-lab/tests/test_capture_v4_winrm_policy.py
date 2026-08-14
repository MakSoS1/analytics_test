from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "scripts/capture_shard_extended_v4.sh"


def test_stage_h_does_not_implicitly_add_partial_winrm_to_primary_corpus():
    text = CAPTURE.read_text(encoding="utf-8")
    assert 'ADMINLAB_INCLUDE_PARTIAL_WINRM' in text
    assert '[[ "$STAGE" == "H" ]] && EXTRA_ARGS+=(--include-partial-winrm)' not in text
    assert '--include-partial-winrm' in text
    assert 'STAGE must be H when ADMINLAB_INCLUDE_PARTIAL_WINRM=1' in text
