from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def test_v2_research_config_is_fail_closed():
    cfg = yaml.safe_load((ROOT / "configs/v2_research.yaml").read_text(encoding="utf-8"))
    assert cfg["schema_version"] == 2
    assert cfg["sessions"] == 1000
    assert cfg["validation_pr_auc_min"] == 0.65
    assert cfg["test_pr_auc_min"] == 0.60
    assert cfg["shortcut_margin_min"] == 0.05
    assert cfg["hard_benign_fpr_max"] == 0.05
    assert cfg["windows_external_only"] is True
    assert cfg["lanl_external_only"] is True
    assert cfg["learning_curve_delta_for_scale"] == 0.005


def test_legacy_v1_research_workflow_is_not_active_on_v3():
    active = REPO / ".github/workflows/remote-admin-research-gate.yml"
    archived = REPO / ".github/legacy/remote-admin-research-gate-v1.yml.disabled"
    assert not active.exists()
    assert archived.exists()


def test_superseded_v2_contract_workflow_is_retired_after_verified_v3_cleanup():
    # Cleanup policy B intentionally removes active V1/V2 Remote Admin workflows
    # only after the V3 final artifact and HF tree have both been verified.
    assert not (REPO / ".github/workflows/remote-admin-v2-contract.yml").exists()
    workflow = (REPO / ".github/workflows/remote-admin-v3-contract.yml").read_text(encoding="utf-8")
    assert "remote-admin-anomaly-lab-v3" in workflow
    assert "pytest -q tests" in workflow
