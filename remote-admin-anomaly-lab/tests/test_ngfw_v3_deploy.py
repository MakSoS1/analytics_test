from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_ngfw_installer_uses_sidecar_expected_src_layout_and_verified_flow_model():
    text = (ROOT / "deploy/ngfw/install_v3.sh").read_text(encoding="utf-8")
    assert "/opt/remote-admin-v3/src" in text
    assert "cp -a \"$PACKAGE_SRC\" /opt/remote-admin-v3/src/adminlab" in text
    assert "gold/V3-1k/models/M1-lightgbm.joblib" in text
    assert "gold/V3-1k/models/M1-lightgbm.metrics.json" in text
    assert "model.feature_names_in_" in text
    assert "EveFeatureState().consume_flow" in text
    assert "model expects features not emitted by EveFeatureState" in text


def test_ngfw_systemd_unit_uses_persistent_state_and_pure_eve_stream():
    text = (ROOT / "deploy/ngfw/remote-admin-v3.service").read_text(encoding="utf-8")
    assert "/var/log/suricata/eve.json" in text
    assert "score_eve_sidecar.py" in text
    assert "M1-lightgbm.joblib" in text
    assert "M1-lightgbm.metrics.json" in text
    assert "--state-file /var/lib/remote-admin-v3/state.json" in text
    assert "session_id" not in text


def test_ngfw_deployment_does_not_require_zeek_or_orchestrator_runtime():
    service = (ROOT / "deploy/ngfw/remote-admin-v3.service").read_text(encoding="utf-8").lower()
    installer = (ROOT / "deploy/ngfw/install_v3.sh").read_text(encoding="utf-8").lower()
    assert "zeek" not in service
    assert "orchestrator" not in service
    assert "suricata" in service
    assert "online_features" in installer
