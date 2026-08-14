from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_samba_fixture_requires_authentication_and_adminlike_share():
    text = (ROOT / "scripts/start_services.sh").read_text(encoding="utf-8")
    assert "adminlab_smb" in text
    assert "smbpasswd" in text
    assert "guest ok = no" in text
    assert "valid users = adminlab_smb" in text
    assert "[adminlab_admin]" in text


def test_smb_client_uses_credentials_not_guest_mode():
    text = (ROOT / "scripts/run_scenarios.py").read_text(encoding="utf-8")
    assert "//{r.dst_ip}/adminlab_admin" in text or "//{record.dst_ip}/adminlab_admin" in text
    assert "adminlab_smb%AdminlabSMB-2026!" in text
    assert "'-N'" not in text and '"-N"' not in text
