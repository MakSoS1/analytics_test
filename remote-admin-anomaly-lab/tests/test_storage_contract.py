from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPLOAD = ROOT / "scripts/upload_hf.py"


def test_hf_uploader_keeps_full_recoverable_layers():
    text = UPLOAD.read_text(encoding="utf-8")
    assert "HF_TOKEN" in text
    assert "Maksim123321/remote-admin-anomaly-v1" in text
    assert "create_repo" in text
    assert "upload_folder" in text
    assert "repo_type=\"dataset\"" in text
    assert "private=True" in text
    assert "bronze" in text
    assert "silver" in text
    assert "gold" in text
    assert "quality" in text


def test_hf_uploader_never_prints_or_persists_token():
    text = UPLOAD.read_text(encoding="utf-8")
    forbidden = [
        "print(token)",
        "print(os.environ['HF_TOKEN'])",
        'write_text(token',
        'json.dump(token',
    ]
    assert all(value not in text for value in forbidden)
    assert "token_present" in text


def test_missing_hf_token_is_an_explicit_non_destructive_skip():
    text = UPLOAD.read_text(encoding="utf-8")
    assert 'if not token:' in text
    assert '"status": "skipped"' in text
    assert '"reason": "HF_TOKEN missing"' in text
    assert "return 0" in text


def test_uploader_does_not_use_github_release_or_delete_bronze():
    text = UPLOAD.read_text(encoding="utf-8").lower()
    assert "github release" not in text
    assert "gh release" not in text
    assert "unlink(" not in text
    assert "rmtree(" not in text
