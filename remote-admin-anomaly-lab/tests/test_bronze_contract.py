from pathlib import Path

from adminlab.quality import validate_bronze_tree

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "scripts/capture_shard.sh"


def test_capture_script_retains_full_compressed_pcap_and_checksums():
    text = CAPTURE.read_text(encoding="utf-8")
    assert "tcpdump" in text
    assert "br-adminlab" in text
    assert ".pcap.zst" in text
    assert "sha256sum" in text
    assert "sessions-executed.jsonl" in text
    assert "reproducibility.json" in text
    assert "rm -f \"$COMPRESSED_PCAP\"" not in text


def test_capture_script_uses_explicit_python_runtime_for_root_packaging():
    text = CAPTURE.read_text(encoding="utf-8")
    assert 'PYTHON_BIN="${ADMINLAB_PYTHON:-python3}"' in text
    assert '"$PYTHON_BIN" "$ROOT/scripts/run_scenarios.py"' in text
    assert '"$PYTHON_BIN" "$ROOT/scripts/package_bronze.py"' in text
    assert 'sudo -E python "$ROOT/scripts/run_scenarios.py"' not in text


def test_capture_script_hands_artifacts_back_to_runner_user():
    text = CAPTURE.read_text(encoding="utf-8")
    assert 'OUTPUT_UID="${ADMINLAB_OUTPUT_UID:-${SUDO_UID:-0}}"' in text
    assert 'OUTPUT_GID="${ADMINLAB_OUTPUT_GID:-${SUDO_GID:-0}}"' in text
    assert 'chown -R "$OUTPUT_UID:$OUTPUT_GID" "$OUT_ROOT"' in text
    assert 'output_owner_uid' in text
    assert 'output_owner_gid' in text


def test_bronze_validator_accepts_complete_tree(tmp_path: Path):
    shard = tmp_path / "bronze" / "A-smoke-00"
    (shard / "captures").mkdir(parents=True)
    (shard / "manifests").mkdir(parents=True)
    (shard / "captures/A-smoke-00.pcap.zst").write_bytes(b"compressed-pcap-placeholder")
    (shard / "manifests/sessions.jsonl").write_text('{"session_id":"s1"}\n', encoding="utf-8")
    (shard / "reproducibility.json").write_text('{"shard":"A-smoke-00"}\n', encoding="utf-8")
    (shard / "checksums.sha256").write_text("placeholder  captures/A-smoke-00.pcap.zst\n", encoding="utf-8")
    report = validate_bronze_tree(shard, verify_checksums=False)
    assert report["ok"] is True
    assert report["pcap_bytes"] > 0


def test_bronze_validator_rejects_missing_capture(tmp_path: Path):
    shard = tmp_path / "bronze" / "broken"
    (shard / "manifests").mkdir(parents=True)
    (shard / "manifests/sessions.jsonl").write_text('{}\n', encoding="utf-8")
    (shard / "reproducibility.json").write_text('{}\n', encoding="utf-8")
    (shard / "checksums.sha256").write_text('', encoding="utf-8")
    report = validate_bronze_tree(shard, verify_checksums=False)
    assert report["ok"] is False
    assert "capture" in " ".join(report["errors"]).lower()
