from pathlib import Path

from adminlab.quality import validate_silver_tree

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "scripts/build_silver.sh"
INSTALL = ROOT / "scripts/install_runner.sh"


def test_runner_pins_reproducible_zeek_parser():
    text = INSTALL.read_text(encoding="utf-8")
    assert "zeek/zeek:8.2.1" in text
    assert "docker pull" in text


def test_silver_builder_consumes_bronze_and_runs_both_parsers():
    text = BUILD.read_text(encoding="utf-8")
    assert ".pcap.zst" in text
    assert "zstd -d" in text or "zstd -q -d" in text
    assert "suricata -r" in text
    assert "zeek/zeek:8.2.1" in text
    assert "conn.log" in text
    assert "eve.json" in text
    assert "parser_versions.json" in text
    assert "parser_health.json" in text


def test_silver_validator_accepts_complete_parser_tree(tmp_path: Path):
    shard = tmp_path / "silver" / "A-smoke-00"
    (shard / "suricata").mkdir(parents=True)
    (shard / "zeek").mkdir(parents=True)
    (shard / "suricata/eve.json.zst").write_bytes(b"zstd-eve-placeholder")
    (shard / "zeek/conn.log.zst").write_bytes(b"zstd-conn-placeholder")
    (shard / "parser_versions.json").write_text(
        '{"suricata":"7.0.3","zeek":"8.2.1"}\n', encoding="utf-8"
    )
    report = validate_silver_tree(shard)
    assert report["ok"] is True
    assert report["eve_bytes"] > 0
    assert report["conn_bytes"] > 0


def test_silver_validator_rejects_missing_conn_log(tmp_path: Path):
    shard = tmp_path / "silver" / "broken"
    (shard / "suricata").mkdir(parents=True)
    (shard / "zeek").mkdir(parents=True)
    (shard / "suricata/eve.json.zst").write_bytes(b"eve")
    (shard / "parser_versions.json").write_text('{}\n', encoding="utf-8")
    report = validate_silver_tree(shard)
    assert report["ok"] is False
    assert "conn" in " ".join(report["errors"]).lower()
