import gzip
import importlib.util
from pathlib import Path


def _load_upload_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("upload_hf_v3_test", root / "scripts/upload_hf.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _touch(path: Path, data: bytes = b"x"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def test_upload_validator_accepts_v3_browsable_bronze_without_merged_capture(tmp_path):
    module = _load_upload_module()
    release = tmp_path / "release"; shard = "V3-1k"
    for layer in ("bronze", "silver", "gold", "quality"):
        _touch(release / layer / shard / "placeholder.bin")
    # Remove generic Bronze placeholder and build authoritative V3 layout.
    (release / "bronze" / shard / "placeholder.bin").unlink()
    _touch(release / "bronze" / shard / "sessions" / "benign" / "ssh" / "s1.pcap.zst")
    _touch(release / "bronze" / shard / "campaigns" / "benign" / "c1.pcap.zst")
    _touch(release / "bronze" / shard / "raw_chunks" / "chunk-0000.pcap.zst")
    _touch(release / "bronze" / shard / "manifests" / "pcap_index.csv", b"kind,path\n")
    _touch(release / "bronze" / shard / "manifests" / "pcap_index.parquet")
    sizes = module.validate_release_shard(release, shard)
    assert sizes["bronze"] > 0


def test_upload_validator_rejects_v3_browsable_layout_if_giant_capture_is_still_present(tmp_path):
    module = _load_upload_module()
    release = tmp_path / "release"; shard = "V3-1k"
    for layer in ("bronze", "silver", "gold", "quality"):
        _touch(release / layer / shard / "placeholder.bin")
    (release / "bronze" / shard / "placeholder.bin").unlink()
    _touch(release / "bronze" / shard / "sessions" / "benign" / "ssh" / "s1.pcap.zst")
    _touch(release / "bronze" / shard / "campaigns" / "benign" / "c1.pcap.zst")
    _touch(release / "bronze" / shard / "raw_chunks" / "chunk-0000.pcap.zst")
    _touch(release / "bronze" / shard / "manifests" / "pcap_index.csv", b"kind,path\n")
    _touch(release / "bronze" / shard / "manifests" / "pcap_index.parquet")
    _touch(release / "bronze" / shard / "captures" / "V3-1k.pcap.zst")
    try:
        module.validate_release_shard(release, shard)
    except ValueError as exc:
        assert "merged" in str(exc).lower() or "V3" in str(exc)
    else:
        raise AssertionError("V3 authoritative layout must reject persisted merged capture")


def test_hf_quality_transport_losslessly_gzips_every_binary_like_windows_txt(tmp_path):
    module = _load_upload_module()
    source = tmp_path / "quality" / "V3-1k"
    windows = source / "external" / "windows"
    windows.mkdir(parents=True)
    capture_bytes = "capture evidence\n".encode("utf-16")
    extra_bytes = "extra pktmon evidence\n".encode("utf-16")
    (windows / "capture.txt").write_bytes(capture_bytes)
    (windows / "v3-extra.txt").write_bytes(extra_bytes)
    (windows / "normal.txt").write_text("plain utf-8 evidence\n", encoding="utf-8")

    target = tmp_path / "staged"
    transforms = module.stage_quality_for_hf(source, target)
    by_original = {row["original_path"]: row for row in transforms}

    assert not (target / "external" / "windows" / "capture.txt").exists()
    assert not (target / "external" / "windows" / "v3-extra.txt").exists()
    assert (target / "external" / "windows" / "normal.txt").read_text(encoding="utf-8") == "plain utf-8 evidence\n"
    for name, expected in (("capture.txt", capture_bytes), ("v3-extra.txt", extra_bytes)):
        stored = target / "external" / "windows" / f"{name}.gz"
        assert gzip.decompress(stored.read_bytes()) == expected
        key = f"external/windows/{name}"
        assert by_original[key]["stored_path"] == f"external/windows/{name}.gz"
        assert by_original[key]["original_sha256"] == module.sha256_file(source / key)
