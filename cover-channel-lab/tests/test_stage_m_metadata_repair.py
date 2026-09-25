from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from coverlab.repair_stage_m_metadata import (
    PROFILES,
    profile_for_shard,
    repair_release,
    verify_release,
)


def test_profile_mapping_repeats_every_five_shards():
    assert [profile_for_shard(i) for i in range(10)] == list(PROFILES) * 2


def test_lossless_metadata_repair(tmp_path: Path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    name = "M-positive-03"

    (source / "bronze" / name / "captures").mkdir(parents=True)
    (source / "bronze" / name / "manifests").mkdir(parents=True)
    (source / "silver" / name / "normalized").mkdir(parents=True)
    (source / "quality" / name).mkdir(parents=True)

    pcap = source / "bronze" / name / "captures" / f"{name}.pcap.zst"
    pcap.write_bytes(b"immutable-wire-bytes")

    rows = [
        {
            "campaign_id": "m-00003",
            "label_binary": 1,
            "netem_profile": "clean",
            "network_profile_id": "clean",
            "leave_one_network_group": "clean",
        },
        {
            "campaign_id": "m-00023",
            "label_binary": 1,
            "netem_profile": "clean",
            "network_profile_id": "clean",
            "leave_one_network_group": "clean",
        },
    ]
    campaign_jsonl = source / "bronze" / name / "manifests" / "campaigns.jsonl"
    campaign_jsonl.write_text("\n".join(json.dumps(x) for x in rows) + "\n")

    df = pd.DataFrame(rows)
    df.to_parquet(source / "silver" / name / "normalized" / "campaigns.parquet", index=False)

    (source / "stage_m_inventory.json").write_text(json.dumps({"netem": {"clean": 2}}) + "\n")
    (source / "bronze" / name / "reproducibility.json").write_text(json.dumps({"github_sha": "abc"}) + "\n")

    report = repair_release(source, out, shard=3, source_run_id=36129636166)
    assert report["passed"]
    assert report["pcap_bytes_unchanged"]
    assert report["network_profile"] == "lossy_wifi"
    assert (out / "bronze" / name / "captures" / f"{name}.pcap.zst").read_bytes() == b"immutable-wire-bytes"

    fixed = [json.loads(x) for x in (out / "bronze" / name / "manifests" / "campaigns.jsonl").read_text().splitlines()]
    assert {r["network_profile_id"] for r in fixed} == {"lossy_wifi"}
    assert {r["netem_profile"] for r in fixed} == {"lossy_wifi"}
    assert {r["leave_one_network_group"] for r in fixed} == {"lossy_wifi"}
    assert {r["network_profile_source_shard"] for r in fixed} == {3}

    pdf = pd.read_parquet(out / "silver" / name / "normalized" / "campaigns.parquet")
    assert set(pdf["network_profile_id"].astype(str)) == {"lossy_wifi"}

    check = verify_release(out, shard=3, source_run_id=36129636166)
    assert check["passed"]
