from __future__ import annotations

"""Batch agent executed inside a real Linux client VM.

It consumes a pre-generated allowlisted VM plan and invokes the same Stage M
application stacks from the VM. The sensor captures packets externally; this
agent never writes packet bytes or creates PCAP files.
"""

import argparse
import json
import os
from pathlib import Path

from .stage_m import CampaignSpec, run_one

ALLOWED_FAMILIES = {
    "M-HTTPS-BEACON", "M-HTTPS-FRONT", "M-HTTPS-LOWENT", "M-HTTPS-FRAG",
    "M-HTTP-443", "M-DNS-BEACON", "M-DNS-BULK", "M-DOH", "M-DOQ",
    "M-DEAD-DROP", "M-WSS-LONG", "M-TUNNEL", "M-FALLBACK",
    "M-CLOUD-API", "M-TIMING-XCARRIER", "M-PUBSUB-MQTT",
    "M-GRPC-BIDI", "M-RMM-SHAPE",
}


def to_spec(row: dict) -> CampaignSpec:
    if row.get("family") not in ALLOWED_FAMILIES:
        raise ValueError(f"family not allowlisted: {row.get('family')}")
    if row.get("client_os") != "linux":
        raise ValueError("Linux agent received a non-Linux plan row")
    return CampaignSpec(
        index=int(row["spec_index"]),
        family=str(row["family"]),
        family_index=int(row["family_index"]),
        implementation_id=str(row["implementation_id"]),
        client_impl=str(row["client_impl"]),
        server_impl=str(row["server_impl"]),
        front_host=str(row.get("front_host") or ""),
        network_topology=str(row["network_topology"]),
        interval_seconds=float(row["interval_seconds"]),
        interval_bucket_seconds=int(row["interval_bucket_seconds"]),
        jitter_fraction=float(row["jitter_fraction"]),
        event_count=int(row["event_count"]),
        event_count_bucket=int(row["event_count_bucket"]),
        volume_mode=str(row["volume_mode"]),
        asymmetry=str(row["asymmetry"]),
        payload_mode=str(row["payload_mode"]),
        holdout_fold=int(row["holdout_fold"]),
    )


def run(plan: Path, out: Path, capture_file: str) -> dict:
    rows = [json.loads(x) for x in plan.read_text().splitlines() if x.strip()]
    out.mkdir(parents=True, exist_ok=True)
    campaigns = out / "campaigns.jsonl"
    events_path = out / "events.jsonl"
    count = 0
    with campaigns.open("w", encoding="utf-8") as cm, events_path.open("w", encoding="utf-8") as ev:
        for row in rows:
            if row.get("client_os") != "linux":
                continue
            spec = to_spec(row)
            seed = 27000000 + spec.index * 1009
            manifest, events = run_one(
                spec,
                seed,
                str(row["campaign_id"]),
                str(row["client_id"]),
                str(row["source_ip"]),
                capture_file,
            )
            manifest["implementation_id"] = row["implementation_id"]
            manifest["split_role"] = row["split_role"]
            manifest["training_eligible"] = bool(row["training_eligible"] and manifest.get("training_eligible"))
            manifest["capture_environment"] = "vm_wire"
            manifest["source_os"] = "linux"
            cm.write(json.dumps(manifest, separators=(",", ":"), default=str) + "\n")
            for event in events:
                event["source_os"] = "linux"
                ev.write(json.dumps(event, separators=(",", ":"), default=str) + "\n")
            count += 1
    result = {"campaigns": count, "positive_only": True, "capture_environment": "vm_wire"}
    print(json.dumps(result, sort_keys=True))
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--capture-file", default="capture.pcapng")
    a = ap.parse_args()
    os.environ["COVERLAB_ENVIRONMENT_TIER"] = "vm_wire"
    run(Path(a.plan), Path(a.out), a.capture_file)


if __name__ == "__main__":
    main()
