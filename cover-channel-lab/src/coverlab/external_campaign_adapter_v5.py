from __future__ import annotations

import argparse
import json
from pathlib import Path


def framework_campaign(row: dict) -> dict:
    campaign = dict(row)
    campaign.setdefault("scenario_id", "EXTERNAL_FRAMEWORK")
    campaign.setdefault("expected_events", 0)
    campaign.setdefault("attack_mapping", [])
    campaign.setdefault("persona", "external_framework")
    campaign.setdefault("client_impl", str(row.get("framework", "external_framework")))
    campaign.setdefault("visibility_mode", "opaque_and_ground_truth")
    campaign.setdefault("inspection_policy", "bypass")
    campaign.setdefault("sni_visibility", "clear")
    campaign.setdefault("status", "success")
    campaign.setdefault("external_dependency", False)
    return campaign


def ech_campaign(row: dict) -> dict:
    campaign = dict(row)
    campaign.setdefault("scenario_id", "EXTERNAL_ECH")
    campaign.setdefault("expected_events", 0)
    campaign.setdefault("attack_mapping", [])
    campaign.setdefault("persona", "external_ech")
    campaign.setdefault("client_impl", "external_ech_client")
    campaign.setdefault("visibility_mode", "opaque_and_ground_truth")
    campaign.setdefault("inspection_policy", "bypass")
    hidden = bool(row.get("ech_enabled")) and str(row.get("ech_mode", "")) in {
        "accepted_h2",
        "accepted_h3",
        "shared_frontend_benign",
        "shared_frontend_suspicious",
    }
    campaign.setdefault("sni_visibility", "hidden" if hidden else "clear")
    campaign.setdefault("status", "success")
    campaign.setdefault("external_dependency", False)
    return campaign


def prepare(kind: str, manifest: Path, evidence: Path, out: Path) -> dict:
    rows = [json.loads(x) for x in manifest.read_text().splitlines() if x.strip()]
    adapter = framework_campaign if kind == "framework" else ech_campaign
    prepared = []
    for row in rows:
        cid = str(row["campaign_id"])
        pcap = evidence / str(row["pcap_file"])
        if not pcap.is_file():
            raise FileNotFoundError(f"missing pcap for {cid}: {pcap}")
        stage = out / cid / "stage"
        manifests = stage / "manifests"
        manifests.mkdir(parents=True, exist_ok=True)
        campaign = adapter(row)
        line = json.dumps(campaign, separators=(",", ":"), sort_keys=True) + "\n"
        (manifests / "campaigns.jsonl").write_text(line)
        (manifests / "events.jsonl").write_text("")
        (manifests / "decrypted_transactions.jsonl").write_text("")
        (stage / "campaigns.jsonl").write_text(line)
        (stage / "events.jsonl").write_text("")
        prepared.append(cid)
    return {"kind": kind, "campaigns": len(prepared), "campaign_ids": prepared}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", required=True, choices=("framework", "ech"))
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--evidence-root", required=True)
    ap.add_argument("--out-root", required=True)
    a = ap.parse_args()
    report = prepare(a.kind, Path(a.manifest), Path(a.evidence_root), Path(a.out_root))
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
