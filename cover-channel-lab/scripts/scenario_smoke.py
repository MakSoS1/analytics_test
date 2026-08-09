#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

# Importing the package installs the safe protocol dispatch wrappers and extends
# the base catalog with future H3/CONNECT/WebTransport scenarios.
import coverlab  # noqa: F401
from coverlab.run_campaign import run
from coverlab.scenarios import SCENARIOS


def client_for(s) -> str:
    if s.family == "browser":
        return "browser_chromium"
    if s.transport == "h2" or s.family in {"http2", "grpc"}:
        return "python_httpx_h2"
    return "python_httpx"


def _normalize_g_manifest(manifest: Path, campaign_id: str, result: dict) -> None:
    if not campaign_id.startswith("g-"):
        return
    updates = {
        "label_binary": 0,
        "label_family": "benign",
        "label_intent": "benign",
        "attack_mapping": [],
        "experiment_stage": "G_trusted_background",
        "dataset_role": "hard_negative",
        "source_family": "trusted_site_inspired",
        "target_task": "cover_channel_detection",
    }
    result.update(updates)
    lines = manifest.read_text().splitlines()
    for i in range(len(lines) - 1, -1, -1):
        row = json.loads(lines[i])
        if str(row.get("campaign_id")) == campaign_id:
            row.update(updates)
            lines[i] = json.dumps(row, separators=(",", ":"), default=str)
            manifest.write_text("\n".join(lines) + "\n")
            return
    raise RuntimeError(f"missing smoke campaign in manifest: {campaign_id}")


def invoke(scenario_id: str, variant: str, campaign_id: str, seed: int, events: int,
           client_impl: str, manifest: Path, events_out: Path) -> dict:
    args = SimpleNamespace(
        scenario=scenario_id,
        variant=variant,
        seed=seed,
        campaign_id=campaign_id,
        run_id="smoke",
        persona="Victim-2-Dev",
        source_ip="10.20.0.11",
        events=events,
        client_impl=client_impl,
        state="/tmp/coverlab_server_state.json",
        manifest=str(manifest),
        events_out=str(events_out),
        capture_file="smoke-catalog.pcap",
    )
    result = run(args)
    if result.get("status") != "success":
        raise RuntimeError(f"{campaign_id}: status={result.get('status')}")
    _normalize_g_manifest(manifest, campaign_id, result)
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest = out / "campaigns.jsonl"
    events_out = out / "events.jsonl"
    manifest.write_text("")
    events_out.write_text("")

    family_counts: Counter[str] = Counter()
    transport_counts: Counter[str] = Counter()
    total = 0

    # These families are explicitly hard-negative/background by design. In
    # particular CC_OHTTP_01 is an OHTTP-like privacy fixture whose purpose is
    # to ensure opaque encrypted binary traffic isn't automatically called a
    # covert channel. It must never be smoke-tested as a positive attack.
    always_benign_families = {"lots", "privacy"}

    for idx, scenario in enumerate(SCENARIOS):
        event_count = 2 if scenario.family in {"timing", "websocket", "http2", "grpc", "sse", "longpoll"} else 1
        variants = ("benign",) if scenario.family in always_benign_families else ("suspicious", "benign")
        for v_idx, variant in enumerate(variants):
            campaign_id = f"g-smoke-catalog-{idx:03d}-{v_idx}" if scenario.family == "lots" else f"smoke-catalog-{idx:03d}-{v_idx}"
            result = invoke(
                scenario.scenario_id, variant, campaign_id, 91000000 + idx * 10 + v_idx,
                event_count, client_for(scenario), manifest, events_out,
            )
            if scenario.family in always_benign_families:
                if result.get("label_binary") != 0 or result.get("label_intent") != "benign":
                    raise RuntimeError(f"{scenario.scenario_id}: hard-negative smoke leaked positive label: {result}")
            else:
                expected = 1 if variant == "suspicious" else 0
                if result.get("label_binary") != expected:
                    raise RuntimeError(f"{scenario.scenario_id}/{variant}: label_binary={result.get('label_binary')} expected={expected}")
            family_counts[scenario.family] += 1
            transport_counts[scenario.transport] += 1
            total += 1

    generic_clients = ["python_httpx", "curl_linux", "node_fetch", "go_nethttp", "python_stdlib"]
    for idx, client in enumerate(generic_clients):
        result = invoke("CC_URI_01", "benign", f"smoke-client-{idx:02d}", 92000000 + idx, 1, client, manifest, events_out)
        if result.get("label_binary") != 0:
            raise RuntimeError(f"client smoke {client} produced wrong label")
        total += 1

    seq = invoke("CC_HDR_01", "suspicious", "c-smoke-00-00", 93000000, 60, "python_httpx", manifest, events_out)
    if seq.get("label_binary") != 1:
        raise RuntimeError("sequence smoke lost suspicious label")
    total += 1

    g_candidates = []
    for family in ("lots", "mqtt_ws", "doh", "browser"):
        match = next((s for s in SCENARIOS if s.family == family), None)
        if match is not None:
            g_candidates.append(match)
    for idx, scenario in enumerate(g_candidates):
        result = invoke(
            scenario.scenario_id, "suspicious", f"g-smoke-contract-{idx:02d}",
            94000000 + idx, 1, client_for(scenario), manifest, events_out,
        )
        if (
            result.get("label_binary") != 0
            or result.get("label_intent") != "benign"
            or result.get("experiment_stage") != "G_trusted_background"
            or result.get("dataset_role") != "hard_negative"
        ):
            raise RuntimeError(f"Stage G contract failed for {scenario.scenario_id}: {result}")
        total += 1

    rows = [json.loads(line) for line in manifest.read_text().splitlines() if line.strip()]
    ids = [r["campaign_id"] for r in rows]
    if len(ids) != len(set(ids)):
        raise RuntimeError("duplicate campaign IDs in smoke manifest")
    if len(rows) != total:
        raise RuntimeError(f"smoke manifest rows={len(rows)} expected={total}")

    summary = {
        "status": "pass",
        "scenario_catalog_size": len(SCENARIOS),
        "campaigns": total,
        "families_exercised": sorted(family_counts),
        "transport_counts": dict(sorted(transport_counts.items())),
        "generic_clients": generic_clients,
        "always_benign_families": sorted(always_benign_families),
        "sequence_transactions": 60,
        "stage_g_contract_cases": [s.scenario_id for s in g_candidates],
        "dataset_contract_revision": 2,
    }
    (out / "smoke_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
