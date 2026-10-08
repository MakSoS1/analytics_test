#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import coverlab  # noqa: F401 - installs runtime transport dispatch
from coverlab.run_campaign import run


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--persona-index", type=int, required=True, choices=range(4))
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    personas = [
        ("Victim-1-Office", "10.20.0.10"),
        ("Victim-2-Dev", "10.20.0.11"),
        ("Victim-3-DevOps", "10.20.0.30"),
        ("Victim-4-SOC", "10.20.0.31"),
    ]
    persona, source_ip = personas[args.persona_index]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest = out / "campaigns.jsonl"
    events_out = out / "events.jsonl"
    manifest.write_text("")
    events_out.write_text("")

    campaign_id = f"c-regression-{args.persona_index:02d}"
    ns = SimpleNamespace(
        scenario="CC_HDR_01",
        variant="suspicious",
        seed=95000000 + args.persona_index * 100003,
        campaign_id=campaign_id,
        run_id="sequence-concurrency-smoke",
        persona=persona,
        source_ip=source_ip,
        events=60,
        client_impl="python_httpx",
        state="/tmp/coverlab_server_state.json",
        manifest=str(manifest),
        events_out=str(events_out),
        capture_file="sequence-concurrency-smoke.pcap",
    )
    record = run(ns)
    rows = [json.loads(x) for x in manifest.read_text().splitlines() if x.strip()]
    events = [json.loads(x) for x in events_out.read_text().splitlines() if x.strip()]
    if record.get("status") != "success":
        raise RuntimeError(f"sequence status={record.get('status')}")
    if record.get("label_binary") != 1:
        raise RuntimeError(f"sequence label={record.get('label_binary')}")
    if len(rows) != 1:
        raise RuntimeError(f"manifest rows={len(rows)} expected=1")
    if len(events) != 60:
        raise RuntimeError(f"events={len(events)} expected=60")
    if record.get("scenario_id") != "SEQUENCE_MULTI_PHASE":
        raise RuntimeError(f"unexpected scenario={record.get('scenario_id')}")

    print(json.dumps({
        "status": "pass",
        "persona_index": args.persona_index,
        "persona": persona,
        "source_ip": source_ip,
        "campaign_id": campaign_id,
        "events": len(events),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
