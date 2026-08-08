from __future__ import annotations

import copy
import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# Ten protocol/behavior phases repeated six times = 60 actual transactions.
# They intentionally include registration, heartbeat, noop-like polling,
# command receipt, result upload, retry/backoff, reconnect and sleep-profile
# changes instead of replaying one request 60 times.
PHASES = (
    ("registration", "CC_HDR_01"),
    ("heartbeat", "CC_TIME_01"),
    ("noop_poll", "CC_URI_05"),
    ("command_poll", "CC_RESP_08"),
    ("result_upload", "CC_BODY_02"),
    ("retry_backoff", "CC_TIME_07"),
    ("reconnect", "CC_WS_09"),
    ("bulk_result", "CC_BODY_04"),
    ("sleep_change", "CC_TIME_03"),
    ("rotating_poll", "CC_URI_04"),
)


def run_sequence(args, original_run) -> dict:
    started = _now()
    all_events: list[dict] = []
    first_record: dict | None = None
    phase_trace: list[str] = []

    with tempfile.TemporaryDirectory(prefix=f"coverlab-seq-{args.campaign_id}-") as td:
        root = Path(td)
        tmp_manifest = root / "campaigns.jsonl"
        tmp_events = root / "events.jsonl"
        tmp_manifest.touch()
        tmp_events.touch()

        for idx in range(60):
            phase_name, scenario_id = PHASES[idx % len(PHASES)]
            phase_trace.append(phase_name)
            inner = copy.copy(args)
            inner.scenario = scenario_id
            inner.events = 1
            # Keep the parent campaign ID. Server-side decrypted traces are then
            # attributable to the same campaign even while scenario/state changes.
            inner.campaign_id = args.campaign_id
            inner.seed = int(args.seed) + idx * 1009
            inner.manifest = str(tmp_manifest)
            inner.events_out = str(tmp_events)
            record = original_run(inner)
            if first_record is None:
                first_record = dict(record)

        for line in tmp_events.read_text().splitlines():
            if not line.strip():
                continue
            ev = json.loads(line)
            seq_idx = len(all_events)
            phase_name, scenario_id = PHASES[seq_idx % len(PHASES)]
            ev["event_id"] = f"{args.campaign_id}-e{seq_idx:03d}"
            ev["campaign_id"] = args.campaign_id
            ev["run_id"] = args.run_id
            ev["scenario_id"] = "SEQUENCE_MULTI_PHASE"
            ev["phase_name"] = phase_name
            ev["phase_scenario_id"] = scenario_id
            all_events.append(ev)

    if first_record is None or len(all_events) != 60:
        raise RuntimeError(f"sequence campaign produced {len(all_events)} events, expected 60")

    suspicious = args.variant == "suspicious"
    record = first_record
    record.update(
        {
            "campaign_id": args.campaign_id,
            "run_id": args.run_id,
            "scenario_id": "SEQUENCE_MULTI_PHASE",
            "label_binary": 1 if suspicious else 0,
            "label_family": "multi_phase_web_c2" if suspicious else "benign",
            "label_intent": "c2" if suspicious else "benign",
            "protocol": "mixed_http_https_wss",
            "carrier": "multi_phase",
            "attack_mapping": ["T1071.001", "T1001.003", "T1041"] if suspicious else [],
            "started_at": started,
            "ended_at": _now(),
            "expected_events": 60,
            "status": "success",
            "generator_name": "coverlab_sequence_campaign",
            "generator_version": "1.0.0",
            "implementation_fidelity": "wire_real_multi_phase_sequence",
            "sequence_profile": list(PHASES),
            "sequence_phase_count": len(PHASES),
            "sequence_repetitions": 6,
            "sequence_actual_stacks": [args.client_impl, "python_websockets_wss"],
            "plaintext_sha256": hashlib.sha256(
                ("SEQUENCE:" + args.variant + ":" + args.campaign_id).encode()
            ).hexdigest(),
        }
    )

    with open(args.manifest, "a", encoding="utf-8") as out:
        out.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
    with open(args.events_out, "a", encoding="utf-8") as out:
        for ev in all_events:
            out.write(json.dumps(ev, separators=(",", ":"), default=str) + "\n")
    return record
