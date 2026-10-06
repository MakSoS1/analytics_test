from __future__ import annotations

import argparse
from pathlib import Path

from .orchestrate import CLIENTS, PERSONAS, SIZES, TIMINGS, TRANSFORMS, invoke
from .scenarios import SCENARIOS


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--capture-file", required=True)
    p.add_argument("--persona-index", type=int, choices=[0, 1, 2, 3], required=True)
    p.add_argument("--seed", type=int, default=26082323)
    args = p.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest = out / "campaigns.jsonl"
    events = out / "events.jsonl"
    manifest.touch()
    events.touch()

    candidates = [
        s for s in SCENARIOS
        if s.family in {
            "uri", "header", "custom_header", "body", "timing", "websocket",
            "http2", "http3", "tunnel", "grpc", "mqtt_ws", "doh",
        }
        and s.scenario_id not in {"CC_BROWSER_01", "CC_BROWSER_02", "CC_BROWSER_03"}
    ]

    # 500 actual suspicious sessions. This is a deterministic randomized
    # nuisance holdout, not a model-in-the-loop black-box optimizer: candidates
    # are generated first and scored against the frozen B3 model afterwards.
    # LOTS/trusted-service scenarios are deliberately excluded from positives.
    for i in range(500):
        persona_idx = i % len(PERSONAS)
        if persona_idx != args.persona_index:
            continue
        scenario = candidates[(i * 23 + i // 11) % len(candidates)]
        persona, ip = PERSONAS[persona_idx]
        client = CLIENTS[(i * 5 + 1) % len(CLIENTS)]
        event_count = 1 + (i % 8)
        cid = f"adv-{i:04d}"
        config = {
            "experiment_stage": "F_adversarial_challenge",
            "challenge_kind": "randomized_nuisance_holdout",
            "configuration_id": f"ADV-{i:04d}",
            "adversarial_candidate_index": i,
            "transform_chain": [TRANSFORMS[(i * 3) % len(TRANSFORMS)]],
            "timing_profile": TIMINGS[(i * 7) % len(TIMINGS)],
            "client_impl": client,
            "payload_size_class": SIZES[(i * 11) % len(SIZES)],
            "open_set": True,
            "adversarial_holdout": True,
            "search_method": "deterministic_randomized_nuisance_no_model_feedback",
        }
        invoke(
            scenario.scenario_id,
            True,
            args.seed + i * 101,
            cid,
            "run-00",
            persona,
            ip,
            event_count,
            manifest,
            out / "events.jsonl",
            args.capture_file,
            config,
        )

    print(f"adversarial persona={args.persona_index} campaigns={sum(1 for _ in manifest.open())}")


if __name__ == "__main__":
    main()
