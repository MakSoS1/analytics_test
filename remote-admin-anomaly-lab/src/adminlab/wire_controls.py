from __future__ import annotations

import hashlib
import random
from dataclasses import replace
from typing import Iterable

from .manifest import SessionRecord


def _seed_for(record: SessionRecord, seed: int) -> int:
    # Counterfactual pairs intentionally share one key, so all observable wire
    # controls are identical. Outside pairs, session identity provides diversity.
    identity = record.pair_id or record.session_id
    payload = f"{seed}|{identity}|{record.protocol}|{record.behavior_profile}".encode()
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def materialize_wire_controls(
    records: Iterable[SessionRecord], behavior_config: dict, *, seed: int
) -> list[SessionRecord]:
    profiles = behavior_config.get("behavior_profiles", {})
    out: list[SessionRecord] = []
    for record in records:
        if record.behavior_profile not in profiles:
            # Compatibility for legacy manifests: never branch on label.
            out.append(replace(record, wire_attempts=1, wire_transfer_bytes=0))
            continue
        cfg = profiles[record.behavior_profile]
        rng = random.Random(_seed_for(record, seed))
        attempts_range = list(cfg.get("attempts", [1, 1]))
        transfer_range = list(cfg.get("transfer_bytes", [0, 0]))
        attempts = rng.randint(int(attempts_range[0]), int(attempts_range[1]))
        transfer = rng.randint(int(transfer_range[0]), int(transfer_range[1]))
        out.append(
            replace(
                record,
                wire_attempts=max(1, attempts),
                wire_transfer_bytes=max(0, transfer),
            )
        )
    return out
