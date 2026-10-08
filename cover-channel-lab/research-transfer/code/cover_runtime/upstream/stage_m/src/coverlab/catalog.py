from __future__ import annotations

from typing import Iterable

from .scenarios import Scenario, SCENARIOS as BASE_SCENARIOS
from .scenarios_extra import EXTRA_SCENARIOS

SCENARIOS: tuple[Scenario, ...] = BASE_SCENARIOS + EXTRA_SCENARIOS
BY_ID = {s.scenario_id: s for s in SCENARIOS}


def select(stage: str, shard: int = 0, shards: int = 1) -> list[Scenario]:
    if stage == "parser": base = list(SCENARIOS[:60])
    elif stage == "core": base = [s for s in SCENARIOS if s.family in {"uri","header","custom_header","body","response","syntax","timing"}]
    elif stage == "web": base = [s for s in SCENARIOS if s.family in {"websocket","http2","http3","sse","longpoll","grpc"}]
    elif stage == "challenge": base = [s for s in SCENARIOS if s.family in {"browser","tunnel","tls","lots","mqtt_ws","doh","http3","connect","masque","webtransport","privacy"}]
    elif stage == "all": base = list(SCENARIOS)
    else: raise ValueError(f"unknown stage: {stage}")
    return [s for i, s in enumerate(base) if i % shards == shard]


def iter_pairs(items: Iterable[Scenario]):
    for scenario in items:
        yield scenario, True
        yield scenario, False
