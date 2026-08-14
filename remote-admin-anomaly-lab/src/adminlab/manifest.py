from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class SessionRecord:
    campaign_id: str
    scenario_id: str
    session_id: str
    pair_id: str
    label_binary: int
    label_family: str
    mitre_technique: str
    src_role: str
    dst_role: str
    src_host_id: str
    dst_host_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    action: str
    wire_fidelity: str
    semantic_fidelity: str
    ground_truth_source: str
    netem_profile: str
    generator_seed: int
    start_ts: str
    end_ts: str
    status: str
    persona_id: str = ""
    task_id: str = ""
    calendar_id: str = ""
    intent_profile: str = ""
    behavior_profile: str = ""
    campaign_type: str = ""
    historical_relation: str = ""
    auth_outcome: str = "success"
    client_stack: str = ""
    simulated_day: int = 0

    def __post_init__(self) -> None:
        if self.label_binary not in (0, 1):
            raise ValueError("label_binary must be 0 or 1")
        if self.ground_truth_source != "scenario_orchestrator":
            raise ValueError("ground truth must originate from scenario_orchestrator")
        # src_port=0 means "unknown until observed on the real wire". The
        # orchestrator must not invent the ephemeral port chosen by a real client.
        if self.src_port < 0 or self.dst_port <= 0:
            raise ValueError("src_port must be >= 0 and dst_port must be positive")
        if self.simulated_day < 0:
            raise ValueError("simulated_day must be non-negative")

    def to_dict(self) -> dict:
        return asdict(self)


def write_sessions(records: Iterable[SessionRecord], path: Path | str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = [record.to_dict() for record in records]
    if target.suffix == ".jsonl":
        with target.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        return
    if target.suffix == ".parquet":
        import pandas as pd

        pd.DataFrame(rows).to_parquet(target, index=False)
        return
    raise ValueError(f"unsupported manifest format: {target.suffix}")
