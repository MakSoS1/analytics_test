from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Iterable, Mapping, Any


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
    server_stack: str = ""
    implementation_id: str = ""
    simulated_day: int = 0
    campaign_position: int = 0
    campaign_size: int = 1
    sequence_profile: str = "single_session"
    wire_attempts: int = 1
    wire_transfer_bytes: int = 0
    execution_start_ts: str = ""
    execution_end_ts: str = ""

    def __post_init__(self) -> None:
        if self.label_binary not in (0, 1):
            raise ValueError("label_binary must be 0 or 1")
        if self.ground_truth_source != "scenario_orchestrator":
            raise ValueError("ground truth must originate from scenario_orchestrator")
        if self.src_port < 0 or self.dst_port <= 0:
            raise ValueError("src_port must be >= 0 and dst_port must be positive")
        if self.simulated_day < 0:
            raise ValueError("simulated_day must be non-negative")
        if self.campaign_position < 0:
            raise ValueError("campaign_position must be non-negative")
        if self.campaign_size <= 0 or self.campaign_position >= self.campaign_size:
            raise ValueError("campaign position/size invalid")
        if self.wire_attempts <= 0:
            raise ValueError("wire_attempts must be positive")
        if self.wire_transfer_bytes < 0:
            raise ValueError("wire_transfer_bytes must be non-negative")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SessionRecord":
        """Deserialize a manifest row while remaining forward-compatible.

        Unknown keys are ignored so evidence produced by a newer writer can still
        be inspected by older readers. Missing optional fields use dataclass
        defaults; missing required fields still fail through the constructor.
        """
        allowed = {field.name for field in fields(cls)}
        kwargs = {str(key): item for key, item in value.items() if str(key) in allowed}
        return cls(**kwargs)


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
