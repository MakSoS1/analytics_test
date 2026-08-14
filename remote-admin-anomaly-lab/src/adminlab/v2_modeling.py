from __future__ import annotations

import pandas as pd


FORBIDDEN_FEATURE_COLUMNS = {
    "label_binary",
    "label_family",
    "split",
    "challenge_reason",
    "scenario_id",
    "campaign_id",
    "session_id",
    "flow_uid",
    "pair_id",
    "campaign_type",
    "behavior_profile",
    "intent_profile",
    "historical_relation",
    "sequence_profile",
    "implementation_id",
    "environment_id",
    "generator_seed",
    "netem_profile",
    "src_host_id",
    "dst_host_id",
    "src_ip",
    "dst_ip",
    "persona_id",
    "task_id",
    "calendar_id",
    "wire_fidelity",
    "semantic_fidelity",
    "ground_truth_source",
    "client_stack",
    "server_stack",
}


def training_mask(labels: pd.DataFrame) -> pd.Series:
    """Return the only rows permitted to fit V2 supervised models.

    Environment B (Windows native) and Environment C (LANL) are external
    holdouts by design. Even a row whose split is accidentally marked train is
    excluded unless it comes from the Linux V2 environment.
    """
    required = {"environment_id", "split"}
    missing = required - set(labels.columns)
    if missing:
        raise ValueError(f"labels missing training boundary columns: {sorted(missing)}")
    return labels["environment_id"].astype(str).eq("linux_v2") & labels["split"].astype(str).eq("train")


def assert_feature_frame_safe(frame: pd.DataFrame) -> None:
    leaked = sorted(FORBIDDEN_FEATURE_COLUMNS & set(map(str, frame.columns)))
    if leaked:
        raise ValueError(f"forbidden V2 model features present: {leaked}")

    bad_objects: list[str] = []
    for column in frame.columns:
        if pd.api.types.is_object_dtype(frame[column]) or pd.api.types.is_string_dtype(frame[column]):
            bad_objects.append(str(column))
    if bad_objects:
        raise ValueError(f"non-numeric V2 model features require explicit encoding: {sorted(bad_objects)}")

    if frame.empty:
        raise ValueError("V2 feature frame is empty")
