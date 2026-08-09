from __future__ import annotations

"""Correctness wrapper for corpus orchestration.

The historical source plan used a LOTS-inspired Stage G that mixed suspicious
and benign variants and normalized labels later.  For the Cover Channel target
this is unsafe: Stage G is a trusted-service hard-negative slice and must be
benign at generation time.  This module patches the orchestration entry point
before delegating to the original CLI so the wire traffic, campaign manifest,
events and split metadata all agree.
"""

from . import orchestrate as _base
from .browser_runtime import install as _install_browser_runtime
from .scenarios import BY_ID

# Browser families are generated through the same run_campaign module used by
# the rest of orchestration. Install the bounded cold-start implementation once
# before any worker begins producing campaigns.
_install_browser_runtime()

_original_invoke = _base.invoke


def _invoke_contract(
    scenario_id: str,
    suspicious: bool,
    seed: int,
    campaign_id: str,
    run_id: str,
    persona: str,
    source_ip: str,
    events: int,
    manifest,
    events_out,
    capture_file: str,
    config: dict,
):
    cfg = dict(config)

    if campaign_id.startswith("g-"):
        # Trusted-service-inspired traffic is a hard negative for this detector.
        # Force benign semantics BEFORE request/payload construction.
        suspicious = False
        cfg.update(
            {
                "experiment_stage": "G_trusted_background",
                "dataset_role": "hard_negative",
                "source_family": "trusted_site_inspired",
                "target_task": "cover_channel_detection",
            }
        )

    if campaign_id.startswith("d-") and suspicious:
        selected = BY_ID.get(scenario_id)
        if selected is not None and selected.family == "lots":
            # Mixed positive points must use an actual covert Web carrier.  Keep
            # LOTS only as ambient benign traffic instead of teaching LOTS=attack.
            cfg["requested_scenario_id"] = scenario_id
            cfg["positive_substitution_reason"] = "trusted_service_not_positive_target"
            scenario_id = "CC_WS_09"

    return _original_invoke(
        scenario_id,
        suspicious,
        seed,
        campaign_id,
        run_id,
        persona,
        source_ip,
        events,
        manifest,
        events_out,
        capture_file,
        cfg,
    )


_base.invoke = _invoke_contract


if __name__ == "__main__":
    _base.main()
