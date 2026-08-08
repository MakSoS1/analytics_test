"""Safe network-only covert-channel traffic generation lab."""

from __future__ import annotations

import json
from pathlib import Path

__version__ = "1.1.0"

# Keep the original source-plan catalog readable while extending it with the
# transport-future challenge corpus. Importing the package happens before any
# submodule imports, so existing `from .scenarios import SCENARIOS/BY_ID`
# consumers automatically receive the extended immutable tuple/map.
from . import scenarios as _base_scenarios
from .scenarios_extra import EXTRA_SCENARIOS as _extra_scenarios

if not any(s.scenario_id == "CC_H3_01" for s in _base_scenarios.SCENARIOS):
    _base_scenarios.SCENARIOS = _base_scenarios.SCENARIOS + _extra_scenarios
    _base_scenarios.BY_ID.update({s.scenario_id: s for s in _extra_scenarios})

# Route protocol families that require their own real stack before orchestrate
# imports `run` from run_campaign. This preserves the existing campaign API.
from . import run_campaign as _run_campaign

_original_run = _run_campaign.run

_TLS_FIDELITY = {
    "CC_TLS_01": "wire_real_default_tls_stack",
    "CC_TLS_02": "browser_like_http_headers_with_script_tls_not_utls_parroting",
    "CC_TLS_03": "tls_stack_diversity_fixture_not_randomized_clienthello",
    "CC_TLS_04": "ordinary_tls_connections_session_resumption_not_forced",
    "CC_TLS_05": "zero_rtt_capability_marker_not_wire_real_0rtt",
    "CC_TLS_06": "visibility_loss_metadata_fixture_not_wire_real_ech",
    "CC_TLS_07": "h2_fixture; real_h3_h2_h1_fallback_is_CC_H3_08",
    "CC_TLS_08": "shared_edge_label_fixture_same_local_edge",
    "CC_TLS_09": "certificate_rotation_label_fixture_static_cert_within_run",
    "CC_TLS_10": "inspection_bypass_ground_truth_fixture_not_actual_pinning",
}


def _decorate_last_manifest(path: str, campaign_id: str, updates: dict) -> None:
    p = Path(path)
    if not p.exists() or not updates:
        return
    lines = p.read_text().splitlines()
    for idx in range(len(lines) - 1, -1, -1):
        try:
            record = json.loads(lines[idx])
        except Exception:
            continue
        if str(record.get("campaign_id")) == str(campaign_id):
            record.update(updates)
            lines[idx] = json.dumps(record, separators=(",", ":"))
            p.write_text("\n".join(lines) + "\n")
            return


def _run_with_transport_dispatch(args):
    scenario = _base_scenarios.BY_ID[args.scenario]
    from .protocol_dispatch import run_protocol

    handled = run_protocol(args, scenario)
    if handled is not None:
        return handled

    record = _original_run(args)
    updates = {}
    if scenario.scenario_id in _TLS_FIDELITY:
        updates["implementation_fidelity"] = _TLS_FIDELITY[scenario.scenario_id]
    elif scenario.family == "browser" and getattr(args, "client_impl", "") == "browser_chromium":
        updates["implementation_fidelity"] = "wire_real_chromium_network_stack"
    elif scenario.transport == "h2":
        updates["implementation_fidelity"] = "wire_real_http2_via_httpx_h2"
    elif scenario.transport == "wss":
        updates["implementation_fidelity"] = "wire_real_websocket_over_tls"
    elif scenario.transport in {"http", "https"}:
        updates["implementation_fidelity"] = "wire_real_http_exchange"
    if updates:
        record.update(updates)
        _decorate_last_manifest(args.manifest, args.campaign_id, updates)
    return record


_run_campaign.run = _run_with_transport_dispatch
