"""Safe network-only covert-channel traffic generation lab."""

from __future__ import annotations

import json
from pathlib import Path

__version__ = "1.2.0"

# Extend the source-plan catalog with future-transport challenge scenarios before
# orchestrate imports SCENARIOS/BY_ID from the base module.
from . import scenarios as _base_scenarios
from .scenarios_extra import EXTRA_SCENARIOS as _extra_scenarios

if not any(s.scenario_id == "CC_H3_01" for s in _base_scenarios.SCENARIOS):
    _base_scenarios.SCENARIOS = _base_scenarios.SCENARIOS + _extra_scenarios
    _base_scenarios.BY_ID.update({s.scenario_id: s for s in _extra_scenarios})

from . import nuisance as _nuisance
from . import run_campaign as _run_campaign

# Keep a stable reference to the ordinary campaign runner. Its module-level
# value/body helpers are replaced below, so even this saved function consumes
# the runtime nuisance context when it constructs actual requests.
_original_run = _run_campaign.run
_run_campaign.encoded_value = _nuisance.encoded_value
_run_campaign.entropy_blob = _nuisance.entropy_blob

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
            lines[idx] = json.dumps(record, separators=(",", ":"), default=str)
            p.write_text("\n".join(lines) + "\n")
            return


def _run_with_transport_dispatch(args):
    token = _nuisance.push(args.campaign_id)
    try:
        nuisance_fields = _nuisance.current()

        # Stage C campaign IDs are c-<profile>-<rep>. A sequence is generated as
        # one campaign with 60 actual multi-phase transactions, not 60 repeats of
        # one carrier. The parent ID is kept in server state and decrypted traces.
        if str(args.campaign_id).startswith("c-") and int(getattr(args, "events", 0)) == 60:
            from .sequence_campaign import run_sequence

            record = run_sequence(args, _original_run)
            record.update(nuisance_fields)
            _decorate_last_manifest(args.manifest, args.campaign_id, nuisance_fields)
            return record

        scenario = _base_scenarios.BY_ID[args.scenario]
        from . import protocol_dispatch as _protocol_dispatch

        # H3/gRPC/MQTT clients construct their message bytes outside
        # run_campaign.make_http, so route their synthetic payload helper through
        # the same nuisance context. This changes real frame/message content and
        # lengths, not just labels.
        _protocol_dispatch.synthetic_value = _nuisance.synthetic_bytes
        handled = _protocol_dispatch.run_protocol(args, scenario)
        if handled is not None:
            handled.update(nuisance_fields)
            _decorate_last_manifest(args.manifest, args.campaign_id, nuisance_fields)
            return handled

        record = _original_run(args)
        updates = dict(nuisance_fields)
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
        record.update(updates)
        _decorate_last_manifest(args.manifest, args.campaign_id, updates)
        return record
    finally:
        _nuisance.reset(token)


_run_campaign.run = _run_with_transport_dispatch
