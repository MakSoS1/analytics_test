"""Safe network-only covert-channel traffic generation lab."""

from __future__ import annotations

import json
import time as _time
from contextlib import asynccontextmanager
from pathlib import Path

__version__ = "1.3.0"

# aioquic 1.2.x exposes SNI through QuicConfiguration.server_name; its
# asyncio.connect() does not accept a server_name keyword. Keep compatibility in
# one place because both the readiness client and the H3 scenario dispatcher use
# the same helper.
import aioquic.asyncio.client as _aioquic_client
from aioquic.quic.configuration import QuicConfiguration as _QuicConfiguration

_aioquic_connect = _aioquic_client.connect


@asynccontextmanager
async def _aioquic_connect_compat(host, port, *, server_name=None, configuration=None, **kwargs):
    if configuration is None:
        configuration = _QuicConfiguration(is_client=True)
    if server_name is not None:
        configuration.server_name = server_name
    async with _aioquic_connect(host, port, configuration=configuration, **kwargs) as protocol:
        yield protocol


_aioquic_client.connect = _aioquic_connect_compat

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

# A corpus shard opens hundreds of short WSS connections from four isolated
# personas. A transient accept/backlog delay must not discard a whole shard, but
# retries must remain bounded so a genuinely dead fixture still fails loudly.
_ws_connect_raw = _run_campaign.ws_connect


def _ws_connect_resilient(*args, **kwargs):
    kwargs.setdefault("proxy", None)
    kwargs.setdefault("compression", None)
    kwargs.setdefault("open_timeout", 6)
    kwargs.setdefault("close_timeout", 2)
    last = None
    for attempt in range(3):
        try:
            return _ws_connect_raw(*args, **kwargs)
        except (TimeoutError, OSError) as exc:
            last = exc
            if attempt < 2:
                _time.sleep((0.10, 0.30)[attempt])
    assert last is not None
    raise last


_run_campaign.ws_connect = _ws_connect_resilient

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
    campaign_id = str(args.campaign_id)

    # The original source plan called Stage G "LOTS-inspired". For a Cover
    # Channel detector that traffic must never be a positive target merely
    # because it uses a trusted service. Keep the slice as benign hard-negative
    # background and preserve its value for false-positive testing.
    if campaign_id.startswith("g-"):
        args.variant = "benign"

    # Mixed captures may still draw a LOTS-family scenario as ambient traffic.
    # If the selected prevalence point is positive, use an actual WSS covert
    # carrier instead; otherwise we would silently teach LOTS == cover channel.
    selected = _base_scenarios.BY_ID[args.scenario]
    if campaign_id.startswith("d-") and getattr(args, "variant", "") == "suspicious" and selected.family == "lots":
        args.scenario = "CC_WS_09"
        selected = _base_scenarios.BY_ID[args.scenario]

    token = _nuisance.push(args.campaign_id)
    try:
        nuisance_fields = _nuisance.current()

        # Stage C campaign IDs are c-<profile>-<rep>. A sequence is generated as
        # one campaign with 60 actual multi-phase transactions, not 60 repeats of
        # one carrier. The parent ID is kept in server state and decrypted traces.
        if campaign_id.startswith("c-") and int(getattr(args, "events", 0)) == 60:
            from .sequence_campaign import run_sequence

            record = run_sequence(args, _original_run)
            record.update(nuisance_fields)
            _decorate_last_manifest(args.manifest, args.campaign_id, nuisance_fields)
            return record

        scenario = selected
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
        if campaign_id.startswith("g-"):
            updates.update({
                "dataset_role": "hard_negative",
                "source_family": "trusted_site_inspired",
                "target_task": "cover_channel_detection",
            })
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
