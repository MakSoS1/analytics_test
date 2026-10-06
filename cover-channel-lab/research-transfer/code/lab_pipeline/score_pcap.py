#!/usr/bin/env python3
"""Score a capture file the way the sensor would: pcap in, per-flow verdicts out.

Everything else in this package works on a labelled corpus. This one takes a
file and nothing else — no metadata, no family, no declared route — because
that is the only honest way to demonstrate the detector: whatever the model is
told here, the sensor could also have worked out for itself from the packets.

The pieces are the shipped ones, not copies. `pcap_packets` returns the packet
dicts the corpus was built from, `flow_observation.ObservationTable` is the
same reducer the sensor runs, and `route_contract.classify_route` picks the
route from the transport alone.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
from lab_pipeline.flow_observation import ObservationTable, Packet  # noqa: E402
from lab_pipeline.online_schema import FEATURE_NAMES  # noqa: E402
from lab_pipeline.pcap_packets import read_pcap_packets  # noqa: E402
from lab_pipeline.route_bundle import load_route_model  # noqa: E402
from lab_pipeline.route_contract import ROUTES, classify_route  # noqa: E402

# The same clock-driven sweep interval the offline extractor and the sensor use;
# a different one would draw flow-instance boundaries in a different place.
SWEEP_INTERVAL_S = 10.0


class MissingRouteModel(RuntimeError):
    """A flow routed somewhere no model was supplied for."""


@dataclass(frozen=True)
class Flow:
    """One observed flow: what the reducer emitted, plus where it routes."""

    flow_instance_id: str
    route: str
    proto: str
    features: dict[str, float]
    scorable: bool
    decision_reason: str
    start_observed: bool
    packets: int
    decision_offset_s: float


def _flow_key(packet: dict[str, Any]) -> str:
    a = (packet["src"], packet["sport"])
    b = (packet["dst"], packet["dport"])
    lo, hi = sorted((a, b))
    return f"{lo[0]}:{lo[1]}-{hi[0]}:{hi[1]}-{packet['proto']}"


def observe_flows(pcap: Path) -> list[Flow]:
    """Every flow in the capture, reduced exactly as the corpus rows were."""
    packets = read_pcap_packets(Path(pcap))
    if not packets:
        return []
    packets.sort(key=lambda p: p["ts"])
    table = ObservationTable()
    initiators: dict[str, tuple[str, int]] = {}
    peers: dict[str, tuple[str, int]] = {}
    emitted: list[dict[str, Any]] = []
    counts: dict[str, int] = {}

    next_sweep: float | None = None
    for packet in packets:
        if next_sweep is None:
            next_sweep = packet["ts"] + SWEEP_INTERVAL_S
        elif packet["ts"] >= next_sweep:
            for record in table.sweep(packet["ts"]):
                record["_key"] = record["flow_instance_id"].rsplit("#", 1)[0]
                emitted.append(record)
            next_sweep = packet["ts"] + SWEEP_INTERVAL_S
        key = _flow_key(packet)
        if key not in initiators:
            initiators[key] = (packet["src"], packet["sport"])
            peers[key] = (packet["dst"], packet["dport"])
        counts[key] = counts.get(key, 0) + 1
        flags = str(packet.get("flags") or "")
        record = table.observe(key, Packet(
            ts=packet["ts"], length=packet["length"],
            from_initiator=(packet["src"], packet["sport"]) == initiators[key],
            syn=("S" in flags and "." not in flags),
            fin=("F" in flags), rst=("R" in flags),
            is_udp=(packet["proto"] == "udp"),
        ))
        if record is not None:
            record["_key"] = key
            emitted.append(record)
    for record in table.sweep(packets[-1]["ts"] + 3600):
        record["_key"] = record["flow_instance_id"].rsplit("#", 1)[0]
        emitted.append(record)

    t0 = packets[0]["ts"]
    flows: list[Flow] = []
    for record in emitted:
        key = record.pop("_key")
        peer = peers.get(key, ("", 0))
        proto = key.rsplit("-", 1)[-1]
        route = classify_route({
            "proto": proto,
            "src_port": int(initiators.get(key, ("", 0))[1] or 0),
            "dst_port": int(peer[1] or 0),
        })
        decided = record.get("decision_ts")
        flows.append(Flow(
            flow_instance_id=record["flow_instance_id"],
            route=route, proto=proto,
            features={name: float(record["features"].get(name, 0.0)) for name in FEATURE_NAMES},
            scorable=bool(record["scorable"]),
            decision_reason=str(record["decision_reason"]),
            start_observed=bool(record["start_observed"]),
            packets=counts.get(key, 0),
            decision_offset_s=round(max(0.0, float(decided) - t0), 6) if decided is not None else 0.0,
        ))
    return flows


def load_route_models(directory: Path) -> dict[str, Any]:
    """Load every `<route>.json` present in a directory of route models.

    A partial set is allowed here and nowhere else: the release bundle must be
    complete, but a demo that only ever sees TCP and UDP should not have to ship
    a model it will not call. Scoring a flow whose route is absent raises.
    """
    directory = Path(directory)
    models: dict[str, Any] = {}
    for route in ROUTES:
        path = directory / f"{route}.json"
        if path.exists():
            models[route] = load_route_model(path, route)
    if not models:
        raise MissingRouteModel(f"no route models found in {directory}")
    return models


def score_flows(flows: list[Flow], models: dict[str, Any]) -> list[dict[str, Any]]:
    """Score each flow with the model of its own route, never another's."""
    out: list[dict[str, Any]] = []
    for flow in flows:
        model = models.get(flow.route)
        if model is None:
            raise MissingRouteModel(
                f"flow routes to {flow.route} but no model for that route was loaded")
        score = model.score(flow.features)
        out.append({
            "flow": flow,
            "route": flow.route,
            "score": score,
            "threshold": model.threshold,
            "tunnel_detected": bool(score >= model.threshold) and flow.scorable,
            "model_id": model.model_id,
        })
    return out


def score_pcap(pcap: Path, models: dict[str, Any]) -> list[dict[str, Any]]:
    return score_flows(observe_flows(Path(pcap)), models)


def _parse_args():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, nargs="+")
    parser.add_argument("--models-dir", required=True, type=Path)
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    loaded = load_route_models(args.models_dir)
    report = {}
    for capture in args.pcap:
        scored = score_pcap(capture, loaded)
        report[capture.name] = {
            "flows": len(scored),
            "flagged": sum(1 for s in scored if s["tunnel_detected"]),
            "max_score": max((s["score"] for s in scored), default=0.0),
            "routes": sorted({s["route"] for s in scored}),
        }
    print(json.dumps(report, indent=2, ensure_ascii=False))
