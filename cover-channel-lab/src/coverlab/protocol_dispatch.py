from __future__ import annotations

import asyncio
import base64
import fcntl
import hashlib
import json
import os
import random
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

import grpc
import httpx
import paho.mqtt.client as mqtt
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration

from .h3_fixture import LabH3Client
from .scenarios import Scenario

TARGET_FAMILIES = {"http3", "masque", "webtransport", "grpc", "mqtt_ws", "connect", "privacy"}
TRACE = Path("/tmp/coverlab_server_trace.jsonl")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def append_trace(record: dict) -> None:
    lock = TRACE.with_suffix(TRACE.suffix + ".lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    with lock.open("w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        with TRACE.open("a", encoding="utf-8") as out:
            out.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
        fcntl.flock(f, fcntl.LOCK_UN)


def append_json(path: str, record: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")


def synthetic_value(r: random.Random, suspicious: bool, n: int = 48) -> bytes:
    if suspicious:
        raw = bytes(r.randrange(256) for _ in range(n))
        return base64.urlsafe_b64encode(raw)
    return json.dumps(
        {"cpu": 20 + r.randrange(40), "mem": 35 + r.randrange(30), "status": "ok"},
        separators=(",", ":"),
    ).encode()


async def h3_batch(s: Scenario, suspicious: bool, r: random.Random, count: int) -> list[dict]:
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, max_datagram_frame_size=65536)
    cfg.verify_mode = ssl.CERT_NONE
    host = "cover-h3.test"
    out: list[dict] = []
    async with connect(host, 8444, configuration=cfg, create_protocol=LabH3Client, server_name=host) as proto:
        authority = f"{host}:8444"
        if s.family == "masque":
            for i in range(count):
                data = synthetic_value(r, suspicious, 64 + i * 8)
                result = await proto.connect_udp(authority, data)
                out.append(
                    {
                        "method": "CONNECT",
                        "path": "/.well-known/masque/udp/echo.test/7/",
                        "status": 200,
                        "encoded_length": len(data),
                        **result,
                    }
                )
            return out
        if s.family == "webtransport":
            for i in range(count):
                data = synthetic_value(r, suspicious, 32 + i * 8)
                result = await proto.webtransport(authority, data)
                out.append(
                    {
                        "method": "CONNECT",
                        "path": "/webtransport",
                        "status": 200,
                        "encoded_length": len(data),
                        **result,
                    }
                )
            return out

        async def one(i: int) -> dict:
            body = synthetic_value(r, suspicious, [0, 64, 256, 1024][i % 4]) if s.scenario_id in {"CC_H3_02", "CC_H3_05"} else b""
            token = hashlib.sha256(synthetic_value(r, suspicious, 16)).hexdigest()[:16]
            path = f"/h3/{s.carrier}/{i}?id={token}"
            result = await proto.request(authority, path, "POST" if body else "GET", body)
            return {
                "method": "POST" if body else "GET",
                "path": path,
                "status": result["status"],
                "encoded_length": len(body),
                **result,
            }

        if s.scenario_id == "CC_H3_02":
            out.extend(await asyncio.gather(*(one(i) for i in range(count))))
        else:
            for i in range(count):
                out.append(await one(i))
                if s.scenario_id == "CC_H3_06":
                    await asyncio.sleep(0.04 + r.random() * 0.04)
        return out


def grpc_exchange(s: Scenario, suspicious: bool, r: random.Random, count: int) -> list[dict]:
    channel = grpc.insecure_channel("cover-h2.test:50051")
    out: list[dict] = []
    payloads = [synthetic_value(r, suspicious, 64 + (i % 4) * 32) for i in range(count)]
    try:
        if s.scenario_id in {"CC_GRPC_01", "CC_GRPC_05", "CC_GRPC_06", "CC_GRPC_07"}:
            call = channel.unary_unary(
                "/coverlab.Control/Unary", request_serializer=lambda x: x, response_deserializer=lambda x: x
            )
            for data in payloads:
                metadata = (("x-lab", base64.b64encode(data[:24]).decode()),) if s.scenario_id == "CC_GRPC_05" else None
                response = call(
                    data,
                    metadata=metadata,
                    compression=grpc.Compression.Gzip if s.scenario_id == "CC_GRPC_07" else None,
                    timeout=8,
                )
                out.append(
                    {
                        "method": "POST",
                        "path": "/coverlab.Control/Unary",
                        "status": 200,
                        "encoded_length": len(data),
                        "reply_len": len(response),
                    }
                )
        elif s.scenario_id == "CC_GRPC_02":
            call = channel.unary_stream(
                "/coverlab.Control/ServerStream", request_serializer=lambda x: x, response_deserializer=lambda x: x
            )
            for data in payloads:
                replies = list(call(data, timeout=8))
                out.append(
                    {
                        "method": "POST",
                        "path": "/coverlab.Control/ServerStream",
                        "status": 200,
                        "encoded_length": len(data),
                        "reply_len": sum(map(len, replies)),
                    }
                )
        elif s.scenario_id == "CC_GRPC_03":
            call = channel.stream_unary(
                "/coverlab.Control/ClientStream", request_serializer=lambda x: x, response_deserializer=lambda x: x
            )
            response = call(iter(payloads), timeout=8)
            out.append(
                {
                    "method": "POST",
                    "path": "/coverlab.Control/ClientStream",
                    "status": 200,
                    "encoded_length": sum(map(len, payloads)),
                    "reply_len": len(response),
                }
            )
        else:
            call = channel.stream_stream(
                "/coverlab.Control/Bidi", request_serializer=lambda x: x, response_deserializer=lambda x: x
            )
            replies = list(call(iter(payloads), timeout=8))
            out.append(
                {
                    "method": "POST",
                    "path": "/coverlab.Control/Bidi",
                    "status": 200,
                    "encoded_length": sum(map(len, payloads)),
                    "reply_len": sum(map(len, replies)),
                }
            )
            if s.scenario_id == "CC_GRPC_08":
                unary = channel.unary_unary(
                    "/coverlab.Control/Unary", request_serializer=lambda x: x, response_deserializer=lambda x: x
                )
                for data in payloads[:2]:
                    unary(data, timeout=8)
    finally:
        channel.close()
    return out


def mqtt_exchange(s: Scenario, suspicious: bool, r: random.Random, count: int, campaign_id: str) -> list[dict]:
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=f"lab-{campaign_id[-16:]}",
        protocol=mqtt.MQTTv5,
        transport="websockets",
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    client.tls_set_context(ctx)
    client.ws_set_options(path="/mqtt")
    client.connect("mqtt-broker.test", 9443, keepalive=15)
    client.loop_start()
    out: list[dict] = []
    try:
        for i in range(count):
            topic = (
                f"control/lab/{campaign_id[-8:]}/{i % 3}"
                if suspicious
                else f"telemetry/lab/{campaign_id[-8:]}/{i % 3}"
            )
            payload = synthetic_value(r, suspicious, 48 + (i % 3) * 32)
            client.subscribe(topic, qos=1)
            info = client.publish(topic, payload=payload, qos=1, retain=False)
            info.wait_for_publish(timeout=5)
            out.append({"method": "MQTT_PUBLISH", "path": topic, "status": 200, "encoded_length": len(payload)})
            if s.scenario_id == "CC_MQTT_03":
                time.sleep(0.01 if i % 2 else 0.04)
    finally:
        client.disconnect()
        client.loop_stop()
    return out


def connect_exchange(s: Scenario, suspicious: bool, r: random.Random, count: int) -> tuple[list[dict], str]:
    out: list[dict] = []
    if s.scenario_id == "CC_CONNECT_01":
        for i in range(count):
            data = synthetic_value(r, suspicious, 32 + i * 8)
            with socket.create_connection(("cover-api.test", 8082), timeout=5) as sock:
                req = (
                    b"CONNECT synthetic-api.test:8081 HTTP/1.1\r\n"
                    b"Host: synthetic-api.test:8081\r\n"
                    b"User-Agent: coverlab-connect/1\r\n\r\n"
                )
                sock.sendall(req)
                head = sock.recv(4096)
                status = 200 if b" 200 " in head else 0
                sock.sendall(data)
                echo = sock.recv(len(data) + 64)
            out.append(
                {
                    "method": "CONNECT",
                    "path": "synthetic-api.test:8081",
                    "status": status,
                    "encoded_length": len(data),
                    "reply_len": len(echo),
                }
            )
        return out, "wire_real_http_connect_bounded_echo"

    # Hypercorn in this lab does not expose an RFC 8441 extended-CONNECT API.
    # Preserve the semantic experiment, but label fidelity explicitly instead of
    # pretending these are wire-real extended-CONNECT frames.
    with httpx.Client(verify=False, http2=True, timeout=8, trust_env=False) as client:
        for _ in range(count):
            data = synthetic_value(r, suspicious, 48)
            path = "/extended-connect/websocket" if s.scenario_id == "CC_CONNECT_03" else "/extended-connect/tcp"
            resp = client.post(
                f"https://cover-h2.test:8443{path}",
                headers={"X-Coverlab-Extended-Connect": s.carrier},
                content=data,
            )
            out.append({"method": "POST", "path": path, "status": resp.status_code, "encoded_length": len(data)})
    return out, "semantic_h2_extended_connect_fixture_not_rfc8441_wire_real"


def privacy_exchange(r: random.Random, count: int) -> list[dict]:
    out: list[dict] = []
    with httpx.Client(verify=False, http2=True, timeout=8, trust_env=False) as client:
        for i in range(count):
            body = bytes(r.randrange(256) for _ in range(256 + 64 * (i % 4)))
            resp = client.post(
                "https://cover-api.test:8443/ohttp",
                headers={"Content-Type": "message/ohttp-req", "Accept": "message/ohttp-res"},
                content=body,
            )
            out.append({"method": "POST", "path": "/ohttp", "status": resp.status_code, "encoded_length": len(body)})
    return out


def run_protocol(args, s: Scenario) -> dict | None:
    if s.family not in TARGET_FAMILIES:
        return None

    r = random.Random(args.seed)
    suspicious = False if s.family == "privacy" else args.variant == "suspicious"
    started = now_iso()
    host = "cover-api.test"

    if s.family in {"http3", "masque", "webtransport"}:
        host = "cover-h3.test"
        if s.scenario_id == "CC_H3_08":
            details = asyncio.run(h3_batch(s, suspicious, r, max(1, args.events // 3)))
            with httpx.Client(verify=False, http2=True, timeout=8, trust_env=False) as c:
                resp = c.get("https://cover-h2.test:8443/tls/fallback/h2")
                details.append({"method": "GET", "path": "/tls/fallback/h2", "status": resp.status_code, "encoded_length": 0})
            with httpx.Client(verify=False, http2=False, timeout=8, trust_env=False) as c:
                resp = c.get("https://cover-api.test:8443/tls/fallback/h1")
                details.append({"method": "GET", "path": "/tls/fallback/h1", "status": resp.status_code, "encoded_length": 0})
            fidelity = "wire_real_h3_h2_h1_fallback"
        else:
            details = asyncio.run(h3_batch(s, suspicious, r, args.events))
            if s.family == "masque":
                fidelity = "wire_real_h3_datagram_connect_udp_like_not_full_rfc9298_capsule_stack"
            elif s.family == "webtransport":
                fidelity = "wire_real_h3_webtransport_stream"
            else:
                fidelity = "wire_real_http3_quic"
    elif s.family == "grpc":
        host = "cover-h2.test"
        details = grpc_exchange(s, suspicious, r, args.events)
        fidelity = "wire_real_grpc_http2"
    elif s.family == "mqtt_ws":
        host = "mqtt-broker.test"
        details = mqtt_exchange(s, suspicious, r, args.events, args.campaign_id)
        fidelity = "wire_real_mqtt_over_wss"
    elif s.family == "connect":
        host = "cover-api.test" if s.scenario_id == "CC_CONNECT_01" else "cover-h2.test"
        details, fidelity = connect_exchange(s, suspicious, r, args.events)
    else:
        details = privacy_exchange(r, args.events)
        fidelity = "ohttp_media_type_binary_fixture_not_full_rfc9458_hpke"

    events: list[dict] = []
    for i, d in enumerate(details):
        event = {
            "event_id": f"{args.campaign_id}-e{i:03d}",
            "event_type": "synthetic_exchange",
            "sent_at": now_iso(),
            "completed_at": now_iso(),
            "http_method": d.get("method"),
            "http_path": d.get("path"),
            "response_status": d.get("status", 200),
            "encoded_length": int(d.get("encoded_length", 0)),
        }
        events.append(event)
        append_trace(
            {
                "ts": time.time(),
                "kind": s.family,
                "client_ip": args.source_ip,
                "scenario_id": s.scenario_id,
                "suspicious": suspicious,
                "method": d.get("method"),
                "path": d.get("path"),
                "query": "",
                "request_headers": {"x-coverlab-fidelity": fidelity},
                "request": {"body_b64": "", "body_length": int(d.get("encoded_length", 0)), "body_truncated": False},
                "response_status": d.get("status", 200),
                "response_headers": {},
                "response": {
                    "body_b64": "",
                    "body_length": int(d.get("reply_len", d.get("response_bytes", 0))),
                    "body_truncated": False,
                },
            }
        )

    ended = now_iso()
    encrypted = s.transport in {"https", "h3", "wss"}
    raw_semantic = (("SYNTHETIC_C2:" if suspicious else "BENIGN:") + s.scenario_id + ":" + str(args.seed)).encode()
    server_impl = {
        "http3": "aioquic_h3",
        "masque": "aioquic_h3",
        "webtransport": "aioquic_h3",
        "grpc": "grpcio_generic_h2",
        "mqtt_ws": "mosquitto_websockets",
        "connect": "asyncio_safe_connect",
        "privacy": "fastapi_hypercorn",
    }[s.family]
    client_impl = {
        "http3": "aioquic",
        "masque": "aioquic",
        "webtransport": "aioquic",
        "grpc": "grpcio",
        "mqtt_ws": "paho_mqtt_websockets",
        "connect": "python_socket" if s.scenario_id == "CC_CONNECT_01" else "python_httpx_h2",
        "privacy": "python_httpx_h2",
    }[s.family]

    record = {
        "campaign_id": args.campaign_id,
        "run_id": args.run_id,
        "scenario_id": s.scenario_id,
        "label_binary": 1 if suspicious else 0,
        "label_family": s.label_family if suspicious else "benign",
        "label_intent": s.label_intent if suspicious else "benign",
        "benign_semantic_type": None if suspicious else s.benign_semantic_type,
        "protocol": s.transport,
        "carrier": s.carrier,
        "attack_mapping": list(s.attack_mapping) if suspicious else [],
        "visibility_mode": "opaque_and_ground_truth" if encrypted else "content",
        "inspection_policy": "bypass" if encrypted else "not_applicable",
        "inspection_outcome": "encrypted" if encrypted else "plaintext",
        "sni_visibility": "clear",
        "feature_availability_bitmap": "runtime",
        "persona": args.persona,
        "source_ip": args.source_ip,
        "destination_ip": "10.20.0.20",
        "destination_host": host,
        "seed": args.seed,
        "started_at": started,
        "ended_at": ended,
        "expected_events": len(events),
        "capture_file": args.capture_file,
        "status": "success",
        "generator_name": "coverlab_protocol_dispatch",
        "generator_version": "1.1.0",
        "generator_commit": os.environ.get("GITHUB_SHA", "local"),
        "server_impl": server_impl,
        "client_impl": client_impl,
        "client_tls_impl": client_impl,
        "external_dependency": False,
        "policy_authorized": False if suspicious else True,
        "infra_category": "synthetic_local_fixture",
        "plaintext_sha256": hashlib.sha256(raw_semantic).hexdigest(),
        "implementation_fidelity": fidelity,
    }
    append_json(args.manifest, record)
    for e in events:
        e.update(
            {
                "campaign_id": args.campaign_id,
                "run_id": args.run_id,
                "scenario_id": s.scenario_id,
                "label_binary": record["label_binary"],
            }
        )
        append_json(args.events_out, e)
    return record
