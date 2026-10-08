from __future__ import annotations

import argparse
import base64
import fcntl
import json
import time
from concurrent import futures
from pathlib import Path

import grpc

TRACE = Path("/tmp/coverlab_server_trace.jsonl")


def trace(kind: str, method: str, body: bytes):
    lock = TRACE.with_suffix(".jsonl.lock"); lock.parent.mkdir(parents=True, exist_ok=True)
    with lock.open("w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        with TRACE.open("a") as out:
            out.write(json.dumps({"ts": time.time(), "kind": "grpc", "client_ip": None, "scenario_id": kind,
                                  "method": method, "path": f"/coverlab.Control/{method}",
                                  "request_headers": {"content-type": "application/grpc"},
                                  "request": {"body_b64": base64.b64encode(body[:16384]).decode(), "body_length": len(body), "body_truncated": len(body) > 16384},
                                  "response_status": 200, "response": {"body_b64": "", "body_length": 0, "body_truncated": False}}, separators=(",", ":")) + "\n")
        fcntl.flock(f, fcntl.LOCK_UN)


def unary(request: bytes, context):
    trace("CC_GRPC_01", "Unary", request); return b'{"ok":true,"mode":"unary"}'


def server_stream(request: bytes, context):
    trace("CC_GRPC_02", "ServerStream", request)
    for i in range(4): yield json.dumps({"seq": i, "command": "ECHO_ALPHA"}).encode()


def client_stream(iterator, context):
    parts = list(iterator); blob = b"".join(parts); trace("CC_GRPC_03", "ClientStream", blob)
    return json.dumps({"parts": len(parts), "bytes": len(blob)}).encode()


def bidi(iterator, context):
    for i, part in enumerate(iterator):
        trace("CC_GRPC_04", "Bidi", part); yield json.dumps({"seq": i, "ack": len(part)}).encode()


def handler():
    return grpc.method_handlers_generic_handler("coverlab.Control", {
        "Unary": grpc.unary_unary_rpc_method_handler(unary, request_deserializer=lambda x: x, response_serializer=lambda x: x),
        "ServerStream": grpc.unary_stream_rpc_method_handler(server_stream, request_deserializer=lambda x: x, response_serializer=lambda x: x),
        "ClientStream": grpc.stream_unary_rpc_method_handler(client_stream, request_deserializer=lambda x: x, response_serializer=lambda x: x),
        "Bidi": grpc.stream_stream_rpc_method_handler(bidi, request_deserializer=lambda x: x, response_serializer=lambda x: x),
    })


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--bind", default="10.20.0.20:50051"); args = ap.parse_args()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8)); server.add_generic_rpc_handlers((handler(),)); server.add_insecure_port(args.bind)
    server.start(); print(f"coverlab grpc ready on {args.bind}", flush=True); server.wait_for_termination()


if __name__ == "__main__": main()
