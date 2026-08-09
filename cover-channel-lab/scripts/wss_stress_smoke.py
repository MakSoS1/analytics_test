#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import ssl
import time

from websockets.sync.client import connect


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="wss://cover-ws.test:8443/ws")
    ap.add_argument("--connections", type=int, default=400)
    args = ap.parse_args()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    started = time.monotonic()
    for i in range(args.connections):
        with connect(
            args.url,
            ssl=ctx,
            proxy=None,
            compression=None,
            open_timeout=6,
            close_timeout=2,
        ) as ws:
            ws.send(json.dumps({
                "action": "recv",
                "container": f"STRESS-{i:05d}",
                "target": "LAB",
                "sender": "stress-smoke",
                "message": "STATUS",
            }))
            if not ws.recv():
                raise RuntimeError(f"empty WSS reply at connection {i}")
    elapsed = time.monotonic() - started
    print(json.dumps({"connections": args.connections, "elapsed_seconds": round(elapsed, 3), "status": "pass"}))


if __name__ == "__main__":
    main()
