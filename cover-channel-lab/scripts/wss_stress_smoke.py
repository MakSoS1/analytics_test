#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import ssl
import time

from websockets.sync.client import connect
from websockets.exceptions import InvalidMessage


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="wss://cover-ws.test:8443/ws")
    ap.add_argument("--connections", type=int, default=120)
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--open-timeout", type=float, default=8.0)
    ap.add_argument("--retry-delay", type=float, default=0.10)
    ap.add_argument("--inter-delay", type=float, default=0.004)
    args = ap.parse_args()

    if args.connections < 1:
        raise SystemExit("--connections must be >= 1")
    if args.attempts < 1:
        raise SystemExit("--attempts must be >= 1")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    started = time.monotonic()
    retries = 0

    # This is a bounded soak, not a synthetic denial-of-service burst. Four
    # namespaces run it concurrently, matching the actual corpus topology while
    # pacing connection churn so failures reflect fixture lifecycle bugs rather
    # than an unrealistic instantaneous TLS flood.
    for i in range(args.connections):
        last_error: Exception | None = None
        for attempt in range(1, args.attempts + 1):
            try:
                with connect(
                    args.url,
                    ssl=ctx,
                    proxy=None,
                    compression=None,
                    open_timeout=args.open_timeout,
                    close_timeout=2,
                ) as ws:
                    ws.send(json.dumps({
                        "action": "recv",
                        "container": f"STRESS-{i:05d}",
                        "target": "LAB",
                        "sender": "stress-smoke",
                        "message": "STATUS",
                    }))
                    if not ws.recv(timeout=5):
                        raise RuntimeError(f"empty WSS reply at connection {i}")
                last_error = None
                break
            except (TimeoutError, OSError, RuntimeError, InvalidMessage) as exc:
                last_error = exc
                if attempt >= args.attempts:
                    break
                retries += 1
                time.sleep(args.retry_delay * attempt)

        if last_error is not None:
            raise RuntimeError(
                f"WSS soak failed at connection {i} after "
                f"{args.attempts} attempts: {last_error}"
            ) from last_error

        if args.inter_delay:
            time.sleep(args.inter_delay)

    elapsed = time.monotonic() - started
    print(json.dumps({
        "connections": args.connections,
        "retries": retries,
        "elapsed_seconds": round(elapsed, 3),
        "connections_per_second": round(args.connections / max(elapsed, 0.001), 3),
        "status": "pass",
    }))


if __name__ == "__main__":
    main()
