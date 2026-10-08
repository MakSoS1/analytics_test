#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import time
from collections import Counter

from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException


async def run_soak(args) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    started = time.monotonic()
    retries = 0
    retry_errors: Counter[str] = Counter()

    # Mirror the production WSS implementation: asyncio client, no helper
    # threads, one complete connect/send/recv/close lifecycle at a time. The old
    # sync client was itself the source of native SIGSEGV/SSLEOF flakiness on
    # GitHub-hosted Python 3.12 and therefore wasn't a valid production smoke.
    for i in range(args.connections):
        last_error: Exception | None = None
        for attempt in range(1, args.attempts + 1):
            try:
                async with connect(
                    args.url,
                    ssl=ctx,
                    proxy=None,
                    compression=None,
                    open_timeout=args.open_timeout,
                    close_timeout=2,
                    ping_interval=None,
                    max_queue=32,
                ) as ws:
                    await ws.send(json.dumps({
                        "action": "recv",
                        "container": f"STRESS-{i:05d}",
                        "target": "LAB",
                        "sender": "stress-smoke",
                        "message": "STATUS",
                    }, separators=(",", ":")))
                    reply = await asyncio.wait_for(ws.recv(), timeout=5)
                    if not reply:
                        raise RuntimeError(f"empty WSS reply at connection {i}")
                last_error = None
                break
            except (TimeoutError, asyncio.TimeoutError, OSError, RuntimeError, WebSocketException) as exc:
                last_error = exc
                retry_errors[type(exc).__name__] += 1
                if attempt >= args.attempts:
                    break
                retries += 1
                await asyncio.sleep(args.retry_delay * attempt)

        if last_error is not None:
            raise RuntimeError(
                f"WSS soak failed at connection {i} after "
                f"{args.attempts} attempts: {type(last_error).__name__}: {last_error}"
            ) from last_error

        if args.inter_delay:
            await asyncio.sleep(args.inter_delay)

    retry_fraction = retries / args.connections
    if retry_fraction > args.max_retry_fraction:
        raise RuntimeError(
            f"WSS service exceeded retry budget: retries={retries} "
            f"connections={args.connections} fraction={retry_fraction:.3f} "
            f"limit={args.max_retry_fraction:.3f} errors={dict(retry_errors)}"
        )

    elapsed = time.monotonic() - started
    return {
        "client_stack": "websockets.asyncio",
        "connections": args.connections,
        "retries": retries,
        "retry_fraction": round(retry_fraction, 4),
        "retry_errors": dict(sorted(retry_errors.items())),
        "max_retry_fraction": args.max_retry_fraction,
        "elapsed_seconds": round(elapsed, 3),
        "connections_per_second": round(args.connections / max(elapsed, 0.001), 3),
        "status": "pass",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="wss://cover-ws.test:8443/ws")
    ap.add_argument("--connections", type=int, default=120)
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--open-timeout", type=float, default=8.0)
    ap.add_argument("--retry-delay", type=float, default=0.10)
    ap.add_argument("--inter-delay", type=float, default=0.004)
    ap.add_argument("--max-retry-fraction", type=float, default=0.50)
    args = ap.parse_args()
    if args.connections < 1:
        raise SystemExit("--connections must be >= 1")
    if args.attempts < 1:
        raise SystemExit("--attempts must be >= 1")
    if not 0 <= args.max_retry_fraction <= 1:
        raise SystemExit("--max-retry-fraction must be in [0,1]")
    print(json.dumps(asyncio.run(run_soak(args)), sort_keys=True))


if __name__ == "__main__":
    main()
