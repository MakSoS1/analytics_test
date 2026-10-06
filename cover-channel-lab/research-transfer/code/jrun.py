#!/usr/bin/env python3
"""Run Python inside the remote Jupyter kernel without opening a browser.

Creates a kernel, executes the code it is given, prints stdout/stderr and
results, then shuts that kernel down. It never touches kernels it did not
create, and the token is read from the environment rather than any argument, so
it does not appear in a process list.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
import uuid

import websocket

BASE = os.environ["JUPYTER_BASE"].rstrip("/")
TOKEN = os.environ["JUPYTER_TOKEN"]
WS_BASE = BASE.replace("https://", "wss://").replace("http://", "ws://")
TIMEOUT = float(os.environ.get("JRUN_TIMEOUT", "600"))


def api(path: str, method: str = "GET", payload: dict | None = None):
    request = urllib.request.Request(
        f"{BASE}{path}", method=method,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Authorization": f"token {TOKEN}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        body = response.read()
        return json.loads(body) if body else None


class Channel:
    """The websocket of one kernel, with a deadline on every wait."""

    def __init__(self, kernel_id: str):
        self.ws = websocket.create_connection(
            f"{WS_BASE}/api/kernels/{kernel_id}/channels",
            header=[f"Authorization: token {TOKEN}"], timeout=10)
        self.session = uuid.uuid4().hex

    def send(self, msg_type, content):
        mid = uuid.uuid4().hex
        self.ws.send(json.dumps({
            "header": {"msg_id": mid, "username": "jrun", "session": self.session,
                       "msg_type": msg_type, "version": "5.3"},
            "parent_header": {}, "metadata": {}, "content": content, "channel": "shell"}))
        return mid

    def receive(self, deadline: float):
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError("kernel gave no answer in time")
            try:
                return json.loads(self.ws.recv())
            except websocket.WebSocketTimeoutException:
                continue


def start_kernel(attempts: int = 3, wait_s: float = 90.0):
    """A kernel that has answered. One can hang starting for good (seen on this
    server), and code sent to it is never run -- the caller would wait forever.
    The kernel_info round trip is also what guarantees the output channel is
    subscribed before any code runs, so no output and no "idle" is lost."""
    for _ in range(attempts):
        kernel_id = api("/api/kernels", "POST", {"name": "python3"})["id"]
        try:
            ch = Channel(kernel_id)
            info_id = ch.send("kernel_info_request", {})
            deadline = time.monotonic() + wait_s
            while (ch.receive(deadline).get("parent_header") or {}).get("msg_id") != info_id:
                pass
            return kernel_id, ch
        except Exception as exc:                      # noqa: BLE001
            print(f"warning: kernel {kernel_id} did not answer ({exc}); replacing it",
                  file=sys.stderr)
            try:
                api(f"/api/kernels/{kernel_id}", "DELETE")
            except Exception:                         # noqa: BLE001
                pass
    raise RuntimeError(f"no kernel answered in {attempts} attempts")


def run(code: str) -> int:
    kernel_id, ch = start_kernel()
    status = 0
    try:
        deadline = time.monotonic() + TIMEOUT
        msg_id = ch.send("execute_request", {
            "code": code, "silent": False, "store_history": False,
            "user_expressions": {}, "allow_stdin": False, "stop_on_error": True})
        while True:
            message = ch.receive(deadline)
            parent = (message.get("parent_header") or {}).get("msg_id")
            if parent != msg_id:
                continue
            kind = message["header"]["msg_type"]
            content = message.get("content") or {}
            if kind == "execute_reply" and content.get("status") == "error":
                status = 1
            if kind == "stream":
                sys.stdout.write(content.get("text", ""))
            elif kind in ("execute_result", "display_data"):
                text = (content.get("data") or {}).get("text/plain")
                if text:
                    print(text)
            elif kind == "error":
                status = 1
                print("\n".join(content.get("traceback") or []), file=sys.stderr)
            elif kind == "status" and content.get("execution_state") == "idle":
                break
        ch.ws.close()
    finally:
        # Only the kernel this call created is ever shut down.
        try:
            api(f"/api/kernels/{kernel_id}", "DELETE")
        except Exception as exc:                      # noqa: BLE001
            print(f"warning: could not shut down kernel {kernel_id}: {exc}", file=sys.stderr)
    return status


if __name__ == "__main__":
    raise SystemExit(run(sys.stdin.read()))
