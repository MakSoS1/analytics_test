#!/usr/bin/env python3
"""Alerts that survive a restart and a sink that is not there.

`AlertSink` keeps alerts in a dict. A restart loses them, and so does a sink
outage: the call simply fails. For a detector whose whole job is to say
something happened, an alert that evaporates is the worst failure mode there is,
because nothing distinguishes it from "nothing happened".

So an alert is written to an append-only spool BEFORE anyone tries to deliver
it, and marked delivered only after the sink accepted it. A crash between those
two points leaves a record that the next start retries. Retries are bounded: a
sink that stays down produces a counter, not a loop.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable


class SinkUnavailable(Exception):
    """The sink could not take this alert now. Retryable."""


class AlertSpool:
    """Append-only spool with bounded retry.

    Two lines per alert at most: the alert itself, then an ack. Replaying the
    file gives the set of alerts with no ack, which is exactly what still needs
    delivering.
    """

    def __init__(self, path: str | Path, sink: Callable[[dict[str, Any]], None],
                 max_attempts: int = 5, backoff_base: float = 0.2) -> None:
        self.path = Path(path)
        self.sink = sink
        self.max_attempts = max(1, int(max_attempts))
        self.backoff_base = backoff_base
        self.counters: dict[str, int] = {"spooled": 0, "delivered": 0,
                                         "undelivered": 0, "retries": 0}

    # ---- spool file ------------------------------------------------------
    def _append(self, kind: str, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as fh:
            fh.write(json.dumps({"t": kind, "a": payload}) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def _undelivered(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        pending: dict[str, dict[str, Any]] = {}
        for line in self.path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            key = _key(d.get("a") or {})
            if d.get("t") == "alert":
                pending[key] = d["a"]
            elif d.get("t") == "ack":
                pending.pop(key, None)
        return list(pending.values())

    # ---- delivery --------------------------------------------------------
    def _deliver(self, alert: dict[str, Any]) -> bool:
        for attempt in range(1, self.max_attempts + 1):
            try:
                self.sink(alert)
            except SinkUnavailable:
                self.counters["retries"] += 1
                if attempt < self.max_attempts and self.backoff_base:
                    time.sleep(self.backoff_base * (2 ** (attempt - 1)))
                continue
            self._append("ack", alert)
            self.counters["delivered"] += 1
            return True
        # Out of attempts. The alert stays in the spool without an ack, so the
        # next start will try again; the counter is what makes the operator see
        # it now rather than after the next restart.
        self.counters["undelivered"] += 1
        return False

    def submit(self, alert: dict[str, Any]) -> bool:
        self._append("alert", alert)
        self.counters["spooled"] += 1
        return self._deliver(alert)

    def recover(self) -> int:
        """Retry everything the spool still has no ack for."""
        n = 0
        for alert in self._undelivered():
            if self._deliver(alert):
                n += 1
        return n

    def compact(self) -> None:
        """Drop acked alerts. The spool is a queue, not a history."""
        pending = self._undelivered()
        tmp = self.path.with_suffix(self.path.suffix + ".part")
        with tmp.open("w") as fh:
            for a in pending:
                fh.write(json.dumps({"t": "alert", "a": a}) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)


def _key(alert: dict[str, Any]) -> str:
    for field in ("id", "alert_id", "flow_instance_id"):
        if field in alert:
            return str(alert[field])
    return json.dumps(alert, sort_keys=True)
