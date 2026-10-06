#!/usr/bin/env python3
"""SOC alert records, and the rules that keep them honest.

This stage raises alerts only — no blocking, no firewall changes, no inline
verdict. What an alert must therefore carry is enough context for a human to
judge it later: which model, which contract, which flow instance, when the
decision was taken, how complete the observation was, and why it fired.

Three rules that are easy to get wrong and are enforced here.

1. **Identity stays out of the model, not out of the alert.** The scored vector
   never contains an IP, a port or an SNI. The alert does carry a flow instance
   id and a host key, because a SOC analyst cannot act on an anonymous number —
   they live in the alert envelope, beside the score, never inside it.

2. **An authorized VPN is still a detection.** Policy decides what to do with
   it; the model's answer does not change. So `tunnel_detected` stays true and
   the policy verdict is a separate annotated field.

3. **Alert ids are deterministic.** The same decision re-delivered after a retry
   or a restart must collapse onto one incident, and a later host20 finding must
   update that incident rather than open a second one.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

SOURCE = Literal["fast", "host20"]
POLICY = Literal["unauthorized", "authorized", "unknown"]

ALERT_VERSION = "alert-v1"


class DurableWriteError(OSError):
    """Journal write failed. The alert is not durable and must not be checkpointed."""


@dataclass
class Alert:
    alert_id: str
    source: SOURCE
    model_id: str
    schema_version: str
    contract_hash: str
    sensor_id: str
    sensor_epoch: str
    flow_instance_id: str
    decision_time: float
    observation_start: float
    observation_end: float
    decision_reason: str
    score: float
    threshold: float
    tunnel_detected: bool
    start_observed: bool
    observed_packets: int
    policy_verdict: POLICY = "unknown"
    host_key: str | None = None
    family_hint: str | None = None
    detector_route: str | None = None
    route_contract_hash: str | None = None
    notes: list[str] = field(default_factory=list)
    alert_version: str = ALERT_VERSION

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    def decision_signature(self) -> str:
        """What the decision IS, without when it was emitted.

        A retried delivery must collapse onto one incident. Comparing whole
        records made that impossible: `decision_time` is the wall clock at
        emission, so two deliveries of the same decision never matched and every
        retry looked like an update.
        """
        d = asdict(self)
        d.pop("decision_time", None)
        return json.dumps(d, sort_keys=True, separators=(",", ":"))


def make_alert_id(sensor_id: str, sensor_epoch: str, flow_instance_id: str, source: SOURCE) -> str:
    """Deterministic id. Same decision, same id — retries must not duplicate.

    `source` is part of it so a host20 finding about the same flow is a distinct
    record that can be correlated, while a retried fast decision is not.
    """
    raw = f"{sensor_id}|{sensor_epoch}|{flow_instance_id}|{source}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def build_alert(
    observation: dict[str, Any],
    score: float,
    *,
    bundle_id: str,
    threshold: float,
    sensor_id: str,
    sensor_epoch: str,
    source: SOURCE = "fast",
    host_key: str | None = None,
    policy_verdict: POLICY = "unknown",
    family_hint: str | None = None,
    detector_route: str | None = None,
    route_contract_hash: str | None = None,
    now: float | None = None,
) -> Alert:
    fid = str(observation.get("flow_instance_id") or "")
    feats = observation.get("features") or {}
    start = float(observation.get("observation_start") or 0.0)
    end = float(observation.get("observation_end") or start + float(feats.get("observed_duration") or 0.0))
    notes: list[str] = []
    if not observation.get("start_observed", True):
        notes.append("flow joined mid-stream; first packets are not the connection's first packets")
    if observation.get("decision_reason") == "insufficient_data":
        notes.append("below the minimum packet count; this is not a benign verdict")
    if policy_verdict == "authorized":
        notes.append("authorized VPN: still a detection, policy decides the response")

    return Alert(
        alert_id=make_alert_id(sensor_id, sensor_epoch, fid, source),
        source=source,
        model_id=bundle_id,
        schema_version=str(observation.get("schema_version") or ""),
        contract_hash=str(observation.get("contract_hash") or ""),
        sensor_id=sensor_id,
        sensor_epoch=sensor_epoch,
        flow_instance_id=fid,
        decision_time=float(now if now is not None else time.time()),
        observation_start=start,
        observation_end=end,
        decision_reason=str(observation.get("decision_reason") or ""),
        score=float(score),
        threshold=float(threshold),
        tunnel_detected=bool(score >= threshold),
        start_observed=bool(observation.get("start_observed", True)),
        observed_packets=int(observation.get("observed_packets") or 0),
        policy_verdict=policy_verdict,
        host_key=host_key,
        family_hint=family_hint,
        detector_route=detector_route,
        route_contract_hash=route_contract_hash,
        notes=notes,
    )


class AlertSink:
    """Local sink with dedup and counters. Not a SOC transport.

    Routing to a real SOC is a separate decision; test alerts land here first.
    Raw decisions and deduplicated alerts are counted apart, because one number
    hides whether a spike is traffic or retries.
    """

    def __init__(self, max_seen: int = 100_000,
                 journal_path: str | Path | None = None) -> None:
        self._seen: dict[str, Alert] = {}
        self._order: list[str] = []
        self._max_seen = max_seen
        self.journal_path = Path(journal_path) if journal_path else None
        self.counters: dict[str, int] = {
            "decisions": 0, "alerts": 0, "duplicates": 0,
            "updates": 0, "suppressed_not_scorable": 0,
        }
        if self.journal_path and self.journal_path.exists():
            self._load_journal()

    def _load_journal(self) -> None:
        """Rebuild in-memory state from the durable JSONL. Last write wins."""
        assert self.journal_path is not None
        for line in self.journal_path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
                alert = Alert(**payload)
            except (ValueError, TypeError):
                continue
            if alert.alert_id not in self._seen:
                self._order.append(alert.alert_id)
            self._seen[alert.alert_id] = alert
        self._evict()

    def _append_journal(self, alert: Alert) -> None:
        if self.journal_path is None:
            return
        try:
            self.journal_path.parent.mkdir(parents=True, exist_ok=True)
            with self.journal_path.open("a", encoding="utf-8") as fh:
                fh.write(alert.to_json() + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise DurableWriteError(exc.errno, os.strerror(exc.errno)
                                    if exc.errno is not None else str(exc),
                                    str(self.journal_path)) from exc

    def submit(self, alert: Alert, *, scorable: bool = True) -> str:
        self.counters["decisions"] += 1
        if not scorable:
            self.counters["suppressed_not_scorable"] += 1
            return "suppressed"
        prev = self._seen.get(alert.alert_id)
        if prev is None:
            self._append_journal(alert)
            self._seen[alert.alert_id] = alert
            self._order.append(alert.alert_id)
            self.counters["alerts"] += 1
            self._evict()
            return "new"
        if prev.decision_signature() == alert.decision_signature():
            self.counters["duplicates"] += 1
            return "duplicate"
        self._append_journal(alert)
        self._seen[alert.alert_id] = alert
        self.counters["updates"] += 1
        return "updated"

    def _evict(self) -> None:
        while len(self._order) > self._max_seen:
            self._seen.pop(self._order.pop(0), None)

    def get(self, alert_id: str) -> Alert | None:
        return self._seen.get(alert_id)

    def __len__(self) -> int:
        return len(self._seen)
