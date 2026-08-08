from __future__ import annotations

import base64
import contextvars
import random
import re
import time
import uuid
import zlib

TRANSFORMS = ["raw_utf8", "base64", "base64url", "hex", "zlib_base64", "semantic_uuid"]
TIMINGS = ["fixed", "low_jitter", "medium_jitter", "burst"]
SIZES = ["tiny", "small", "medium", "large"]

_CTX: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "coverlab_nuisance", default={"transform_chain": ["base64url"], "timing_profile": "fixed", "payload_size_class": "small"}
)


def _core_len() -> int:
    from .scenarios import select
    return max(1, len(select("core")))


def infer(campaign_id: str) -> dict:
    """Reconstruct the exact nuisance assignment written by orchestrate.

    Campaign IDs are deterministic and part of the reproducibility contract.
    The returned values therefore match each stage's configured transform,
    timing and payload-size factors and are consumed before bytes hit the wire.
    """
    cid = str(campaign_id)
    transform_idx = 0
    timing_idx = 0
    size_idx = 1

    m = re.match(r"^a-\d+-\d+-(\d+)-[01]$", cid)
    if m:
        rep = int(m.group(1))
        transform_idx = rep % len(TRANSFORMS)
        timing_idx = rep % len(TIMINGS)
        size_idx = rep % len(SIZES)
    else:
        m = re.match(r"^b-(\d+)-\d+$", cid)
        if m:
            cfg = int(m.group(1))
            transform_idx = (cfg // _core_len()) % len(TRANSFORMS)
            timing_idx = (cfg // 7) % len(TIMINGS)
            size_idx = (cfg // 13) % len(SIZES)
        else:
            m = re.match(r"^c-(\d+)-(\d+)$", cid)
            if m:
                profile = int(m.group(1))
                transform_idx = profile % len(TRANSFORMS)
                timing_idx = profile % len(TIMINGS)
                size_idx = profile % len(SIZES)
            else:
                m = re.match(r"^[fgh]-(\d+)-(\d+)(?:-\d+)?$", cid)
                if m:
                    profile = int(m.group(1))
                    rep = int(m.group(2))
                    transform_idx = (profile + rep) % len(TRANSFORMS)
                    timing_idx = (profile + rep) % len(TIMINGS)
                    size_idx = (profile + rep) % len(SIZES)
                else:
                    m = re.match(r"^d-(\d+)-(\d+)$", cid)
                    if m:
                        capture_idx = int(m.group(1))
                        flow_idx = int(m.group(2))
                        transform_idx = (flow_idx + capture_idx) % len(TRANSFORMS)
                        timing_idx = (flow_idx + capture_idx) % len(TIMINGS)
                        size_idx = (flow_idx + capture_idx) % len(SIZES)
                    else:
                        m = re.match(r"^adv-(\d+)$", cid)
                        if m:
                            i = int(m.group(1))
                            transform_idx = (i * 3) % len(TRANSFORMS)
                            timing_idx = (i * 7) % len(TIMINGS)
                            size_idx = (i * 11) % len(SIZES)

    return {
        "transform_chain": [TRANSFORMS[transform_idx]],
        "timing_profile": TIMINGS[timing_idx],
        "payload_size_class": SIZES[size_idx],
        "wire_nuisance_applied": True,
    }


def push(campaign_id: str):
    return _CTX.set(infer(campaign_id))


def reset(token) -> None:
    _CTX.reset(token)


def current() -> dict:
    return dict(_CTX.get())


def _size_bytes(default: int) -> int:
    name = _CTX.get().get("payload_size_class", "small")
    floors = {"tiny": 16, "small": 32, "medium": 96, "large": 256}
    multipliers = {"tiny": 0.35, "small": 0.70, "medium": 1.25, "large": 2.25}
    return max(floors[name], min(16384, int(max(1, default) * multipliers[name])))


def _delay(r: random.Random) -> None:
    profile = _CTX.get().get("timing_profile", "fixed")
    # Delays are accelerated for CI but remain packet-timestamp-observable and
    # statistically distinct. Long 60/90/120-minute mixed captures add their own
    # real wall-clock scheduling on top of this per-event nuisance.
    if profile == "fixed":
        d = 0.012
    elif profile == "low_jitter":
        d = 0.010 + r.random() * 0.004
    elif profile == "medium_jitter":
        d = 0.004 + r.random() * 0.025
    else:  # burst
        d = 0.002 if r.random() < 0.80 else 0.045
    time.sleep(d)


def _raw_bytes(r: random.Random, n: int, suspicious: bool) -> bytes:
    data = bytearray(r.randrange(0, 256) for _ in range(max(1, n)))
    # Equal-length semantic markers alter meaning without introducing a trivial
    # length shortcut. Both sides pass through exactly the same transform family.
    marker = b"C2" if suspicious else b"LG"
    data[: min(2, len(data))] = marker[: min(2, len(data))]
    return bytes(data)


def _encode(raw: bytes, transform: str) -> str:
    if transform == "raw_utf8":
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        return "".join(alphabet[b % len(alphabet)] for b in raw)
    if transform == "base64":
        return base64.b64encode(raw).decode("ascii")
    if transform == "base64url":
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if transform == "hex":
        return raw.hex()
    if transform == "zlib_base64":
        return base64.urlsafe_b64encode(zlib.compress(raw, 6)).decode("ascii").rstrip("=")
    if transform == "semantic_uuid":
        chunks = []
        for offset in range(0, len(raw), 16):
            part = raw[offset : offset + 16].ljust(16, b"\x00")
            chunks.append(str(uuid.UUID(bytes=part)))
        return ".".join(chunks)
    raise ValueError(f"unknown transform: {transform}")


def encoded_value(r: random.Random, suspicious: bool, default_size: int = 48) -> str:
    _delay(r)
    raw = _raw_bytes(r, _size_bytes(default_size), suspicious)
    transform = _CTX.get().get("transform_chain", ["base64url"])[0]
    return _encode(raw, transform)


def entropy_blob(r: random.Random, default_size: int) -> bytes:
    # Payload-size nuisance affects multipart/octet-stream/browser upload bodies.
    return bytes(r.randrange(0, 256) for _ in range(_size_bytes(default_size)))


def synthetic_bytes(r: random.Random, suspicious: bool, default_size: int = 48) -> bytes:
    # Used by H3/gRPC/MQTT dispatchers: transform result changes actual
    # frame/message lengths and alphabets rather than only manifest metadata.
    return encoded_value(r, suspicious, default_size).encode("ascii")
