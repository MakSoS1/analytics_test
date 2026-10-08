from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .contracts import FrozenProfileManifest, RuntimeProfile


class ProfileRegistry:
    def __init__(self, profiles: Iterable[RuntimeProfile]):
        items = list(profiles)
        self._profiles = {p.profile_id: p for p in items}
        if len(self._profiles) != len(items):
            raise ValueError("duplicate profile_id")

    @classmethod
    def default(cls) -> "ProfileRegistry":
        all_web = ("https", "http1", "http2", "websocket", "wss")
        profiles = [
            RuntimeProfile(
                "linux-python-ssl",
                "linux",
                "python-stdlib-ssl",
                ("https", "http1"),
                "tcpdump",
                False,
            ),
            RuntimeProfile(
                "linux-curl",
                "linux",
                "curl",
                ("https", "http1", "http2"),
                "tcpdump",
                False,
            ),
            RuntimeProfile(
                "linux-chromium",
                "linux",
                "chromium",
                all_web + ("http3", "quic"),
                "tcpdump",
                True,
            ),
            RuntimeProfile(
                "linux-protocol-native",
                "linux",
                "coverlab-native",
                (
                    "https",
                    "http1",
                    "http2",
                    "http3",
                    "quic",
                    "grpc",
                    "websocket",
                    "wss",
                    "mqtt-wss",
                ),
                "tcpdump",
                True,
            ),
            RuntimeProfile(
                "windows-native-http",
                "windows",
                "windows-native-http",
                ("https", "http1", "http2"),
                "pktmon",
                True,
            ),
        ]
        return cls(profiles)

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._profiles))

    def resolve(self, profile_id: str) -> RuntimeProfile:
        try:
            return self._profiles[profile_id]
        except KeyError:
            raise KeyError(f"unknown runtime profile: {profile_id}") from None

    def manifest(
        self,
        profile_ids: Iterable[str],
        seed: int,
        *,
        reference_id: str = "",
    ) -> FrozenProfileManifest:
        unique = sorted(set(profile_ids))
        if not unique:
            raise ValueError("at least one profile required")
        for profile_id in unique:
            self.resolve(profile_id)
        weight = 1.0 / len(unique)
        return FrozenProfileManifest(
            seed=int(seed),
            profile_weights=tuple((p, weight) for p in unique),
            reference_id=reference_id,
        )
