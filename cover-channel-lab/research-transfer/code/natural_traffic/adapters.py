from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable

from office_injection.activity import prepare_activity
from office_injection.source import sha256 as file_sha256

from .contracts import ActivityDescriptor, CaptureBundle, GenerationContext
from .profiles import ProfileRegistry


_FORBIDDEN_EXECUTION_KEYS = {"command", "shell", "exec", "argv", "script"}


def _reject_execution_surface(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in _FORBIDDEN_EXECUTION_KEYS:
                raise ValueError(f"executable metadata key is forbidden at {path}.{key}")
            _reject_execution_surface(item, f"{path}.{key}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _reject_execution_surface(item, f"{path}[{i}]")


@dataclass(frozen=True)
class CoverChannelMapping:
    entry_id: str
    runtime_profile_id: str
    protocol: str
    fidelity: str
    supported: bool
    reason: str
    source_path: str
    source_sha256: str
    source_profile_ids: tuple[str, ...]


class ExternalActivityAdapter:
    adapter_id = "external"

    def import_pair(self, spec_path: Path, out: Path) -> tuple[CaptureBundle, CaptureBundle]:
        spec_path = Path(spec_path)
        spec = json.loads(spec_path.read_text())
        _reject_execution_surface(spec)
        prepared = prepare_activity(spec_path, out)
        bundles: list[CaptureBundle] = []
        root = Path(out)
        for campaign in prepared["campaigns"]:
            role = campaign["arm"]
            role_dir = root / role
            pcap = Path(campaign["path"])
            evidence: list[tuple[str, str]] = []
            for item in campaign.get("evidence", []):
                ep = root / item["path"]
                evidence.append((str(ep), item["sha256"]))
            runtime = role_dir / "natural_runtime.json"
            runtime_body = {
                "version": "natural-external-import-v2",
                "origin": "external",
                "source_fidelity": campaign["source_fidelity"],
                "pair_id": campaign["parent_campaign_id"],
                "campaign_id": campaign["campaign_id"],
                "activity_id": campaign["technique"],
                "role": role,
                "source_capture_sha256": campaign["source_capture_sha256"],
                "membership": campaign["membership"],
                "semantic_verification": campaign["semantic_verification"],
                "training_eligible": False,
            }
            runtime.write_text(json.dumps(runtime_body, sort_keys=True, indent=2) + "\n")
            bundles.append(
                CaptureBundle(
                    pair_id=campaign["parent_campaign_id"],
                    role=role,
                    profile_id="external-import",
                    fidelity="external-observed-capture",
                    pcap_path=pcap,
                    pcap_sha256=campaign["sha256"],
                    evidence=tuple(evidence),
                    runtime_metadata_path=runtime,
                    runtime_metadata_sha256=file_sha256(runtime),
                )
            )
        by_role = {b.role: b for b in bundles}
        if set(by_role) != {"scenario", "control"}:
            raise ValueError("external activity must produce exactly scenario and control bundles")
        return by_role["scenario"], by_role["control"]


class CoverChannelAdapter:
    adapter_id = "cover-channel"

    def __init__(self, runtime_root: Path, profiles: ProfileRegistry | None = None):
        self.runtime_root = Path(runtime_root)
        self.profiles = profiles or ProfileRegistry.default()
        registry_path = self.runtime_root / "registry.json"
        body = json.loads(registry_path.read_text())
        entries = list(body.get("entries", []))
        self.registry_sha256 = body.get("sha256", "")
        self._entries = {e["entry_id"]: e for e in entries}
        if len(self._entries) != len(entries):
            raise ValueError("duplicate Cover Channel entry_id")

    def entry_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._entries))

    def _entry(self, entry_id: str) -> dict[str, Any]:
        try:
            return self._entries[entry_id]
        except KeyError:
            raise KeyError(f"unknown Cover Channel entry: {entry_id}") from None

    @staticmethod
    def _protocol(entry: dict[str, Any]) -> str:
        entry_id = str(entry.get("entry_id", ""))
        explicit = str(entry.get("transport", "")).lower()
        if entry_id == "M-H3-QUIC" or explicit in {"h3", "quic", "http3"}:
            return "http3"
        if entry_id == "M-GRPC-BIDI" or explicit == "grpc":
            return "grpc"
        if entry_id == "M-WSS-LONG" or explicit in {"wss", "websocket", "ws"}:
            return "wss"
        if entry_id == "M-PUBSUB-MQTT" or explicit.startswith("mqtt"):
            return "mqtt-wss"
        return {
            "h2": "http2",
            "http2": "http2",
            "https": "https",
            "http": "http1",
        }.get(explicit, "https")

    @staticmethod
    def _fidelity(entry: dict[str, Any]) -> str:
        source = str(entry.get("source_fidelity", ""))
        if source == "semantic_fixture":
            return "semantic_fixture"
        if "visibility" in source or "raw" in source:
            return "visibility_only"
        return "wire-real"

    def describe(self, entry_id: str) -> ActivityDescriptor:
        entry = self._entry(entry_id)
        return ActivityDescriptor(
            technique_id=entry_id,
            protocol_families=(self._protocol(entry),),
            fidelity=self._fidelity(entry),
        )

    def resolve(self, entry_id: str, runtime_profile_id: str) -> CoverChannelMapping:
        entry = self._entry(entry_id)
        runtime = self.profiles.resolve(runtime_profile_id)
        protocol = self._protocol(entry)
        supported = runtime.supports(protocol)
        reason = (
            "supported"
            if supported
            else f"runtime profile {runtime_profile_id} does not support {protocol}"
        )
        return CoverChannelMapping(
            entry_id=entry_id,
            runtime_profile_id=runtime_profile_id,
            protocol=protocol,
            fidelity=self._fidelity(entry),
            supported=supported,
            reason=reason,
            source_path=str(entry.get("source_path", "")),
            source_sha256=str(entry.get("source_sha256", "")),
            source_profile_ids=tuple(
                p["profile_id"] for p in entry.get("profiles", []) if "profile_id" in p
            ),
        )

    def contexts(
        self,
        entry_id: str,
        runtime_profile_id: str,
        pair_id: str,
        seed: int,
        output_root: Path,
    ) -> tuple[GenerationContext, GenerationContext]:
        mapping = self.resolve(entry_id, runtime_profile_id)
        if not mapping.supported:
            raise ValueError(mapping.reason)
        profile = self.profiles.resolve(runtime_profile_id)
        root = Path(output_root)
        return (
            GenerationContext(pair_id, "scenario", profile, seed, root / "scenario"),
            GenerationContext(pair_id, "control", profile, seed, root / "control"),
        )


class AdapterRegistry:
    def __init__(self, adapters: Iterable[Any]):
        items = list(adapters)
        self._items = {item.adapter_id: item for item in items}
        if len(self._items) != len(items):
            raise ValueError("duplicate adapter_id")

    @classmethod
    def default(cls, *, runtime_root: Path) -> "AdapterRegistry":
        return cls(
            (
                CoverChannelAdapter(runtime_root, ProfileRegistry.default()),
                ExternalActivityAdapter(),
            )
        )

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._items))

    def get(self, name: str) -> Any:
        try:
            return self._items[name]
        except KeyError:
            raise KeyError(f"unknown adapter: {name}") from None
