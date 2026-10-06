from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Literal


Role = Literal["scenario", "control"]


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class RuntimeProfile:
    profile_id: str
    os_family: str
    client_implementation: str
    protocols: tuple[str, ...]
    capture_type: str
    capability_required: bool
    resource_budget_gib: float = 2.0

    def supports(self, protocol: str) -> bool:
        return protocol.lower() in {p.lower() for p in self.protocols}

    def identity(self) -> tuple[object, ...]:
        return (
            self.profile_id,
            self.os_family,
            self.client_implementation,
            self.protocols,
            self.capture_type,
            self.capability_required,
            self.resource_budget_gib,
        )


@dataclass(frozen=True)
class ActivityDescriptor:
    technique_id: str
    protocol_families: tuple[str, ...]
    required_capabilities: tuple[str, ...] = ()
    roles: tuple[Role, ...] = ("scenario", "control")
    timing_owner: str = "adapter"
    fidelity: str = "wire-real"


@dataclass(frozen=True)
class GenerationContext:
    pair_id: str
    role: Role
    profile: RuntimeProfile
    seed: int
    output_dir: Path

    def __post_init__(self) -> None:
        if self.role not in ("scenario", "control"):
            raise ValueError(f"invalid role: {self.role}")

    def environment_identity(self) -> tuple[object, ...]:
        return (self.pair_id, self.profile.identity(), int(self.seed))


@dataclass(frozen=True)
class CaptureBundle:
    pair_id: str
    role: Role
    profile_id: str
    fidelity: str
    pcap_path: Path
    pcap_sha256: str
    evidence: tuple[tuple[str, str], ...]
    runtime_metadata_path: Path
    runtime_metadata_sha256: str


@dataclass(frozen=True)
class FrozenProfileManifest:
    seed: int
    profile_weights: tuple[tuple[str, float], ...]
    reference_id: str = ""
    version: str = "natural-profile-v2"

    def as_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "seed": int(self.seed),
            "reference_id": self.reference_id,
            "profile_weights": [
                {"profile_id": profile_id, "weight": float(weight)}
                for profile_id, weight in self.profile_weights
            ],
        }

    def to_json(self) -> str:
        return _canonical_json(self.as_dict())

    @property
    def sha256(self) -> str:
        return sha256(self.to_json().encode("utf-8")).hexdigest()
