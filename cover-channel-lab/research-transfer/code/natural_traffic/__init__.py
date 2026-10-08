"""Natural office traffic generator v2 public API."""

from .contracts import (
    ActivityDescriptor,
    CaptureBundle,
    FrozenProfileManifest,
    GenerationContext,
    RuntimeProfile,
)
from .profiles import ProfileRegistry
from .reference import ReferenceDataset, load_reference, model_feature_columns

__all__ = [
    "ActivityDescriptor",
    "CaptureBundle",
    "FrozenProfileManifest",
    "GenerationContext",
    "RuntimeProfile",
    "ProfileRegistry",
    "ReferenceDataset",
    "load_reference",
    "model_feature_columns",
]
