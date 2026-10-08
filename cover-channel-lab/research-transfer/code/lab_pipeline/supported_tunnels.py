#!/usr/bin/env python3
"""The release registry: which tunnel families this build actually stands behind.

"Detects all the tunnels" used to mean a folder with twelve labels in it. Three
of those labels did not describe what was captured, and two more families had no
captures at all. This file is the list that acceptance checks against, so a
family cannot be counted as covered by being mentioned somewhere.

A family missing from the registry is NOT supported. That is the whole point:
absence of a row is not evidence of coverage.
"""
from __future__ import annotations

import json
from pathlib import Path

REGISTRY_PATH = Path(__file__).resolve().parent.parent / "docs" / "supported_tunnels.json"

# Statuses that mean "there is measured evidence for this family". Anything
# below this is a plan, not a claim.
EVIDENCED = ("evaluated", "release_supported")


def load_registry(path: Path = REGISTRY_PATH) -> dict:
    return json.loads(path.read_text())


def declared_families(path: Path = REGISTRY_PATH) -> list[str]:
    """Families an evaluation must find data for, or block the release."""
    return sorted(f["family"] for f in load_registry(path)["families"]
                  if f["status"] in EVIDENCED)


def required_families() -> list[str]:
    """Canonical full68 acceptance scope, distinct from historic run2 evidence."""
    from .full_scope import required_families as full_scope_required_families

    return full_scope_required_families()


if __name__ == "__main__":
    print(",".join(declared_families()))
