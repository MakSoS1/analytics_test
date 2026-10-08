#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Reuse the proven checksum/decompression/tail implementation, but replace its
# dataset contract with revision 3 and rewrite provenance accordingly.
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import reuse_hf_shard as legacy  # noqa: E402
from coverlab.validate_dataset_contract_v3 import validate as validate_v3  # noqa: E402


def _validate_contract_v3(bronze: Path) -> dict:
    report = validate_v3(bronze)
    report["contract_revision"] = 3
    return report


def main() -> None:
    legacy._validate_contract = _validate_contract_v3
    # Parse only fields needed to update the provenance written by legacy.main;
    # legacy.main performs the authoritative argument validation itself.
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--dest-release", required=True)
    ap.add_argument("--shard", required=True)
    known, _ = ap.parse_known_args()
    legacy.main()
    p = Path(known.dest_release) / "quality" / known.shard / "reuse_provenance.json"
    if p.exists():
        data = json.loads(p.read_text())
        data["reuse_policy_revision"] = 5
        data["recovery_contract_revision"] = 3
        if isinstance(data.get("contract"), dict):
            data["contract"]["contract_revision"] = 3
        p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
