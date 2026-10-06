from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

import pandas as pd

from .adapters import CoverChannelAdapter
from .calibration import calibrate_profiles
from .capture import probe_capability
from .composition import compose_feature_alternatives
from .contracts import FrozenProfileManifest
from .evaluation import ManifestIntegrityError, confirm_naturalness, evaluate_technique_signal
from .profiles import ProfileRegistry
from .reference import load_reference, model_feature_columns
from .reporting import package_release, write_report

HERE = Path(__file__).resolve()
RESEARCH_ROOT = HERE.parents[2]
CODE_ROOT = HERE.parents[1]
DEFAULT_REFERENCE = RESEARCH_ROOT / "datasets" / "office-cover-20261006"
DEFAULT_DICTIONARY = DEFAULT_REFERENCE / "pipeline_column_dictionary.json"
RUNTIME_ROOT = CODE_ROOT / "cover_runtime"

COMMANDS = (
    "validate-reference",
    "probe",
    "generate-benign",
    "calibrate",
    "confirm",
    "generate-scenarios",
    "evaluate-techniques",
    "compose",
    "package",
)

def _manifest_from_dict(body: dict) -> FrozenProfileManifest:
    weights = tuple(
        (str(row["profile_id"]), float(row["weight"]))
        for row in body.get("profile_weights", [])
    )
    if not weights:
        raise ValueError("frozen manifest has no profile_weights")
    return FrozenProfileManifest(
        seed=int(body["seed"]),
        profile_weights=weights,
        reference_id=str(body.get("reference_id", "")),
        version=str(body.get("version", "natural-profile-v2")),
    )

def load_frozen_manifest(path: Path, *, expected_sha: str) -> FrozenProfileManifest:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    manifest = _manifest_from_dict(json.loads(path.read_text()))
    if not expected_sha or manifest.sha256 != expected_sha:
        raise ManifestIntegrityError(
            f"frozen manifest hash mismatch: {manifest.sha256} != {expected_sha}"
        )
    return manifest

def _dictionary(path: Path) -> list[dict]:
    return list(json.loads(Path(path).read_text()))

def _feature_columns(frame: pd.DataFrame, dictionary: Path) -> list[str]:
    return model_feature_columns(frame, _dictionary(dictionary))

def _write_manifest(path: Path, manifest: FrozenProfileManifest) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(manifest.to_json() + "\n")
    target.with_suffix(target.suffix + ".sha256").write_text(manifest.sha256 + "\n")

def _run_cover_batch(args: argparse.Namespace, *, source_profile: str) -> dict:
    output = Path(args.out)
    command = [
        sys.executable,
        str(RUNTIME_ROOT / "run_batch.py"),
        "--out", str(output),
        "--image", str(args.image),
        "--entry", str(args.entry),
        "--profile", str(source_profile),
        "--seed", str(args.seed),
        "--timing", str(args.timing),
    ]
    proc = subprocess.run(command, cwd=RESEARCH_ROOT)
    if proc.returncode:
        raise RuntimeError(f"cover runtime failed with exit code {proc.returncode}")
    result = {
        "status": "generated",
        "entry": args.entry,
        "source_profile": source_profile,
        "seed": int(args.seed),
        "output": str(output),
        "production_ready": False,
    }
    print(json.dumps(result, sort_keys=True))
    return result

def _cmd_validate_reference(args: argparse.Namespace) -> int:
    ref = load_reference(args.root, verify_hashes=args.verify_hashes)
    body = {
        "status": "ok",
        "root": str(ref.root),
        "pipeline_office": list(ref.pipeline_office.shape),
        "pipeline_added": list(ref.pipeline_added.shape),
        "matched_mixed": list(ref.matched_mixed.shape),
        "feature_columns": len(ref.feature_columns),
        "dictionary_decryption_required": False,
    }
    if args.out:
        write_report(args.out, kind="reference", status="ok", payload=body)
    print(json.dumps(body, sort_keys=True))
    return 0

def _cmd_probe(args: argparse.Namespace) -> int:
    profile = ProfileRegistry.default().resolve(args.profile)
    report = probe_capability(profile)
    body = {
        "profile_id": report.profile_id,
        "supported": report.supported,
        "capture_type": report.capture_type,
        "reason": report.reason,
        "details": report.details,
    }
    if args.out:
        write_report(
            args.out,
            kind="capability",
            status="supported" if report.supported else "unsupported",
            payload=body,
        )
    print(json.dumps(body, sort_keys=True))
    return 0

def _cmd_generate_benign(args: argparse.Namespace) -> int:
    _run_cover_batch(args, source_profile=args.source_profile)
    return 0

def _cmd_calibrate(args: argparse.Namespace) -> int:
    office = pd.read_parquet(args.office)
    controls = pd.read_parquet(args.controls)
    if "profile_id" not in controls.columns:
        raise ValueError("controls parquet requires profile_id")
    groups = {
        "office": office[args.office_group].astype(str).tolist(),
        "controls": controls[args.control_group].astype(str).tolist(),
    }
    features = _feature_columns(office, args.dictionary)
    manifest = calibrate_profiles(
        office,
        controls,
        groups,
        ProfileRegistry.default(),
        args.seed,
        feature_columns=features,
    )
    _write_manifest(args.out, manifest)
    print(json.dumps({"status": "frozen", "sha256": manifest.sha256, "out": str(args.out)}, sort_keys=True))
    return 0

def _cmd_confirm(args: argparse.Namespace) -> int:
    manifest = load_frozen_manifest(args.manifest, expected_sha=args.manifest_sha)
    office = pd.read_parquet(args.office)
    controls = pd.read_parquet(args.controls)
    groups = {
        "office": office[args.office_group].astype(str).tolist(),
        "controls": controls[args.control_group].astype(str).tolist(),
    }
    features = _feature_columns(office, args.dictionary)
    report = confirm_naturalness(
        manifest,
        office,
        controls,
        groups,
        expected_manifest_sha=args.manifest_sha,
        feature_columns=features,
        bootstrap_reps=args.bootstrap_reps,
    )
    write_report(
        args.out,
        kind="naturalness",
        status=report.status,
        support=report.support,
        payload=report.as_dict(),
    )
    print(json.dumps(report.as_dict(), sort_keys=True))
    return 0

def _cmd_generate_scenarios(args: argparse.Namespace) -> int:
    manifest = load_frozen_manifest(args.manifest, expected_sha=args.manifest_sha)
    selected = {p for p, weight in manifest.profile_weights if weight > 0}
    if args.runtime_profile not in selected:
        raise ValueError(f"runtime profile {args.runtime_profile} is not in frozen manifest")
    natural = json.loads(Path(args.naturalness_report).read_text())
    status = natural.get("status")
    if status != "passed_candidate":
        raise ValueError(f"scenario generation blocked by naturalness status: {status}")
    adapter = CoverChannelAdapter(RUNTIME_ROOT, ProfileRegistry.default())
    mapping = adapter.resolve(args.entry, args.runtime_profile)
    if not mapping.supported:
        raise ValueError(mapping.reason)
    if args.source_profile not in mapping.source_profile_ids:
        raise ValueError("source profile is not declared by the Cover Channel entry")
    _run_cover_batch(args, source_profile=args.source_profile)
    return 0

def _cmd_evaluate_techniques(args: argparse.Namespace) -> int:
    manifest = load_frozen_manifest(args.manifest, expected_sha=args.manifest_sha)
    scenario = pd.read_parquet(args.scenario)
    control = pd.read_parquet(args.control)
    natural = json.loads(Path(args.naturalness_report).read_text())
    natural_status = str(natural.get("status"))
    features = _feature_columns(control, args.dictionary)
    pairs = control[args.pair_group].astype(str).tolist()
    report = evaluate_technique_signal(
        manifest,
        scenario,
        control,
        pairs,
        naturalness_status=natural_status,
        feature_columns=features,
        bootstrap_reps=args.bootstrap_reps,
    )
    write_report(
        args.out,
        kind="technique-signal",
        status=report.status,
        support={"pair_groups": report.pair_groups},
        payload=report.as_dict(),
    )
    print(json.dumps(report.as_dict(), sort_keys=True))
    return 0

def _cmd_compose(args: argparse.Namespace) -> int:
    report = compose_feature_alternatives(
        args.office, args.scenario, args.control, args.out, pair_id=args.pair_id
    )
    print(json.dumps(report, sort_keys=True))
    return 0

def _cmd_package(args: argparse.Namespace) -> int:
    report = package_release(args.input, args.out)
    print(json.dumps(report, sort_keys=True))
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="natural-traffic-v2")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate-reference")
    p.add_argument("--root", type=Path, default=DEFAULT_REFERENCE)
    p.add_argument("--verify-hashes", action="store_true")
    p.add_argument("--out", type=Path)
    p.set_defaults(func=_cmd_validate_reference)

    p = sub.add_parser("probe")
    p.add_argument("--profile", required=True, choices=ProfileRegistry.default().ids())
    p.add_argument("--out", type=Path)
    p.set_defaults(func=_cmd_probe)

    p = sub.add_parser("generate-benign")
    p.add_argument("--entry", required=True)
    p.add_argument("--source-profile", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--image", default="cover-complete:natural-v2")
    p.add_argument("--seed", type=int, default=20261006)
    p.add_argument("--timing", choices=("native", "accelerated_smoke"), default="accelerated_smoke")
    p.set_defaults(func=_cmd_generate_benign)

    p = sub.add_parser("calibrate")
    p.add_argument("--office", type=Path, required=True)
    p.add_argument("--controls", type=Path, required=True)
    p.add_argument("--office-group", required=True)
    p.add_argument("--control-group", required=True)
    p.add_argument("--dictionary", type=Path, default=DEFAULT_DICTIONARY)
    p.add_argument("--seed", type=int, default=20261006)
    p.add_argument("--out", type=Path, required=True)
    p.set_defaults(func=_cmd_calibrate)

    p = sub.add_parser("confirm")
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--manifest-sha", required=True)
    p.add_argument("--office", type=Path, required=True)
    p.add_argument("--controls", type=Path, required=True)
    p.add_argument("--office-group", required=True)
    p.add_argument("--control-group", required=True)
    p.add_argument("--dictionary", type=Path, default=DEFAULT_DICTIONARY)
    p.add_argument("--bootstrap-reps", type=int, default=200)
    p.add_argument("--out", type=Path, required=True)
    p.set_defaults(func=_cmd_confirm)

    p = sub.add_parser("generate-scenarios")
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--manifest-sha", required=True)
    p.add_argument("--naturalness-report", type=Path, required=True)
    p.add_argument("--runtime-profile", required=True, choices=ProfileRegistry.default().ids())
    p.add_argument("--entry", required=True)
    p.add_argument("--source-profile", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--image", default="cover-complete:natural-v2")
    p.add_argument("--seed", type=int, default=20261006)
    p.add_argument("--timing", choices=("native", "accelerated_smoke"), default="native")
    p.set_defaults(func=_cmd_generate_scenarios)

    p = sub.add_parser("evaluate-techniques")
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--manifest-sha", required=True)
    p.add_argument("--naturalness-report", type=Path, required=True)
    p.add_argument("--scenario", type=Path, required=True)
    p.add_argument("--control", type=Path, required=True)
    p.add_argument("--pair-group", required=True)
    p.add_argument("--dictionary", type=Path, default=DEFAULT_DICTIONARY)
    p.add_argument("--bootstrap-reps", type=int, default=200)
    p.add_argument("--out", type=Path, required=True)
    p.set_defaults(func=_cmd_evaluate_techniques)

    p = sub.add_parser("compose")
    p.add_argument("--office", type=Path, required=True)
    p.add_argument("--scenario", type=Path, required=True)
    p.add_argument("--control", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--pair-id", required=True)
    p.set_defaults(func=_cmd_compose)

    p = sub.add_parser("package")
    p.add_argument("--input", type=Path, nargs="+", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.set_defaults(func=_cmd_package)
    return parser

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))

if __name__ == "__main__":
    raise SystemExit(main())
