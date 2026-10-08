#!/usr/bin/env python3
"""The release decision, assembled from evidence rather than asserted.

`model_card.py` describes one model. A release is a wider question: the sensor
computes the vector the model was fitted on, the corpus rows are independent
decisions, every declared family has data, the false-positive bound is proven on
the population the detector will actually see, and the runtime fits the link.

The rule that makes this document worth reading: **a missing input is a blocker,
not an omission**. Every earlier version of this claim — "twelve families,
recall 1.000" — was true of a file that existed and silent about the files that
did not. So each gate here is either backed by a named artifact or listed under
what is not proven, and `RELEASE: NOT READY` is printed whenever anything is.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from lab_pipeline.online_schema import SCHEMA_VERSION, contract_hash  # noqa: E402
from lab_pipeline.extract_fastv1_features import EXCLUDED_SESSIONS  # noqa: E402
from lab_pipeline.full_scope import load_full_scope, required_families  # noqa: E402
from lab_pipeline.supported_tunnels import REGISTRY_PATH, load_registry  # noqa: E402


def _load(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _throughput(bench: dict[str, Any]) -> float | None:
    for key in ("packets_per_second", "pps", "with_exporter_pps", "flows_per_second"):
        val = bench.get(key)
        if isinstance(val, (int, float)) and val > 0:
            return float(val)
    for stage in ("reducer", "inference", "exporter", "chain"):
        nested = bench.get(stage)
        if not isinstance(nested, dict):
            continue
        for key in ("packets_per_second", "pps", "flows_per_second"):
            val = nested.get(key)
            if isinstance(val, (int, float)) and val > 0:
                return float(val)
    return None


def _benchmark_gate(bench: dict[str, Any] | None) -> tuple[bool | None, str]:
    """Existence of a JSON file is not a measurement. `{}` used to pass.

    A named load with any positive pps also used to pass, including 1 pps and
    an exporter-only replay. The gate now requires a full-chain rate compared
    with an explicit budget.
    """
    if bench is None:
        return None, "no benchmark report; the exporter's cost is unknown"
    if not bench:
        return None, "benchmark file is empty {}; that is not a measurement"
    budgets = bench.get("budgets") if isinstance(bench.get("budgets"), dict) else {}
    min_pps = budgets.get("min_chain_pps")
    stages = bench.get("stages")
    if isinstance(stages, dict):
        stage_names = set(stages)
    elif isinstance(stages, list):
        stage_names = {str(s) for s in stages}
    else:
        stage_names = set()
    chain = bench.get("chain") if isinstance(bench.get("chain"), dict) else {}
    chain_pps = bench.get("chain_pps")
    if chain_pps is None:
        for key in ("pps", "packets_per_second"):
            if isinstance(chain.get(key), (int, float)) and chain.get(key) > 0:
                chain_pps = float(chain[key])
                break
    needed = {"exporter", "inference", "sink"}
    load = (bench.get("load_profile") or bench.get("load") or bench.get("measured"))
    if min_pps is None:
        return False, ("no min_chain_pps budget; a positive throughput "
                       f"({_throughput(bench)}) is not an NGFW passport")
    if chain_pps is None:
        return False, ("no full-chain pps (exporter+inference+sink); "
                       "exporter replay alone is not the chain")
    missing_stages = sorted(needed - stage_names)
    if missing_stages:
        return False, f"full chain stages missing: {missing_stages}"
    if float(chain_pps) < float(min_pps):
        return False, f"chain {float(chain_pps):g} pps below budget {float(min_pps):g}"
    max_lat = budgets.get("max_decision_latency_s")
    latency = bench.get("decision_latency_p50_s")
    if latency is None:
        latency = chain.get("decision_latency_p50_s")
    if max_lat is not None and latency is not None and float(latency) > float(max_lat):
        return False, f"decision latency {latency} s above budget {max_lat} s"
    if not load:
        load = "full_chain"
    return True, f"{load} chain {float(chain_pps):g} pps vs budget {float(min_pps):g}"


def collect(acceptance: Path | None, benchmark: Path | None,
            protocol_qc: Path | None, model_path: Path | None = None,
            registry_path: Path | None = None, scope_path: Path | None = None,
            phase: str = "office") -> dict[str, Any]:
    """Gather the evidence. Absent evidence is recorded as absent."""
    if phase not in {"lab", "office"}:
        raise ValueError("phase must be 'lab' or 'office'")
    rep = _load(acceptance)
    bench = _load(benchmark)
    qc = _load(protocol_qc)
    registry = load_registry(registry_path) if registry_path else load_registry()
    full_scope = load_full_scope(scope_path) if scope_path else (load_full_scope() if phase == "lab" else None)
    full68 = required_families(full_scope) if full_scope else []

    gates: list[dict[str, Any]] = []

    def gate(name: str, ok: bool | None, detail: str, source: str) -> None:
        gates.append({"name": name, "ok": ok, "detail": detail, "source": source})

    if rep is None:
        gate("acceptance report present", False,
             "no acceptance report: nothing here is measured", str(acceptance))
    else:
        src = str(acceptance)
        acceptance_gates = (
            ("positive_evidence_present", "positive evidence present"),
            ("all_declared_families_present", "every declared family has data"),
            ("all_families_meet_session_floor", "every family meets the session floor"),
            ("all_families_have_enough_sessions", "every family has enough test sessions"),
            ("rows_are_independent_decisions", "rows are independent decisions"),
            ("model_matches_current_contract", "model matches the current contract"),
        )
        if phase == "office":
            acceptance_gates += (
                ("office_evidence_present", "office evidence present"),
                ("office_fpr_upper95_within_budget", "office FPR upper bound within budget"),
            )
        for key, label in acceptance_gates:
            gates.append({"name": label, "ok": bool(rep.get("gates", {}).get(key)),
                          "detail": _detail(key, rep), "source": src})

    if qc is None:
        gate("protocol QC run", False, "no protocol QC report", str(protocol_qc))
    else:
        t = qc.get("totals", {})
        # Four named verdicts. Folding "nothing in rejected" into "confirmed"
        # invents evidence: encrypted families are honestly indeterminate.
        missing = [k for k in ("confirmed", "contradicted", "no_server_traffic",
                               "indeterminate") if k not in t]
        gate("QC reports confirmed, contradicted, no_server_traffic, indeterminate",
             not missing,
             f"missing verdicts: {missing}" if missing else
             f"confirmed {t.get('confirmed')}, contradicted {t.get('contradicted')}, "
             f"no_server_traffic {t.get('no_server_traffic')}, "
             f"indeterminate {t.get('indeterminate')}",
             str(protocol_qc))
        rejected = qc.get("rejected") or []
        unmanaged = [r["session"] for r in rejected
                     if r.get("session") not in EXCLUDED_SESSIONS]
        unmanaged_contra = [r["session"] for r in rejected
                            if r.get("session") not in EXCLUDED_SESSIONS
                            and r.get("verdict", "contradicted") == "contradicted"]
        unmanaged_empty = [r["session"] for r in rejected
                           if r.get("session") not in EXCLUDED_SESSIONS
                           and r.get("verdict") == "no_server_traffic"]
        named_verdicts = any(r.get("verdict") for r in rejected)
        gate("every contradicted capture is excluded from the corpus",
             not unmanaged_contra if named_verdicts else not unmanaged,
             f"confirmed {t.get('confirmed')}, contradicted {t.get('contradicted')}, "
             f"no server traffic {t.get('no_server_traffic')}; "
             + (f"NOT excluded: {(unmanaged_contra or unmanaged)[:5]}"
                if (unmanaged_contra or unmanaged)
                else f"all {len(rejected)} are in the exclusion manifest"),
             str(protocol_qc))
        gate("no_server_traffic captures are excluded from the corpus",
             not unmanaged_empty,
             f"unmanaged no_server_traffic: {unmanaged_empty[:5]}" if unmanaged_empty
             else f"no_server_traffic {t.get('no_server_traffic') or 0}",
             str(protocol_qc))
        gate("QC indeterminate count is reported, not treated as confirmed",
             t.get("indeterminate") is not None,
             f"indeterminate {t.get('indeterminate')}",
             str(protocol_qc))
        # Empty rejected is not endpoint confirmation. A corpus with zero
        # confirmed openings has not shown that the labelled protocol ran.
        confirmed = int(t.get("confirmed") or 0)
        gate("endpoint-confirmed openings exist in the QC'd corpus",
             confirmed > 0,
             f"confirmed {confirmed}; absence from rejected is not a confirmation",
             str(protocol_qc))

    ok_runtime, runtime_detail = _benchmark_gate(bench)
    gate("runtime measured on the target rate", ok_runtime, runtime_detail,
         str(benchmark))

    mix = (rep or {}).get("mix") if rep else None
    if not mix:
        gate("mix precision measured on a labelled mix", None,
             "no labelled mix; Precision≥0.95 is unmeasured",
             str(acceptance))
    else:
        prec = mix.get("precision")
        rec = mix.get("recall")
        ok_mix = (isinstance(prec, (int, float)) and prec >= 0.95
                  and isinstance(rec, (int, float)) and rec >= 0.95)
        gate("mix precision measured on a labelled mix",
             ok_mix if prec is not None else None,
             f"precision {prec}, recall {rec}, rows {mix.get('rows')}",
             str(acceptance))

    cov = (rep or {}).get("coverage") if rep else None
    if not cov or cov.get("test_sessions_declared") is None:
        if not cov or cov.get("sessions_in_metadata") is None:
            gate("coverage denominator present", None,
                 "no metadata session count; dropped sessions would vanish from recall",
                 str(acceptance))
        else:
            gate("coverage denominator is the frozen test session set", False,
                 "sessions_in_metadata without test_sessions_declared mixes train/val/test roles",
                 str(acceptance))
    else:
        gate("coverage denominator is the frozen test session set", True,
             f"{cov.get('sessions_reaching_a_decision')} of "
             f"{cov.get('test_sessions_declared')} frozen test sessions reached a decision "
             f"(coverage {cov.get('coverage')}; qc_excluded {cov.get('qc_excluded')}, "
             f"unscorable {cov.get('unscorable')}, missing {cov.get('missing')})",
             str(acceptance))

    arts = (rep or {}).get("artifacts") if rep else None
    needed = ["model_sha256", "lab_csv_sha256", "exclusions_sha256"]
    if phase == "office":
        needed.append("office_csv_sha256")
    if not arts or any(not arts.get(k) for k in needed):
        gate("acceptance report binds artifact hashes", None,
             "report is missing model/csv/exclusions SHA256; it cannot name this build",
             str(acceptance))
    else:
        gate("acceptance report binds artifact hashes", True,
             f"model {arts['model_sha256'][:16]}…", str(acceptance))
        if model_path is None:
            gate("model file matches bound hash", None,
                 "no --model given; the file on disk is not checked against the report",
                 str(acceptance))
        else:
            try:
                actual = _sha256(Path(model_path))
            except OSError:
                actual = ""
            gate("model file matches bound hash",
                 bool(actual) and actual == arts["model_sha256"],
                 f"file {actual[:16] or 'unreadable'}… report {arts['model_sha256'][:16]}…",
                 str(model_path))

    # What a gate is for: blocking a CLAIM that outruns its evidence.
    #
    # "No family is still `planned`" was the wrong test. A `planned` family makes
    # no claim — `sstp` and `tor_obfs4` are listed precisely so that their
    # absence is visible, and blocking the release because they are honestly
    # marked would punish the registry for being accurate. What must hold is the
    # other direction: nothing is marked supported without evidence behind it.
    #
    # The supported set is COMPUTED from this acceptance, not read as a claim:
    # a family is in scope when this report shows data for it that meets the
    # floors. The registry is then a projection of the evidence, not a licence
    # that had to be stamped by hand before the card would pass.
    planned = [f["family"] for f in registry["families"] if f["status"] == "planned"]
    supported = [f["family"] for f in registry["families"]
                 if f["status"] == "release_supported"]
    unevidenced = [f["family"] for f in registry["families"]
                   if f["status"] == "release_supported"
                   and (not f.get("test_sessions") or f.get("session_recall") is None)]
    per_family = (rep or {}).get("per_family") or []
    evidenced_scope = sorted(
        d["family"] for d in per_family
        if d.get("passes_session_floor") and d.get("enough_sessions"))
    # A registry row claiming support that THIS acceptance cannot prove is an
    # overclaim: the build being judged covers less than the registry says.
    overclaimed = [f for f in supported if f not in evidenced_scope] if rep else []
    gate("nothing is marked release_supported without evidence",
         not unevidenced and not overclaimed,
         ("claimed without evidence: " + str(unevidenced)) if unevidenced
         else ("not proven by this build: " + str(overclaimed)) if overclaimed
         else f"{len(evidenced_scope)} evidenced, {len(supported)} stamped, "
              f"{len(planned)} planned and claiming nothing",
         "docs/supported_tunnels.json")
    gate("release scope non-empty and evidenced by this build",
         bool(evidenced_scope) if rep is not None else None,
         f"{len(evidenced_scope)} families meet the floors in this acceptance: "
         f"{evidenced_scope or 'none'}",
         str(acceptance))
    report_scope = {"release_supported": evidenced_scope,
                    "registry_release_supported": supported,
                    "planned_not_claimed": planned}

    if full68:
        per_family_by_name = {
            str(row.get("family") or ""): row for row in per_family if isinstance(row, dict)
        }
        missing_full68 = []
        incomplete_metrics = []
        for family in full68:
            row = per_family_by_name.get(family)
            if not row or not row.get("passes_session_floor") or not row.get("enough_sessions"):
                missing_full68.append(family)
                continue
            metrics = (row.get("precision"), row.get("recall"), row.get("f1"))
            if not all(isinstance(value, (int, float)) and 0.0 <= value <= 1.0 for value in metrics):
                incomplete_metrics.append(family)
        gate("every full68 family has frozen evidence",
             not missing_full68 and not incomplete_metrics,
             (f"missing or below floor: {missing_full68}; missing P/R/F1: {incomplete_metrics}")
             if (missing_full68 or incomplete_metrics)
             else "68 canonical families have frozen test evidence with P/R/F1",
             str(acceptance))
        frozen = bool((rep or {}).get("gates", {}).get("frozen_split_manifest"))
        gate("full68 evaluation uses a frozen split manifest", frozen,
             "frozen split manifest required for full68 release evidence",
             str(acceptance))

        qc_rows = (qc or {}).get("session_verdicts") or []
        endpoint_families = {
            str(row.get("family") or "") for row in qc_rows if isinstance(row, dict)
            and row.get("verdict") in ("confirmed", "indeterminate")
            and row.get("endpoint_evidence") == "confirmed"
        }
        missing_endpoint = [family for family in full68 if family not in endpoint_families]
        gate("every full68 family has explicit endpoint evidence", not missing_endpoint,
             f"missing endpoint-confirmed family evidence: {missing_endpoint}"
             if missing_endpoint else "all 68 families have explicit endpoint evidence",
             str(protocol_qc))
        report_scope["full68_required"] = full68
        report_scope["full68_missing"] = missing_full68

    blockers = [g for g in gates if g["ok"] is not True]
    ready = not blockers
    release_supported = ready and phase == "office"
    status = ("LAB READY / OFFICE ACCEPTANCE PENDING" if ready and phase == "lab"
              else "LAB NOT READY" if phase == "lab"
              else "READY" if ready else "NOT READY")
    return {"schema_version": SCHEMA_VERSION, "contract_hash": contract_hash(),
            "scope": report_scope,
            "phase": phase, "status": status, "release_supported": release_supported,
            "gates": gates, "blockers": blockers, "ready": ready}


def stamp_registry(card: dict[str, Any], registry_path: Path,
                   acceptance_source: str | None,
                   model_sha256: str | None) -> dict[str, Any]:
    """Write the computed scope into the registry as `release_supported`.

    Stamping is only reachable from a READY card: the status means "evaluated
    AND the release gates pass for this build", so the gates passing is the
    precondition, not a formality. Planned rows are never touched — a family
    with no captures cannot be promoted by a passing build — and demotion is
    not a card decision; a stale stamp is corrected by the overclaim gate when
    a later acceptance cannot prove the family any more.
    """
    if not card.get("release_supported", False):
        return {"stamped": False, "reason": "card is not office release-supported; nothing is stamped"}
    scope = set(card.get("scope", {}).get("release_supported") or [])
    if not scope:
        return {"stamped": False, "reason": "computed scope is empty"}
    registry = json.loads(registry_path.read_text())
    today = datetime.date.today().isoformat()
    changed: list[str] = []
    for fam in registry["families"]:
        if fam.get("family") in scope and fam.get("status") in ("evaluated", "release_supported"):
            if fam.get("status") != "release_supported":
                fam["status"] = "release_supported"
            fam["release_evidence"] = {
                "acceptance": acceptance_source or "",
                "model_sha256": model_sha256 or "",
                "stamped": today,
            }
            changed.append(fam["family"])
    registry["generated"] = today
    registry_path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
    return {"stamped": True, "families": changed}


def _detail(key: str, rep: dict[str, Any]) -> str:
    if key == "office_fpr_upper95_within_budget":
        off = rep.get("office") or {}
        hi = (off.get("fpr_ci95") or [None, None])[1]
        return (f"{off.get('flagged')} of {off.get('flows')} office decisions, "
                f"upper 95% {hi:.3g} against {rep.get('max_fpr_target')}"
                if hi is not None else "no office evidence")
    if key == "all_families_meet_session_floor":
        below = rep.get("families_below_session_floor") or []
        return f"below the floor: {below}" if below else \
            f"session recall {rep.get('session_recall')}, {rep.get('test_sessions')} test sessions"
    if key == "rows_are_independent_decisions":
        return f"duplicate flow instances: {rep.get('duplicate_flow_instances')}"
    if key == "all_declared_families_present":
        missing = rep.get("declared_families_without_data") or []
        return f"missing: {missing}" if missing else f"{len(rep.get('per_family') or [])} families"
    return ""


def render(card: dict[str, Any]) -> str:
    lines = ["# Release card — fast-v1", "",
             f"Contract `{card['contract_hash'][:16]}`, schema `{card['schema_version']}`.", ""]
    phase = card.get("phase", "office")
    verdict = card.get("status") or ("READY" if card["ready"] else "NOT READY")
    heading = "LAB" if phase == "lab" else "RELEASE"
    lines += [f"## {heading}: {verdict}", ""]
    if not card["ready"]:
        lines += ["Blocked by:", ""]
        for g in card["blockers"]:
            state = "unknown" if g["ok"] is None else "FAILS"
            lines.append(f"- **{g['name']}** — {state}. {g['detail']}")
        lines.append("")
    sc = card.get("scope") or {}
    lines += [f"Covers {len(sc.get('release_supported') or [])} families, "
              f"computed from this build's acceptance, not asserted. "
              f"Not covered, and not claimed: {sc.get('planned_not_claimed') or 'none'}.", ""]
    lines += ["## Every gate", "", "| Gate | State | Evidence |", "|---|---|---|"]
    for g in card["gates"]:
        state = {True: "pass", False: "FAIL", None: "unknown"}[g["ok"]]
        lines.append(f"| {g['name']} | {state} | {g['detail'] or g['source']} |")
    lines += ["", "A gate with no evidence is `unknown` and blocks the release. "
                  "Absence of a measurement is not a passing measurement.", ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--acceptance", default=None, help="evaluate_alerts / train_fastv1 report")
    ap.add_argument("--benchmark", default=None)
    ap.add_argument("--protocol-qc", default=None)
    ap.add_argument("--model", default=None, help="model file to bind against the report hashes")
    ap.add_argument("--registry", default=None,
                    help="registry file to read and, with --update-registry, to stamp")
    ap.add_argument("--update-registry", action="store_true",
                    help="when the card is READY, stamp the computed scope as "
                         "release_supported with the evidence behind it")
    ap.add_argument("--scope", default=None,
                    help="full68 scope catalogue; required for a full-scope decision")
    ap.add_argument("--phase", choices=("lab", "office"), default="office")
    ap.add_argument("--out-md", required=True)
    ap.add_argument("--out-json", default=None)
    args = ap.parse_args()

    registry_path = Path(args.registry) if args.registry else None
    card = collect(Path(args.acceptance) if args.acceptance else None,
                   Path(args.benchmark) if args.benchmark else None,
                   Path(args.protocol_qc) if args.protocol_qc else None,
                   Path(args.model) if args.model else None,
                   registry_path, Path(args.scope) if args.scope else None, args.phase)
    stamp: dict[str, Any] | None = None
    if args.update_registry:
        target = registry_path or REGISTRY_PATH
        model_sha = None
        if args.acceptance:
            model_sha = (_load(Path(args.acceptance)) or {}).get("artifacts", {}).get("model_sha256")
        stamp = stamp_registry(card, target,
                               args.acceptance, model_sha)
    Path(args.out_md).write_text(render(card), encoding="utf-8")
    if args.out_json:
        payload = dict(card)
        if stamp is not None:
            payload["registry_stamp"] = stamp
        Path(args.out_json).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ready": card["ready"], "status": card["status"],
                      "blockers": [g["name"] for g in card["blockers"]],
                      "stamp": stamp,
                      "card": args.out_md}, ensure_ascii=False))
    return 0 if card["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
