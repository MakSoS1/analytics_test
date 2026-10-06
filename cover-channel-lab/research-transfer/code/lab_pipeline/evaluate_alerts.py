#!/usr/bin/env python3
"""Evaluation that cannot hide a failing family behind a flow-weighted average.

The reason this module exists: the deployed packet model scores micro-recall
0.998 on campaign_04 and AmneziaWG 40/58 = 0.690 at the same threshold. Every one
of the 18 missed flows is AmneziaWG. The average hides it because families
contribute wildly different flow counts — httptunnel produces 1845 test flows
from 59 sessions, AmneziaWG produces 58 flows from 58 sessions. A mean over
flows is a mean over httptunnel.

So every report here carries, always and together:

  micro recall      over flows, the number that looks good
  macro recall      unweighted mean over families, the number that does not
  per-family        flows AND independent sessions, with a binomial upper bound
  session recall    a session counts as detected if any of its flows fired
  coverage          how many metadata sessions reached a decision at all

`production_ready` is computed, never asserted: it requires every family to pass
its own recall floor, the FPR upper confidence bound to fit the budget, and the
evidence gates to be filled in. Missing evidence returns false.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
from lab_pipeline.flow_tier import predict_proba  # noqa: E402
from lab_pipeline.online_schema import SCHEMA_VERSION, contract_hash  # noqa: E402

MIN_TEST_SESSIONS = 50  # plan 7.2: below this a family metric is not publishable


def count_duplicate_instances(rows: list[dict[str, Any]]) -> int:
    """Rows beyond the first for any flow instance id.

    Every row is supposed to be one bounded decision about one connection. The
    observation table used to re-decide a live flow every twenty packets under an
    unchanged id, so a corpus could hold a thousand rows describing one
    connection. Averaging over those overstates the evidence behind an FPR and
    turns "detected" into "detected on one of many tries".

    Instance ids are pseudonyms, unique only inside the capture that produced
    them: a lab session, or an office capture window. Comparing them across that
    boundary reports collisions as re-decided flows — on the first office corpus
    that was 3 018 phantom duplicates, none of them real.
    """
    seen: set[tuple[str, str]] = set()
    dupes = 0
    for r in rows:
        inst = str(r.get("flow_instance_id") or "")
        if not inst:
            continue
        scope = str(r.get("session_id") or r.get("capture_id") or "")
        pair = (scope, inst)
        if pair in seen:
            dupes += 1
        else:
            seen.add(pair)
    return dupes


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = q * (len(ordered) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def wilson_interval(successes: int, total: int, z: float = 1.959963985) -> tuple[float, float]:
    """Wilson score interval — usable at 0 or 100 percent, unlike normal approx.

    A count of 0 false positives out of 8 118 does not demonstrate FPR <= 1e-4:
    the upper bound is about 4.5e-4. The gate uses the bound, not the point.
    """
    if total <= 0:
        return (0.0, 1.0)
    p = successes / total
    d = 1.0 + z * z / total
    centre = (p + z * z / (2 * total)) / d
    half = (z / d) * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
    return (max(0.0, centre - half), min(1.0, centre + half))


def load_rows(path: Path) -> list[dict[str, Any]]:
    opener: Any = open
    if path.suffix == ".gz":
        import gzip

        opener = gzip.open
    with opener(path, "rt") as fh:
        return list(csv.DictReader(fh))


def score_rows(model: dict[str, Any], rows: list[dict[str, Any]]) -> list[float]:
    feats = model["features"]
    return [predict_proba(model, {f: float(r.get(f) or 0.0) for f in feats}) for r in rows]


def evaluate(
    model: dict[str, Any],
    lab_rows: list[dict[str, Any]],
    office_rows: list[dict[str, Any]] | None,
    threshold: float,
    family_recall_floor: float,
    max_fpr: float,
    metadata_sessions: dict[str, int] | None = None,
    declared_families: list[str] | None = None,
    mix_rows: list[dict[str, Any]] | None = None,
    test_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pos = [r for r in lab_rows if str(r.get("y")) == "1"]
    neg = [r for r in lab_rows if str(r.get("y")) != "1"]
    p_pos = score_rows(model, pos)
    p_neg = score_rows(model, neg)

    fam_flows: dict[str, list[int]] = defaultdict(list)
    fam_sessions: dict[str, dict[str, int]] = defaultdict(dict)
    # (family, session) -> list of (offset, hit), to answer when the first alert
    # appeared rather than only whether one ever did.
    timeline: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    for r, s in zip(pos, p_pos):
        fam = r.get("label_family") or "?"
        hit = 1 if s >= threshold else 0
        fam_flows[fam].append(hit)
        sid = r.get("session_id") or ""
        fam_sessions[fam][sid] = max(fam_sessions[fam].get(sid, 0), hit)
        raw_off = r.get("decision_offset_s")
        if raw_off not in (None, ""):
            try:
                timeline[(fam, sid)].append((float(raw_off), hit))
            except (TypeError, ValueError):
                pass

    # Early detection, per family: did the FIRST decision of a session fire, and
    # how long after the session opened did the first alert appear.
    fam_first: dict[str, list[int]] = defaultdict(list)
    fam_latency: dict[str, list[float]] = defaultdict(list)
    for (fam, _sid), entries in timeline.items():
        entries.sort(key=lambda e: e[0])
        fam_first[fam].append(entries[0][1])
        fired = [off for off, hit in entries if hit]
        if fired:
            fam_latency[fam].append(fired[0])

    per_family = []
    for fam in sorted(fam_flows):
        hits = fam_flows[fam]
        sess = fam_sessions[fam]
        n_f, d_f = len(hits), sum(hits)
        n_s, d_s = len(sess), sum(sess.values())
        lo_f, hi_f = wilson_interval(d_f, n_f)
        per_family.append({
            "family": fam,
            "test_flows": n_f, "flows_detected": d_f,
            "flow_recall": d_f / n_f if n_f else 0.0,
            "flow_recall_ci95": [lo_f, hi_f],
            "test_sessions": n_s, "sessions_detected": d_s,
            "session_recall": d_s / n_s if n_s else 0.0,
            "session_recall_ci95": list(wilson_interval(d_s, n_s)),
            "enough_sessions": n_s >= MIN_TEST_SESSIONS,
            "passes_flow_floor": (d_f / n_f if n_f else 0.0) >= family_recall_floor,
            "passes_session_floor": (d_s / n_s if n_s else 0.0) >= family_recall_floor,
            "first_decision_recall": (
                sum(fam_first[fam]) / len(fam_first[fam]) if fam_first.get(fam) else None
            ),
            "time_to_alert_p50": _percentile(fam_latency.get(fam, []), 0.5),
            "time_to_alert_p90": _percentile(fam_latency.get(fam, []), 0.9),
        })
    per_family.sort(key=lambda d: d["flow_recall"])

    total_flows = sum(d["test_flows"] for d in per_family)
    total_hits = sum(d["flows_detected"] for d in per_family)
    micro = total_hits / total_flows if total_flows else 0.0
    macro = (sum(d["flow_recall"] for d in per_family) / len(per_family)) if per_family else 0.0
    sess_tot = sum(d["test_sessions"] for d in per_family)
    sess_hit = sum(d["sessions_detected"] for d in per_family)

    lab_fp = sum(1 for s in p_neg if s >= threshold)
    report: dict[str, Any] = {
        "threshold": threshold,
        "family_recall_floor": family_recall_floor,
        "max_fpr_target": max_fpr,
        "micro_recall": micro,
        "macro_recall": macro,
        "session_recall": sess_hit / sess_tot if sess_tot else 0.0,
        "test_flows": total_flows, "test_sessions": sess_tot,
        "lab_benign": {
            "flows": len(neg), "flagged": lab_fp,
            "fpr": lab_fp / len(neg) if neg else None,
            "fpr_ci95": list(wilson_interval(lab_fp, len(neg))),
        },
        "per_family": per_family,
        "families_below_session_floor": [d["family"] for d in per_family if not d["passes_session_floor"]],
        "families_below_flow_floor": [d["family"] for d in per_family if not d["passes_flow_floor"]],
        "families_below_floor": [d["family"] for d in per_family if not d["passes_session_floor"]],
        "families_without_enough_sessions": [d["family"] for d in per_family if not d["enough_sessions"]],
    }

    all_first = [v for vals in fam_first.values() for v in vals]
    all_latency = [v for vals in fam_latency.values() for v in vals]
    report["first_decision_recall"] = (sum(all_first) / len(all_first)) if all_first else None
    report["time_to_alert_p50"] = _percentile(all_latency, 0.5)
    report["time_to_alert_p90"] = _percentile(all_latency, 0.9)
    report["early_detection_note"] = (
        "first_decision_recall is the share of sessions caught on their earliest "
        "decision; session_recall allows any later flow to be the one that fires. "
        "Reported, not gated: no alert-latency budget has been agreed."
    )

    dupes_lab = count_duplicate_instances(lab_rows)
    dupes_office = count_duplicate_instances(office_rows or [])
    report["duplicate_flow_instances"] = {"lab": dupes_lab, "office": dupes_office}

    if office_rows:
        p_off = score_rows(model, office_rows)
        off_fp = sum(1 for s in p_off if s >= threshold)
        lo, hi = wilson_interval(off_fp, len(p_off))
        report["office"] = {
            "flows": len(p_off), "flagged": off_fp,
            "fpr": off_fp / len(p_off) if p_off else None,
            "fpr_ci95": [lo, hi],
            "fpr_upper95_within_budget": hi <= max_fpr,
            "label_note": "office rows are presumed negative and unlabeled; a real tunnel there inflates this",
        }

    if test_manifest:
        declared_ids = [str(s) for s in (test_manifest.get("test_session_ids") or [])]
        decided = {sid for fam in fam_sessions.values() for sid in fam}
        qc_ex = [str(s) for s in (test_manifest.get("qc_excluded") or [])]
        unscorable = [str(s) for s in (test_manifest.get("unscorable") or [])]
        missing = [str(s) for s in (test_manifest.get("missing") or [])]
        if not missing:
            missing = [s for s in declared_ids if s not in decided
                       and s not in set(qc_ex) and s not in set(unscorable)]
        report["coverage"] = {
            "test_sessions_declared": len(declared_ids),
            "sessions_in_metadata": len(declared_ids),
            "sessions_reaching_a_decision": len(decided & set(declared_ids)) if declared_ids else sess_tot,
            "qc_excluded": len(qc_ex),
            "unscorable": len(unscorable),
            "missing": len(missing),
            "coverage": (
                (len(decided & set(declared_ids)) / len(declared_ids))
                if declared_ids else None
            ),
            "note": "denominator is the frozen TEST session set, not metadata of every role",
        }
        if metadata_sessions:
            report["coverage"]["all_role_metadata_sessions"] = sum(metadata_sessions.values())
        e2e_den = len(declared_ids) if declared_ids else (sess_tot + len(missing))
        e2e_hit = sum(1 for sid in declared_ids if any(fam.get(sid) for fam in fam_sessions.values()))
        if not declared_ids:
            e2e_hit, e2e_den = sess_hit, sess_tot + len(missing)
        report["end_to_end_session_recall"] = e2e_hit / e2e_den if e2e_den else 0.0
    elif metadata_sessions:
        declared = sum(metadata_sessions.values())
        report["coverage"] = {
            "sessions_in_metadata": declared,
            "sessions_reaching_a_decision": sess_tot,
            "coverage": sess_tot / declared if declared else None,
            "note": "all-role metadata count is not a test-coverage denominator; "
                    "pass test_manifest for an honest figure",
        }
        report["end_to_end_session_recall"] = sess_hit / sess_tot if sess_tot else 0.0
    else:
        report["end_to_end_session_recall"] = sess_hit / sess_tot if sess_tot else 0.0

    if mix_rows:
        y_mix = [int(float(r.get("y") or 0)) for r in mix_rows]
        p_mix = score_rows(model, mix_rows)
        pred = [1 if s >= threshold else 0 for s in p_mix]
        tp = sum(1 for yi, pi in zip(y_mix, pred) if yi == 1 and pi == 1)
        fp = sum(1 for yi, pi in zip(y_mix, pred) if yi == 0 and pi == 1)
        fn = sum(1 for yi, pi in zip(y_mix, pred) if yi == 1 and pi == 0)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        report["mix"] = {
            "rows": len(mix_rows), "tp": tp, "fp": fp, "fn": fn,
            "precision": prec, "recall": rec,
            "precision_within_budget": prec >= 0.95,
            "recall_within_budget": rec >= 0.95,
            "label_note": "labelled mix at the frozen threshold; not office presumed-negatives",
        }

    # Which unit the floor applies to.
    #
    # The fast level alerts per flow instance, and one tunnel session produces
    # many flows. Flagging 100 of a session's 150 flows still detects that
    # tunnel — the SOC gets an alert either way; the other 50 cost nothing
    # operationally. So the question a recall floor has to answer is "was this
    # tunnel session detected at all", which is the session number.
    #
    # The flow number stays in the report as a diagnostic: it says how much of a
    # session's traffic the model recognises, which matters for how quickly an
    # alert appears and for host-level aggregation. It is not the acceptance
    # criterion, and the report names both so neither can be quoted alone.
    # Absence of evidence is not evidence of a pass.
    #
    # Every family gate iterates `per_family`, and an empty list satisfies "no
    # family is below the floor" exactly as well as a full one does. Measured:
    # evaluate(model, [], 80 000 negatives, ...) returned production_ready=True
    # with zero families and session_recall 0.0 — a detector that detects
    # nothing, cleared for release. A declared family with no rows is the same
    # mistake at family scale, so a release list can be handed in and checked.
    declared = [str(f) for f in (declared_families or [])]
    families_present = {d["family"] for d in per_family}
    report["declared_families"] = declared
    report["declared_families_without_data"] = [f for f in declared if f not in families_present]
    report["positive_rows"] = len(pos)

    gates = {
        "positive_evidence_present": bool(pos) and bool(per_family),
        "all_declared_families_present": not report["declared_families_without_data"],
        "all_families_meet_session_floor": not report["families_below_session_floor"],
        "all_families_have_enough_sessions": not report["families_without_enough_sessions"],
        "office_fpr_upper95_within_budget": bool(report.get("office", {}).get("fpr_upper95_within_budget", False)),
        "office_evidence_present": bool(office_rows),
        # Every row must be one decision about one connection. Without this a
        # corpus extracted by a build that re-decided live flows would be
        # accepted, and its FPR bound would rest on a denominator that counts the
        # same connection over and over.
        "rows_are_independent_decisions": (dupes_lab == 0 and dupes_office == 0),
        # The model must have been trained against the contract the sensor
        # computes. A stamp that does not match means the vector being scored is
        # not the vector being produced.
        "model_matches_current_contract": (
            str(model.get("contract_hash") or "") == contract_hash()
            and str(model.get("schema_version") or SCHEMA_VERSION) == SCHEMA_VERSION
        ),
    }
    gates["all_families_meet_flow_floor"] = not report["families_below_flow_floor"]
    report["gates"] = gates
    report["floor_unit"] = ("session: a tunnel session counts as detected when any of its "
                            "flows fires; the flow number is reported as a diagnostic")
    report["lab_metrics_publishable"] = gates["all_families_have_enough_sessions"]

    # Two different questions, kept apart because reporting one as the other let
    # a test-slice result read as a release decision.
    #
    #   metrics_pass      did the numbers clear their floors on this slice
    #   production_ready  ...and is the evidence behind them real: the sensor
    #                     computes this vector, the office denominator counts
    #                     independent decisions, nothing was counted twice
    #
    # The flow floor is in neither: see the note above `gates`.
    metric_gates = ("positive_evidence_present", "all_families_meet_session_floor",
                    "all_families_have_enough_sessions")
    report["metrics_pass"] = all(gates[k] for k in metric_gates)
    report["production_ready"] = all(
        v for k, v in gates.items() if k != "all_families_meet_flow_floor"
    )
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True)
    ap.add_argument("--lab-csv", required=True, help="rows with y, label_family, session_id")
    ap.add_argument("--office-csv", default=None)
    ap.add_argument("--campaign", default="campaign_04", help="'' to use every row")
    ap.add_argument("--threshold", type=float, default=None, help="default: the model's own")
    ap.add_argument("--family-recall-floor", type=float, default=0.95)
    ap.add_argument("--max-fpr", type=float, default=1e-4)
    ap.add_argument("--metadata-dir", default=None, help="for the coverage denominator")
    ap.add_argument("--declared-families", default=None,
                    help="comma-separated release list; a declared family with no rows blocks")
    ap.add_argument("--out-json", required=True)
    args = ap.parse_args()

    model = json.loads(Path(args.model).read_text())
    thr = args.threshold if args.threshold is not None else float(model.get("threshold", 0.5))

    rows = load_rows(Path(args.lab_csv))
    if args.campaign:
        rows = [r for r in rows if r.get("campaign_id") == args.campaign]
    office = load_rows(Path(args.office_csv)) if args.office_csv else None

    meta_counts: dict[str, int] | None = None
    if args.metadata_dir:
        meta_counts = defaultdict(int)
        for f in Path(args.metadata_dir).glob("*_tunnel.json"):
            try:
                d = json.loads(f.read_text())
            except (OSError, ValueError):
                continue
            if not args.campaign or d.get("campaign_id") == args.campaign:
                meta_counts[d.get("label_family") or "?"] += 1

    declared = [f.strip() for f in (args.declared_families or "").split(",") if f.strip()]
    report = evaluate(model, rows, office, thr, args.family_recall_floor, args.max_fpr,
                      meta_counts, declared_families=declared or None)
    Path(args.out_json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({
        "micro_recall": round(report["micro_recall"], 4),
        "macro_recall": round(report["macro_recall"], 4),
        "session_recall": round(report["session_recall"], 4),
        "families_below_floor": report["families_below_floor"],
        "lab_fpr": report["lab_benign"]["fpr"],
        "office_fpr": report.get("office", {}).get("fpr"),
        "metrics_pass": report["metrics_pass"],
        "production_ready": report["production_ready"],
        "report": args.out_json,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
