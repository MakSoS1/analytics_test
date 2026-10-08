# SDD ledger — plan: docs/superpowers/plans/2026-10-09-office-benign-adaptix-transfer.md

## Execution setup

- Working copy: `adaptix_detector_research`, a separate Git clone and feature branch; the user-owned `analytics_test` checkout and its uncommitted files are untouched.
- No linked git worktree was created: the existing separate clone already isolates operations from the original repository. Ruling: use this clone and stage explicit paths only — creating another worktree would omit uncommitted Adaptix evaluator components; cost if wrong: branch metadata differs from recommended worktree layout, but source isolation is maintained.
- Baseline initially failed to import 46 tests because this environment lacked `pyarrow` (and one previously known CSV/TSV/JSONL support mismatch); `pyarrow==22.0.0` was installed under `/tmp/adaptix_pydeps_20261009` rather than into the project or global Python.

## Pre-flight interface checks

- Task 1 → Task 3: verified HTTPS fixture produces immutable PCAP and semantic receipt; Task 3 consumes only the measured production extractor output. No type conflict.
- Task 2 → Task 3: `profile_office_reference(days, columns=...)` supplies numeric summary; Task 3 consumes these summaries and frozen numeric features, never origin labels. No type conflict.
- Task 1 → Task 4: verified legitimate hard negatives must be separately labelled as fixture controls, never as verified office labels. No type conflict.
- Task 3/4 → Task 5: both evaluators emit safe aggregate JSON, CI must not upload raw captures. No type conflict.
- Task 5 → Task 6: documentation claims are sourced from completed CI JSON; unsuccessful capture means metrics unavailable, never fabricated. No type conflict.
- Extra user request added Task 6 documentation audit and chronological history to the approved plan.

## Task progress

- Initial full clone baseline after `pyarrow` installation: 313 tests, 1 failure, 2 errors, 2 skipped. Two errors arose from missing `office_workload.py`; the remaining failure/error from previously missing measured CSV/TSV/JSONL ingestion.
- Task 1 RED: imported tests raised `ModuleNotFoundError: natural_traffic.office_workload` (expected).
- Task 1 GREEN: `6/6` local HTTPS workload tests after sandbox escalation for loopback socket; confirmed real semantic HTTPS actions and simulated missing-handshake fail closed.
- Task 1 Ruling: port the already authored strict CSV/TSV/JSONL importer from the user's original dirty working tree, in addition to the fixture, because it was the root cause of preexisting regression failures and is required by the approved input-format contract. Risk if wrong: support for extra measured feature formats enlarges ingestion surface, mitigated by the 12-column/80%-finite fail-closed validator and existing tests.
- Task 1 complete: commit `ceb7073`; full suite `PYTHONPATH=/tmp/adaptix_pydeps_20261009:code python -m unittest discover -s code/tests -q` with local-loopback permission → **322 tests, 0 failures, 0 errors, 2 skipped**, 45.547 s. Workflow parsed as YAML; `git diff --cached --check` clean before commit.
- Task 2 RED: `ModuleNotFoundError: natural_traffic.office_profile_audit`. Additional regression tests caught numeric TLS `0` falsely treated as measured and Sep 23 missing its historical-unmatched-scope marker (1 failure, 2 errors before fix).
- Task 2 GREEN: 6/6 office-profile tests, including real pinned 22/23/28 manifests and no cross-day pseudonym joining. Real audited counts: Sep 22: 4,000 rows/382 groups/pkt median 21; Sep 23: 5,726 rows/332 within-day host groups/pkt median 2 (different source scope); Sep 28: 4,002 rows/348 groups/pkt median 21. TLS for Sep 22 unmeasured; numeric zero in other days now treated as unmeasured.
- Task 2 complete: commit `46fbc5f`; full suite **328 tests, 0 failures, 0 errors, 2 skipped**, 48.204 s. Safe local aggregate report `/tmp/office-profile-audit-20261009.json` (produced before the 0-TLS correction; rerun before any publication); `git diff --cached --check` clean.
- Task 3 RED: `ModuleNotFoundError: natural_traffic.benign_transfer_evaluation`; additional test of feature-family shift returned missing-key error before implementation.
- Task 3 GREEN: 6/6 grouped C2ST tests, including independent source-group splits, strong synthetic shift, train-only preprocessing, strict feature eligibility and explicit insufficient-support outcomes. Frozen reference 22/28 office samples remain unverified. All metrics from synthetic unit fixtures are test-only, not naturalness evidence.
- Task 3 complete: commit `d3ef4b1`; full suite **334 tests, 0 failures, 0 errors, 2 skipped**, 46.907 s. `git diff --cached --check` clean.
- Task 4 RED: four new cases failed for absent hard-negative argument, training-only threshold metadata and small-sample/model-comparison fields. An additional negative control failed when an unverified hard-negative caller was accepted without semantic attestation.
- Task 4 GREEN: 11/11 Adaptix paired-detector tests. ExtraTrees reported as predeclared exploratory comparison only; held-out recall uses the training-control exploratory threshold, no office FPR. Caller must explicitly attest `semantically_verified=True` for each hard negative; this is not independent authentication of its source.
- Task 4 Ruling: report `uncertainty_status=insufficient_support` below 20 independent pairs; for larger samples use `not_estimated` until a statistically appropriate pair-bootstrap is implemented, rather than fabricate confidence bounds. Risk if wrong: less polished model report, but avoids misleading precision.
- Task 4 complete: commit `8d0d818`; full suite **339 tests, 0 failures, 0 errors, 2 skipped**, 49.174 s. `git diff --cached --check` clean.
- Task 5 RED: new workflow unit tests failed because branch `office-benign-adaptix-transfer-2026-10-09` was not triggered and the benign transfer/audit step was absent.
- Task 5 GREEN: new branch triggers both isolated Adaptix research and benign TDD; skips expensive Cover fixture. Benign workflow now blocks transfer on semantic TLS, complete PCAP handshake evidence, unmodified hash and successful production extractor. One local runner is explicitly one independently grouped benign source: generated-vs-office status `insufficient_support` is mandatory. Only four safe JSON reports, never PCAP or TLS keys, are uploaded. Targeted workflow tests **11/11** passed. Local office CLI independently measured 4000/5726/4002 rows from immutable manifests, using TLS-zero correction.
- Task 5 outstanding: new live CI run and new aggregate v2 ExtraTrees/threshold model metrics must be observed after publishing the authorized new branch. Until then reports retain historical v1 metrics with explicit provenance; `production_ready=false`.
- Task 6 RED: documentation tests could not open current status index and research history (expected missing files); one new check later caught the omission of an explicit unknown-label explanation.
- Task 6 GREEN: added `CURRENT_PROJECT_STATUS.md`, `OFFICE_BENIGN_AND_TECHNIQUE_TRANSFER_RESULTS.md`, `RESEARCH_CHANGELOG_2026.md`, chronological run links, dated dataset summary, old/new protocol distinction, exact feature-family/missing-label limitations. Updated root/subproject README and important existing model/workload/plan/status docs. All linked relative documentation paths checked by unit test.
- Joint local full suite after Tasks 5 and 6 initial green: **345 tests, 0 failures, 0 errors, 2 skipped**, 52.869 s. One additional document-link verification test added after this full run (targeted docs: 4/4 green). Await next full verification and remote Actions.
