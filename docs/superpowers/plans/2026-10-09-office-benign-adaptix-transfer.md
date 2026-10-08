# Office Benign Workload and Adaptix Transfer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Объединить семантически подтверждённые легитимные HTTPS-сессии, офисную профильную диагностику и честную независимую оценку детектора Adaptix; получить новые *измеренные* CI-метрики без ложных production claims.

**Architecture:** Офисные Parquet используются только как immutable reference без приписывания benign. Отдельный локальный TLS workload создаёт реальные проверяемые действия; paired Adaptix/control захваты проходят штатный extractor. Изолированные аудиторы сравнивают legitimate-vs-office и scenario-vs-control, публикуя раздельные safe JSON с group-held-out метриками.

**Tech Stack:** Python 3.12; `pandas`, `numpy`, `scikit-learn`, `pyarrow`; стандартные `unittest`, `ssl`/`http.client`; Linux `tcpdump` и OpenSSL; GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-09-office-benign-and-adaptix-transfer-design.md`

**Execution closeout (2026-10-09):** All six implementation tasks executed; TDD and proof-of-execution details are in `docs/superpowers/progress/2026-10-09-office-benign-adaptix-execution.md`. Final [benign/office CI 37857455916](https://github.com/MakSoS1/analytics_test/actions/runs/37857455916) and [paired Adaptix CI 37855273740](https://github.com/MakSoS1/analytics_test/actions/runs/37855273740) passed their scoped workflows; `production_ready=false` because naturalness and blind labeled transfer are not established. The checkboxes below preserve the originally approved **execution plan**, not a replacement for this evidence ledger.

## Global Constraints

- Исходные офисные/сценарные PCAP неизменяемы; сверять SHA-256 до и после обработки.
- Офисные строки 22/23/28 сентября: `unverified/unlabeled`, не `benign`; FPR на них недоступна.
- 22 сентября TLS-признаки не измерялись; не восстанавливать их нулями или предполагаемыми значениями.
- `pair_id`, `campaign_id`, `capture_day_id`, `profile_id`, identity/TLS fingerprints и provenance никогда не включать в model-X.
- Выбор признаков, предобработка, балансировка и порог — строго на training groups, ни разу на внешнем holdout.
- Из 6 независимых Adaptix-пар нельзя делать production-выводов даже при ROC-AUC=1.0.
- Не ретаймить, не изменять payload и не адаптировать атакующие пакеты для обхода обнаружения.
- В CI публиковать только агрегаты; без PCAP, сертификатов, секретов и per-host scores.
- Не затрагивать пользовательские незакоммиченные файлы первой рабочей копии и PR №58.

## Review Focus

1. Office reference Sep 22 не содержит TLS: `test_missing_tls_stays_unavailable` в Task 2.
2. Sep 23 имеет другую псевдонимизацию/группировку: `test_older_day_never_cross_joins_identity` в Task 2.
3. Пропущен handshake/неполный wire capture: `test_capture_fails_on_missing_handshake` в Task 1.
4. Признак или labels тестовой группы влияют на обучение: `test_outer_holdout_is_not_used_for_selection` в Task 4.
5. Внешний CI не смог захватить real PCAP: `test_ci_requires_verified_capture_and_sanitized_report` в Task 5.

---

### Task 1: Integrate verified benign workload without overwriting user changes

**Files:**
- Import preserving original content from `analytics_test/cover-channel-lab/research-transfer/code/natural_traffic/office_workload.py` into this feature branch's matching package path.
- Import corresponding `code/tests/test_natural_office_workload.py`.
- Port only reviewed independent CI job from `analytics_test/.github/workflows/natural-traffic-tdd.yml`.
- Reference: `analytics_test/cover-channel-lab/research-transfer/docs/VERIFIED_BENIGN_OFFICE_WORKLOAD.md`.

**Interfaces:**
- Consumes: Python stdlib `ssl`, `http.client`, local HTTPS test server; `office_injection.source.read_pcap`.
- Produces: `run_benign_office_workload(out: Path, *, sessions: int, seed: int, capture: bool) -> dict` and `workload_receipt.json`; source is immutable.

- [ ] **Step 1: Import tests before production code** from the original working tree: `test_real_tls_tasks_preserve_application_causality`, `test_tcp_handshakes_are_accounted_for_independently_of_actions`, `test_capture_waits_for_initialized_pcap_header`, `test_refuses_unbounded_or_invalid_sessions` and `test_refuses_overwrite_of_existing_corpus`. Add `test_capture_fails_on_missing_handshake` to assert a missing handshake prevents the verified capture receipt.
- [ ] **Step 2: Verify RED** `cd cover-channel-lab/research-transfer && PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_office_workload.py' -v` — target module absent in this worktree.
- [ ] **Step 3: Import original module and preserve its semantic/certificate/capture checks**; do not weaken `tcpdump` readiness, handshake parity, hash audits or loopback binding. Preserve the original signature `run_benign_office_workload(out: Path, *, sessions: int = 3, seed: int = 20261008, action_pause_seconds: float = 0.03, capture: bool = False) -> dict[str, object]`. Integrate related CI without rewriting original worktree. A browser client requires a real browser runtime and separate verified receipt; if unavailable, report the capability absent rather than claim browser naturalness.
- [ ] **Step 4: Verify GREEN** repeat Step 2, then `python -m compileall -q code/natural_traffic/office_workload.py`.
- [ ] **Step 5: Commit** only imported module, test and corresponding CI job with `git add -- <explicit files>` then `git commit -m 'feat: integrate verified benign office workload'`.

### Task 2: Implement read-only office-profile audit

**Files:**
- Create `cover-channel-lab/research-transfer/code/natural_traffic/office_profile_audit.py`.
- Create `cover-channel-lab/research-transfer/code/tests/test_natural_office_profile_audit.py`.

**Interfaces:**
- Consumes: `load_office_reference(additional_days_dir: Path, office_cover_dir: Path | None) -> dict[str, pd.DataFrame]`; `TRANSPORT_FEATURES`.
- Produces: `profile_office_reference(days: dict[str, pd.DataFrame], *, columns: list[str]) -> dict` and safe JSON CLI `--office-dir`, `--office-cover-dir`, `--out`.
- Per day: `rows`, `independent_groups` (or `unavailable`), measured feature coverage/quantiles, `unavailable_families`; never raw identity strings.

- [ ] **Step 1: Write failing tests** `test_missing_tls_stays_unavailable`, `test_older_day_never_cross_joins_identity`, `test_profile_contains_only_numeric_aggregates`; use small frames with `capture_day_id`, `independent_source_group`, null TLS, and arbitrary HMAC strings; assert TLS not zero-filled and no source groups/IP in JSON.
- [ ] **Step 2: Verify RED** `PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_office_profile_audit.py' -v` from `research-transfer` — ImportError for missing module.
- [ ] **Step 3: Implement** `profile_office_reference` on *predeclared measured* numeric transport columns, finite-only coverage and deterministic robust quantiles (0.1/0.5/0.9). Group Sep 23 only inside its own day; mark cross-snapshot join unsupported.
- [ ] **Step 4: Verify GREEN** repeat Step 2; add real-data audit test using immutable manifests for 22/23/28 and check 4000/5726/4002 rows.
- [ ] **Step 5: Commit** module/tests with `git commit -m 'feat: audit measured office profiles without labels'`.

### Task 3: Add independent benign-background comparison

**Files:**
- Create `cover-channel-lab/research-transfer/code/natural_traffic/benign_transfer_evaluation.py`.
- Create `cover-channel-lab/research-transfer/code/tests/test_natural_benign_transfer_evaluation.py`.

**Interfaces:**
- Consumes: `profile_office_reference`; office reference; measured benign extraction `office_sessions.parquet`; independent capture/group IDs.
- Produces: `evaluate_benign_transfer(office_days: dict[str, pd.DataFrame], benign: pd.DataFrame, *, feature_columns: list[str], benign_group_ids: list[str]) -> dict`.
- Report: `office_negative_control_auc`, `generated_vs_office_c2st_auc`, feature-family shifts, support/groups, `naturalness_status=not_proven` unless genuinely new independent target evidence is provided.

- [ ] **Step 1: Write failing tests** `test_group_split_has_no_source_overlap`, `test_benign_c2st_does_not_train_on_outer_holdout`, `test_missing_feature_coverage_fails_closed`; assert null/insufficient support yields explicit `insufficient_support`, never 0.5 fabricated as a result.
- [ ] **Step 2: Verify RED** run test file via `PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_benign_transfer_evaluation.py' -v`.
- [ ] **Step 3: Implement** grouped train/holdout C2ST with `HistGradientBoostingClassifier` and `ExtraTreesClassifier`; office-vs-office negative control, train-only median/imputation and fixed candidate feature-family comparisons; no iterative tuning of generated activity to maximize classifier confusion.
- [ ] **Step 4: Verify GREEN** repeat Step 2; on a deterministic synthetic dataset, assert known strong domain shift gives C2ST above a neutral baseline without inventing production naturalness.
- [ ] **Step 5: Commit** new evaluator/tests with `git commit -m 'feat: add grouped benign-office transfer diagnostics'`.

### Task 4: Extend paired Adaptix assessment with hard negatives and uncertainty

**Files:**
- Modify `cover-channel-lab/research-transfer/code/natural_traffic/adaptix_detector_research.py`.
- Modify `cover-channel-lab/research-transfer/code/tests/test_natural_adaptix_detector_research.py`.

**Interfaces:**
- Existing API stays valid: `evaluate_paired_detector(captures: Sequence[CaptureFeatures], *, feature_columns: Sequence[str] | None, max_features: int, office_days: dict | None) -> dict`.
- Add optional independent controls via `hard_negative_captures: Sequence[CaptureFeatures] | None = None` with a separate `arm=hard_negative` validation path; no reclassification of office unknowns.
- Report extends `folds` with per-fold `positive_count`, `control_count`, `threshold_source`, `recall_at_train_control_threshold`, `hard_negative_alert_fraction` or `insufficient_support`; preserve v1 fields for readers.

- [ ] **Step 1: Write failing tests** `test_outer_holdout_is_not_used_for_selection` (alter all withheld rows; selected feature list remains identical), `test_hard_negative_not_mislabeled_office`, `test_threshold_does_not_use_holdout`, `test_empty_hard_negatives_explicitly_unavailable`.
- [ ] **Step 2: Verify RED** `PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_adaptix_detector_research.py' -v` — new cases fail on absent capabilities.
- [ ] **Step 3: Implement** validation, train-control-derived threshold and outer-test recall, strict per-fold support, descriptive uncertainty using pair-resampling only when enough independent pairs; otherwise emit `insufficient_support`. Compute hard negative fractions only for verified hard negatives with compatible measured feature columns. Keep leave-one-profile and leave-one-transport splits unchanged.
- [ ] **Step 4: Verify GREEN** repeat Step 2; test preservation of old fold AUC on the six-pair fixture and `origin_only_roc_auc` diagnostic.
- [ ] **Step 5: Commit** module/tests with `git commit -m 'feat: report Adaptix transfer controls and small-N limits'`.

### Task 5: CI execution, safe metric reporting and release gates

**Files:**
- Modify `.github/workflows/isolated-cover-adaptix-research.yml`.
- Modify `.github/workflows/natural-traffic-tdd.yml`.
- Modify `cover-channel-lab/research-transfer/code/tests/test_natural_isolated_lab_workflow.py`.
- Modify `cover-channel-lab/research-transfer/docs/ADAPTIX_PAIRED_DETECTION_RESEARCH.md`.
- Create `cover-channel-lab/research-transfer/docs/OFFICE_BENIGN_AND_TECHNIQUE_TRANSFER_RESULTS.md`.

**Interfaces:**
- Consumes: Task 1 `workload_receipt`, Task 2 `office-profile-report.json`, Task 3 `benign-transfer-report.json`, Task 4 `adaptix-detector-report.json`.
- Produces: CI artifact with only safe aggregated reports, source/count diagnostics, and explicit `technique_research_validated=false` / `production_ready=false` pending independent evidence.

- [ ] **Step 1: Write failing workflow tests** `test_ci_requires_verified_capture_and_sanitized_report` and `test_adaptix_training_depends_on_extractor_success`; assert workflow fails on missing handshake/extraction and artifact paths are safe JSON only, no `*.pcap`, key or certificate files.
- [ ] **Step 2: Verify RED** `PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_isolated_lab_workflow.py' -v` with new assertions.
- [ ] **Step 3: Implement** workflow links to verified HTTPS capture and paired Adaptix extractor; run Tasks 2–4 after validation, upload safe reports only; do not publish fitted models, raw captures or per-host scores. Update docs with real run ID, capture counts, feature lists, fold metrics and limitations.
- [ ] **Step 4: Verify GREEN** run targeted tests, then full `PYTHONPATH=code python -m unittest discover -s code/tests -v`; run `git diff --check`; trigger the authorized GitHub Actions branch workflow and inspect completed job and JSON before claiming measured metrics.
- [ ] **Step 5: Commit** verified CI/docs/tests with `git commit -m 'ci: evaluate benign office and Adaptix transfer from captures'`. If CI cannot run or no independent new captures exist, report exact blocker and only previously verified metrics.

### Task 6: Maintain consistent project documentation and research history

**Files:**
- Modify `README.md` and `cover-channel-lab/research-transfer/README.md` to link the current index.
- Create `cover-channel-lab/research-transfer/docs/CURRENT_PROJECT_STATUS.md` with audited module inventory, command examples, metric/status definitions and evidence links.
- Create `cover-channel-lab/research-transfer/docs/RESEARCH_CHANGELOG_2026.md` with dated experiments, available source IDs and honest known failures.
- Modify `cover-channel-lab/research-transfer/docs/ADAPTIX_PAIRED_DETECTION_RESEARCH.md` and `VERIFIED_BENIGN_OFFICE_WORKLOAD.md` to cross-link the current report (do not erase historical measurements).
- Create `cover-channel-lab/research-transfer/code/tests/test_natural_project_docs.py`.

**Interfaces:**
- Consumes: Task 5 actual CI report JSON plus earlier verified naturalness feasibility and Adaptix research records; git history and extant documentation.
- Produces: one accurate navigable entry point, one chronological research log and a complete reproducibility/status guide. Every numerical claim cites the run/report that measured it.

- [ ] **Step 1: Write failing tests** `test_status_index_references_existing_docs`, `test_research_history_distinguishes_measured_from_unproven`, `test_no_production_claim_without_blind_labels`. Assert concrete linked local document paths exist and both `production_ready=false` and `office_labels=unverified` appear in current-status explanations.
- [ ] **Step 2: Verify RED** `PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_project_docs.py' -v`.
- [ ] **Step 3: Implement** status index/history and update the two existing README entry points. Include all verified CI run links, immutable dataset manifest locations, input formats, test commands and scoped metrics; mark missing raw office PCAP, trusted labels and unseen independent captures as unresolved.
- [ ] **Step 4: Verify GREEN** repeat Step 2, run documentation link verifier and the full unittest suite. Compare every claimed metric with the exact safe JSON report (otherwise mark historical or unavailable).
- [ ] **Step 5: Commit** only documentation and its link-check tests with `git commit -m 'docs: consolidate NDR generator history and current evidence'`.

## Handoff acceptance

- All tasks individually TDD-verified; full regression and at least one fresh end-to-end capture verified.
- Real metrics copied from exact report JSON with support counts and group IDs redacted from public output; no invented successes or unavailable production FPR.
- Side-by-side prior/new LOPO/LOTO AUC, AP, hard negative alert fractions and office unlabeled alert fractions; any loss of quality is reported.
- Document new independent data required before `production_ready` can change.
