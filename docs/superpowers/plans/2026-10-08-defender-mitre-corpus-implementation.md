# Defender MITRE Corpus and Office Transfer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Построить расширяемый защитный конвейер из неизменяемых PCAP/измеренных таблиц, подтверждённых MITRE-сценариев и парных контролей в честную исследовательскую модель NDR с отдельной оценкой офисного переноса.

**Architecture:** `source_manifest` удостоверяет входы и доказательства, `verified_corpus` извлекает исходные измеренные признаки и отделяет метки от model-X, `corpus_splits` удерживает связанные кампании вместе. `technique_training` обучает на проверенных парах, а `technique_transfer_evaluation` независимо измеряет технику, утечки и доли тревог на неизменённых офисных днях. Существующие `defender_domain`, `office_workload` и `office_injection.research_training` остаются рабочими; выпуск новой модели не снимает их прежние safety/naturalness gates.

**Tech Stack:** Python 3.12, `unittest`, pandas/Parquet, NumPy, scikit-learn, существующий production PCAP extractor, GitHub Actions; версии, проверенные в проекте: numpy 2.5.2, pandas 3.0.5, pyarrow 25.0.1, scikit-learn 1.9.0, scipy 1.18.1.

**Spec:** `docs/superpowers/specs/2026-10-08-defender-domain-corpus-design.md`

## Global Constraints

- Оригинальные PCAP, timestamps и payload никогда не переписывать, ретаймить или маскировать; до/после извлечения проверять SHA-256.
- Допускать измеренные classic Ethernet `.pcap`, `.parquet`, `.csv`, `.tsv`, `.jsonl`; `.pcapng` и сырые Zeek/Suricata EVE без отдельного проверенного экстрактора отвергать.
- Числовые таблицы требуют **≥12** распознаваемых измеренных transport features с **≥80%** конечных значений на колонку; не восстанавливать несуществующие TLS признаки нулями.
- `label_state`: `verified_positive`, `matched_control`, `hard_negative`, `unlabeled_office`, `unverified_external`. Офисные наблюдения остаются `label=-1`.
- Источник и информация о кампании, MITRE ID, capture day, client/profile, group и происхождении не попадают в model-X; подтверждение техники требует свидетельств членства конкретных сессий.
- Train/validation/test разъединять по связанным `parent_campaign_id`, `capture_group_id`, `runtime_profile_id`; сегменты одного PCAP и `pair_id` всегда остаются вместе.
- Не использовать финальный офисный holdout для выбора модели/признаков/порога. Без размеченной целевой проверки `production_ready=false`.
- Различать `pipeline_verified`, `technique_research_validated`, `office_transfer_diagnostic` и `production_ready`; office alert fraction не именовать FPR.
- Сохранять исходную `naturalness_status=not_passed` и отклоняющий release gate, пока отсутствуют независимые данные для подтверждения packet-level naturalness.
- Не расширять данный конвейер до универсального изменения/камуфляжа произвольного MITRE attack PCAP или выполнения сценариев из недоверенного манифеста.

## Review Focus

1. Manifest path выходит за разрешённый source root через `../` или symlink: валидатор отвергает путь до чтения — Task 1.
2. Один PCAP содержит фон и только одну подтверждённую позитивную сессию: никакие остальные строки не становятся позитивными без session membership — Task 2.
3. Разные `pair_id`, но один `parent_campaign_id` или `runtime_profile_id`: связанные записи никогда не расходятся между train и holdout — Task 3.
4. Таблицы 22 сентября не имеют TLS, а столбец 28 сентября имеет: feature contract не восстанавливает TLS и явно сообщает `unavailable` — Task 4.
5. Одна MITRE-техника представлена одним профилем или только позитивным классом: research gate отказывает и не печатает бессмысленный ROC-AUC — Task 6.

---

## File Structure

- `cover-channel-lab/research-transfer/code/natural_traffic/source_manifest.py`: версия JSON-контракта, относительные пути, checksum, evidence и pair validation.
- `cover-channel-lab/research-transfer/code/natural_traffic/verified_corpus.py`: существующая immutable загрузка, per-row session membership, сохранение `features.parquet` и `labels_metadata.parquet` отдельно.
- `cover-channel-lab/research-transfer/code/natural_traffic/corpus_splits.py`: граф связанных групп и сохранённая карта train/validation/test.
- `cover-channel-lab/research-transfer/code/natural_traffic/office_reference.py`: frozen совместимость с офисными 22/23/28 сентября и проверка SHA/schema.
- `cover-channel-lab/research-transfer/code/office_injection/technique_training.py`: train-only обучение, pair/group weights, threshold на validation и сравнение с research baseline.
- `cover-channel-lab/research-transfer/code/natural_traffic/technique_transfer_evaluation.py`: независимые per-technique test metrics, shortcut controls, office alert fractions, отдельные release statuses.
- `cover-channel-lab/research-transfer/code/natural_traffic/workload_adapters.py`: registry только разрешённых локальных легитимных task receipts; существующий `office_workload` — первая работающая реализация.
- `cover-channel-lab/research-transfer/code/natural_traffic/defender_corpus_cli.py`: orchestration `prepare`/`train`/`evaluate`/`report`; без запуска команд из входного JSON.
- Tests: `code/tests/test_natural_source_manifest.py`, `test_natural_verified_corpus.py`, `test_natural_corpus_splits.py`, `test_natural_office_reference.py`, `test_natural_technique_training.py`, `test_natural_technique_transfer_evaluation.py`, `test_natural_workload_adapters.py`, `test_natural_defender_corpus_cli.py`.
- Docs/CI: `docs/DEFENDER_MITRE_CORPUS.md`, `.github/workflows/natural-traffic-tdd.yml`; сохранить существующие smoke stages и запускать новые тесты вместе с полным регрессом.

## Task 1: Версионированный источник и evidence contract

**Files:** Create `code/natural_traffic/source_manifest.py`; Test `code/tests/test_natural_source_manifest.py` (оба пути относительно `cover-channel-lab/research-transfer/`).

**Interfaces:**
- Produces: `load_source_manifest(path: Path, *, allowed_root: Path) -> dict` (strict JSON v1, canonicalized source entries); `verify_sources(manifest: dict) -> None` (checksum before loading).
- `sources[]`: `source_id`, `relative_path`, `sha256`, `label_state`, `technique_ids: list[str]`, `pair_id`, `parent_campaign_id`, `runtime_profile_id`, `capture_group_id`, `capture_day_id`, `measurement_vantage`, `extractor_version`, `evidence_tier`, optional `membership_relative_path`, `membership_sha256`, `receipt_relative_path`, `receipt_sha256`. All paths confined to `allowed_root` after resolution; never run specified code.
- `evidence_tier` enum `fixture_only` / `operator_attested` / `independently_verified`; only the last tier **can be considered for** research validation. Positive sources require pinned receipt and per-session membership; the validator checks integrity, not truth of third-party statements.
- MITRE pattern `T[0-9]{4}(\.[0-9]{3})?`, nonempty only for verified positives and their matched controls; `pair_id` connects compatible positive/control sources with same declared extractor and vantage. `hard_negative` has independent confirmed `label=0`, office/external unknown.

- [ ] **Step 1: Write failing tests** for valid two-technique v1 manifest, unknown label/version, malformed IDs, tampered SHA, missing positive membership, unmatched pair, root-escape traversal and symlink, wrong-format `.pcapng`/raw EVE.

```python
with self.assertRaisesRegex(ValueError, "outside source root"):
    load_source_manifest(escape_manifest, allowed_root=fixtures_root)
with self.assertRaisesRegex(ValueError, "membership"):
    load_source_manifest(positive_without_membership, allowed_root=fixtures_root)
```

- [ ] **Step 2: Verify RED:** `PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_source_manifest.py' -v` from `cover-channel-lab/research-transfer/`; expected import missing.
- [ ] **Step 3: Implement** strict immutable manifest parse, path containment and SHA; make positive/controls evidence constraints explicit and error messages deterministic.
- [ ] **Step 4: Verify GREEN:** same command; expected all tests pass.
- [ ] **Step 5: Commit** only this module and its tests: `feat: validate immutable MITRE source manifests`.

## Task 2: Корпус с точной меткой конкретной сессии

**Files:** Create `code/natural_traffic/verified_corpus.py`; Test `code/tests/test_natural_verified_corpus.py`; reuse `natural_traffic.defender_domain.load_user_input` unchanged when possible.

**Interfaces:**
- Consumes `load_source_manifest`, `load_user_input(path, work)`; session membership JSONL entries `{source_id, session_key, label_binary, technique_id}` keyed to a measured stable identity (`global_session_uid` or a documented extractor-equivalent). Unmatched sessions remain `-1` and never enter supervised training.
- Produces `build_verified_corpus(manifest_path: Path, allowed_root: Path, out: Path, *, min_free_gib: float = 1) -> dict` writing `features.parquet` (measured X), `labels_metadata.parquet` (labels, evidence tier, pair/group/provenance), `corpus_manifest.json` (source and output hashes). Existing output is rejected, intermediate raw extractors cleaned.

- [ ] **Step 1: Write failing tests** for: two verified MITRE IDs, one positive among background sessions, unverified input never promoted to label 1, source digest unchanged, changed receipt/membership rejected, two files with same source ID rejected, and no group IDs smuggled into X.

```python
report = build_verified_corpus(manifest, root, out)
meta = pd.read_parquet(out / "labels_metadata.parquet")
assert meta.loc[meta.session_key.eq("target"), "label_binary"].tolist() == [1]
assert meta.loc[meta.session_key.eq("background"), "label_binary"].tolist() == [-1]
assert "capture_group_id" not in pd.read_parquet(out / "features.parquet")
```

- [ ] **Step 2: Verify RED:** `PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_verified_corpus.py' -v`.
- [ ] **Step 3: Implement** one measured-extraction pass per source, immutable identity map, `≥12` transport feature gate, single X schema and pair/evidence metadata sidecar; treat missing stable session keys as ineligible, never infer membership from `source_id`.
- [ ] **Step 4: Verify GREEN:** same command and existing `test_natural_defender_domain` unchanged.
- [ ] **Step 5: Commit:** `feat: assemble measured MITRE corpus with session-grounded labels`.

## Task 3: Не пересекающиеся независимые группы

**Files:** Create `code/natural_traffic/corpus_splits.py`; Test `code/tests/test_natural_corpus_splits.py`.

**Interfaces:**
- Consumes metadata from Task 2.
- Produces `assign_connected_splits(metadata: pd.DataFrame, *, seed: int = 20261008) -> pd.Series`: deterministic train/validation/test; connected components formed by same nonempty `parent_campaign_id`, `capture_group_id`, `runtime_profile_id`, `pair_id`, physical source hash and session parent. No row of one component crosses splits.
- Produces `assert_split_independence(metadata: pd.DataFrame, splits: pd.Series) -> None` for reload verification.

- [ ] **Step 1: Write failing tests** for pair siblings, same physical source split into segments, cross-campaign same runtime profile, permutation stability, frozen repeatability, missing independence fields and too few components.

```python
splits = assign_connected_splits(rows, seed=7)
assert splits.iloc[0] == splits.iloc[1]  # shared parent_campaign_id
assert splits.iloc[1] == splits.iloc[2]  # transitively shared runtime_profile_id
assert_split_independence(rows, splits)
```

- [ ] **Step 2: Verify RED:** `PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_corpus_splits.py' -v`.
- [ ] **Step 3: Implement** union-find connected-component assignment, `≥10` independent components and explicit support/cross-class checks delegated to Task 5; record component hashes/split policy.
- [ ] **Step 4: Verify GREEN:** same command, plus existing `test_office_injection_dataset` regression.
- [ ] **Step 5: Commit:** `feat: keep MITRE campaign and profile siblings out of holdouts`.

## Task 4: Замороженный измерительный контракт офиса

**Files:** Create `code/natural_traffic/office_reference.py`; Test `code/tests/test_natural_office_reference.py`; reuse `natural_traffic.office_day_transfer.load_additional_days`, `TRANSPORT_FEATURES` and `defender_domain.shared_transport_columns`.

**Interfaces:**
- Produces `load_office_reference(additional_days_dir: Path, office_cover_dir: Path | None = None) -> dict[str, pd.DataFrame]`: SHA-verified 22/28 Sep, and hash/schema-validated 23 Sep as a separate optional diagnostic reference; never silently merge day populations.
- Produces `freeze_feature_contract(corpus_X: pd.DataFrame, days: dict[str, pd.DataFrame]) -> dict` with ordered common measured transport features, unavailable family reasons and train-only validity; return a `feature_schema_sha256` to pin later stages.

- [ ] **Step 1: Write failing tests** for tampered September manifest/table, unknown office labels, 22 Sep absent TLS, feature identity exclusion, 23 Sep incompatible schema separately reported, less than 12 comparable observed columns.

```python
contract = freeze_feature_contract(corpus_X, {"2026-09-22": day22, "2026-09-28": day28})
assert "tls_version" not in contract["feature_columns"]
assert "capture_day_id" not in contract["feature_columns"]
assert contract["unavailable_families"]["tls"] == "unmeasured_on_2026-09-22"
```

- [ ] **Step 2: Verify RED:** `PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_office_reference.py' -v`.
- [ ] **Step 3: Implement** office-date loading, checksum verification and deterministic feature contract without fit-on-holdout selection; no restoration of missing TLS and no office benign assumption.
- [ ] **Step 4: Verify GREEN:** same command and `test_natural_additional_days` regression with actual checked-in office samples.
- [ ] **Step 5: Commit:** `feat: pin measured office feature contract across dates`.

## Task 5: Train-only MITRE модель и контрольная baseline

**Files:** Create `code/office_injection/technique_training.py`; Test `code/tests/test_natural_technique_training.py`; Modify `code/office_injection/research_training.py` only to expose its existing baseline through an additive documented adapter if necessary.

**Interfaces:**
- Consumes verified `features.parquet`, `labels_metadata.parquet`, group splits, frozen `feature_columns` from Tasks 2–4.
- Produces `train_technique_models(prepared_dir: Path, splits: pd.Series, feature_contract: dict, out: Path, *, seed: int = 20261008, control_alert_budget: float = .01) -> dict`; per-technique one-vs-matched-control model; fixed frozen feature set (no supervised selection in v1), imputer/scaler fit only on training groups, group-balanced samples, validation-only threshold; saved `joblib` with feature order/checksums. Separately trains a provenance-only diagnostic and shuffled-label negative control **on training groups only**, saved for Task 6.
- `fixture_only` / `operator_attested` may exercise the pipeline but do not qualify model for `technique_research_validated`.

- [ ] **Step 1: Write failing tests** for two independently verified technique IDs with independent groups, missing one class in any fold, label source/profile shortcut, oversized group weights, shuffled train labels, early attempt to access office holdout, and unchanged validation threshold under test-label perturbation.

```python
result = train_technique_models(prepared, splits, contract, out, seed=11)
assert set(result["techniques"]) == {"T1001", "T1071.001"}
assert result["threshold_fit"] == "validation_controls_only"
assert result["office_holdout_used_for_model_selection"] is False
```

- [ ] **Step 2: Verify RED:** `PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_technique_training.py' -v`.
- [ ] **Step 3: Implement** deterministic `HistGradientBoostingClassifier` pipeline, reusing `fit_research` group-weighting policy without calling its 89-column-only schema validator; fail closed on unsupported classes/groups. Save frozen unweighted baseline and diagnostic controls, compare them without auto-picking by final holdout.
- [ ] **Step 4: Verify GREEN:** same command and `test_office_injection_dataset` regression; assert artifacts `production_ready=false`.
- [ ] **Step 5: Commit:** `feat: train group-held-out defender technique models`.

## Task 6: Независимая оценка техники, shortcuts и офиса

**Files:** Create `code/natural_traffic/technique_transfer_evaluation.py`; Test `code/tests/test_natural_technique_transfer_evaluation.py`.

**Interfaces:**
- Consumes fitted models/validation thresholds, test-only verified rows, frozen feature contract, SHA-verified office days. Does not retrain or tune.
- Produces `evaluate_technique_transfer(prepared_dir: Path, model_dir: Path, office_days: dict[str, pd.DataFrame], out: Path) -> dict` containing per-technique ROC-AUC/PR-AUC/recall where defined, independent group counts, provenance-only/shuffled-label controls **precomputed on training groups in Task 5**, 22/28/optional 23 Sep office alert **fractions**, model/source origins and explicit reasoned gates.
- Report has independent `pipeline_verified`, `technique_research_validated`, `office_transfer_diagnostic`, `production_ready=false`, `office_naturalness_proven=false`.

- [ ] **Step 1: Write failing tests** for a synthetic strong true feature effect; origin-only correlated labels; shuffled labels; a single class/group; missing TLS; mutated model/report hash; no metric named office `false_positive_rate`; frozen office holdout untouched.

```python
report = evaluate_technique_transfer(prepared, models, office, output)
assert report["production_ready"] is False
assert "office_alert_fraction" in report["office_days"]["2026-09-28"]
assert "false_positive_rate" not in str(report)
assert report["per_technique"]["T1001"]["independent_test_groups"] >= 2
```

- [ ] **Step 2: Verify RED:** `PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_technique_transfer_evaluation.py' -v`.
- [ ] **Step 3: Implement** fixed test evaluation and diagnostics; origin-only and shuffled-label controls are negative **reports**, not optimizers; failure or insufficient support must remain explicit, not replaced with perfect metrics.
- [ ] **Step 4: Verify GREEN:** same command, check synthetic origin-only fixture sets `technique_research_validated=false`.
- [ ] **Step 5: Commit:** `feat: independently audit MITRE detection and office transfer`.

## Task 7: Легитимные workload adapters и receipts

**Files:** Create `code/natural_traffic/workload_adapters.py`; Test `code/tests/test_natural_workload_adapters.py`; minimal additive integration with `code/natural_traffic/office_workload.py` if required.

**Interfaces:**
- Produces `register_benign_adapter(name: str, runner: Callable[..., dict]) -> None` and `run_benign_adapter(name: str, out: Path, *, sessions: int, seed: int) -> dict` with allowlisted built-ins; no manifest-provided import/shell entrypoints.
- The first built-in wraps `run_benign_office_workload`; exposes semantically verified document read/edit, file upload/download (local sync analogue), message and HTTPS navigation receipts. Browser-specific automation is a separately capability-gated plug-in, never implied by plain `HTTPSConnection`.

- [ ] **Step 1: Write failing tests** for known fixture adapter receipts, unknown adapter rejection, malicious dotted-name/shell string rejection, no overwriting existing path and no claim of a real browser from stdlib HTTPS.

```python
receipt = run_benign_adapter("verified_local_https", out, sessions=2, seed=12)
assert receipt["tasks_completed"] == 8
assert receipt["client_stack"] == "python_stdlib_https"
assert receipt["production_ready"] is False
```

- [ ] **Step 2: Verify RED:** `PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_workload_adapters.py' -v`.
- [ ] **Step 3: Implement** local-only adapter registry with strict capability receipt; keep original fixture, isolation, hash, TLS verification and no production-naturalness claim.
- [ ] **Step 4: Verify GREEN:** same command and `test_natural_office_workload` regression.
- [ ] **Step 5: Commit:** `feat: register safe benign application workload adapters`.

## Task 8: Единый CLI, документация и CI end-to-end

**Files:** Create `code/natural_traffic/defender_corpus_cli.py`; Test `code/tests/test_natural_defender_corpus_cli.py`; Create `docs/DEFENDER_MITRE_CORPUS.md`; Modify `.github/workflows/natural-traffic-tdd.yml` and `README.md` additively.

**Interfaces:**
- `python -m natural_traffic.defender_corpus_cli prepare --manifest <json> --source-root <dir> --out <dir>`; `train --prepared <dir> --office-dir <dir> --out <dir>`; `evaluate --prepared <dir> --models <dir> --office-dir <dir> --out <dir>`; `report --evaluation <dir>` prints aggregate non-sensitive JSON.
- Write example `manifest.json` with *fixture-only* sample IDs `T1001` and `T1071.001`, capabilities/unsupported formats, provenance/ground-truth requirements and status semantics; no repo raw PCAP artifacts or credentials.

- [ ] **Step 1: Write failing CLI tests** for 2 synthetic MITRE scenarios/controls with pinned memberships, malformed manifest, SHA mismatch, format refusal, CLI output paths and separation of production/research gates. Keep real-office fixture smoke aggregate-only.

```python
assert result.returncode == 0
assert (out / "corpus_manifest.json").exists()
assert json.loads(report.read_text())["production_ready"] is False
```

- [ ] **Step 2: Verify RED:** `PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_defender_corpus_cli.py' -v`.
- [ ] **Step 3: Implement** additive subcommands and versioned JSON outputs; link to existing `defender_domain` CLI without changing it. Document full concrete commands, limitations, evidence tiers and release statuses.
- [ ] **Step 4: Verify GREEN:** run from `cover-channel-lab/research-transfer/`: `PYTHONPATH=code python -m unittest discover -s code/tests -p 'test_natural_*.py' -v`; expected PASS with existing documented skips, no altered scientific gate.
- [ ] **Step 5: Verify whole regression:** `PYTHONPATH=code python -m unittest discover -s code/tests -v`; expected PASS or documented environment-only skips; CI Linux TLS capture must still show 3 wire handshakes / 3 extracted sessions.
- [ ] **Step 6: Verify Actions:** new PR run of `natural-traffic-tdd.yml` including provenance-negative tests and read-only real office 22/28 smoke; inspect failures instead of adjusting naturalness cutoffs.
- [ ] **Step 7: Commit:** `feat: expose defender MITRE corpus CLI and regression checks`.

## Post-implementation decision gates

1. `pipeline_verified` may pass using pinned synthetic semantic fixtures and byte-integrity checks.
2. `technique_research_validated` may pass only for genuine independently verified, sufficiently diverse and held-out technique scenarios, not solely fixture-only labels.
3. `office_transfer_diagnostic` reports observed day-level fractions and schema limitations, not production recall/FPR.
4. `production_ready` remains `false` until separately obtained verified target-network labels, blind unseen office day and comparable measurement vantage. Historical source-origin C2ST `~0.9997–1.0` remains a recorded unresolved failure, not something this training workflow declares fixed.

Do not mark the PR ready for merge only because CI succeeds. Run `superpowers:verification-before-completion` before claiming a task or branch complete, and `superpowers:requesting-code-review` after the final regression and before handoff.
