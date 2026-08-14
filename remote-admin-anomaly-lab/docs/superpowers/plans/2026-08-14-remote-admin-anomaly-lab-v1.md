# Remote Admin Anomaly Lab V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and validate an isolated GitHub Actions laboratory that produces recoverable Bronze PCAP, Silver Suricata/Zeek telemetry, Gold ML features/splits, and M0/M1/M2 baselines for remote-administration anomaly detection.

**Architecture:** Each GitHub-hosted Ubuntu shard creates a bridge plus Linux network namespaces, runs real SSH/Samba and best-effort RDP/VNC/DCE-RPC/WS-Man fixtures, captures the bridge with tcpdump, records orchestrator ground truth, then transforms the same capture into Suricata/Zeek telemetry and ML features. Large artifacts are retained as Actions artifacts and uploaded to Hugging Face when `HF_TOKEN` is available; PCAP is never a GitHub Release asset.

**Tech Stack:** Ubuntu 24.04, Bash, Linux network namespaces/veth/bridge, OpenSSH, Samba/smbclient, xrdp/FreeRDP where available, TigerVNC where available, rpcclient, Python 3.12, pandas, pyarrow, scikit-learn, LightGBM, tcpdump, Suricata, Zeek, zstd, GitHub Actions, Hugging Face Hub.

## Global Constraints

- Work only in branch `remote-admin-anomaly-lab-v1`.
- Lab endpoints must have no unrestricted default route to the Internet.
- Do not execute malware, C2 agents, credential dumping, persistence, unrestricted proxies, or external attack traffic.
- Ground truth must originate from the orchestrator, never from Suricata alerts.
- Bronze must retain complete PCAP plus manifests/checksums so Silver/Gold can be rebuilt.
- Do not publish PCAP as GitHub Release assets.
- `HF_TOKEN` must never be printed or committed.
- Main V1 production candidate is LightGBM; benign-only baseline is robust quantile/MAD plus Isolation Forest; TCN is deferred until the tabular pipeline is validated.

---

## File map

- `remote-admin-anomaly-lab/README.md` — user-facing lab overview and run instructions.
- `remote-admin-anomaly-lab/PLAN.md` — living checklist plus actual run results/storage paths.
- `remote-admin-anomaly-lab/requirements.txt` — Python runtime dependencies.
- `remote-admin-anomaly-lab/configs/topology.yaml` — host identities, roles and addresses.
- `remote-admin-anomaly-lab/configs/scenarios.yaml` — benign/suspicious scenario catalog.
- `remote-admin-anomaly-lab/configs/netem.yaml` — nuisance network profiles.
- `remote-admin-anomaly-lab/configs/feature_contract.yaml` — production-safe feature allowlist/denylist.
- `remote-admin-anomaly-lab/src/adminlab/config.py` — typed configuration loading/validation.
- `remote-admin-anomaly-lab/src/adminlab/manifest.py` — canonical session/campaign manifest writer.
- `remote-admin-anomaly-lab/src/adminlab/scenarios.py` — deterministic scenario planner and label-independent nuisance selection.
- `remote-admin-anomaly-lab/src/adminlab/features.py` — Silver-to-Gold feature extraction.
- `remote-admin-anomaly-lab/src/adminlab/splits.py` — campaign/pair/user/host/time grouped splits and leakage checks.
- `remote-admin-anomaly-lab/src/adminlab/models.py` — M1 LightGBM and M2 Isolation Forest training/evaluation.
- `remote-admin-anomaly-lab/src/adminlab/quality.py` — capture/parser/storage quality gates.
- `remote-admin-anomaly-lab/scripts/install_runner.sh` — install system/runtime dependencies.
- `remote-admin-anomaly-lab/scripts/setup_topology.sh` — create/remove bridge and namespaces safely.
- `remote-admin-anomaly-lab/scripts/start_services.sh` — start real protocol endpoints.
- `remote-admin-anomaly-lab/scripts/run_scenarios.py` — execute bounded real-wire scenarios and ground truth.
- `remote-admin-anomaly-lab/scripts/capture_shard.sh` — capture, package Bronze and invoke parsers.
- `remote-admin-anomaly-lab/scripts/build_silver.sh` — offline Suricata/Zeek processing.
- `remote-admin-anomaly-lab/scripts/build_gold.py` — normalize events and write features/splits.
- `remote-admin-anomaly-lab/scripts/train_eval.py` — train/evaluate M1/M2 and produce reports.
- `remote-admin-anomaly-lab/scripts/upload_hf.py` — upload shard tree without exposing credentials.
- `remote-admin-anomaly-lab/tests/` — unit/contract tests.
- `.github/workflows/remote-admin-smoke.yml` — push-triggered smoke validation.
- `.github/workflows/remote-admin-dataset.yml` — marker-triggered shard fan-out and persistence.
- `.github/workflows/remote-admin-train-eval.yml` — model/evaluation pipeline after Gold assembly.

---

### Task 1: Project skeleton, schemas and configuration contract

**Files:**
- Create: `remote-admin-anomaly-lab/requirements.txt`
- Create: `remote-admin-anomaly-lab/configs/topology.yaml`
- Create: `remote-admin-anomaly-lab/configs/scenarios.yaml`
- Create: `remote-admin-anomaly-lab/configs/netem.yaml`
- Create: `remote-admin-anomaly-lab/configs/feature_contract.yaml`
- Create: `remote-admin-anomaly-lab/src/adminlab/__init__.py`
- Create: `remote-admin-anomaly-lab/src/adminlab/config.py`
- Test: `remote-admin-anomaly-lab/tests/test_config.py`

**Interfaces:**
- Produces: `load_yaml(path: Path) -> dict`, `validate_topology(data: dict) -> None`, `validate_scenarios(data: dict) -> None`, `FORBIDDEN_FEATURE_COLUMNS: set[str]`.

- [ ] **Step 1: Write tests for unique host IDs/IPs, known roles/protocols and forbidden feature names.**
- [ ] **Step 2: Run `pytest -q tests/test_config.py` and confirm failure before implementation.**
- [ ] **Step 3: Implement loaders/validators and committed YAML configuration.**
- [ ] **Step 4: Run `pytest -q tests/test_config.py` and confirm pass.**
- [ ] **Step 5: Record result in `PLAN.md` and commit.**

### Task 2: Canonical ground-truth manifest and deterministic scenario planner

**Files:**
- Create: `remote-admin-anomaly-lab/src/adminlab/manifest.py`
- Create: `remote-admin-anomaly-lab/src/adminlab/scenarios.py`
- Test: `remote-admin-anomaly-lab/tests/test_manifest.py`
- Test: `remote-admin-anomaly-lab/tests/test_scenarios.py`

**Interfaces:**
- Produces: `SessionRecord` dataclass, `write_sessions(records, path)`, `plan_sessions(config, seed, count, stage) -> list[SessionRecord]`.
- Invariant: `label_binary` cannot be derived from source subnet, netem profile or clock hour alone.

- [ ] **Step 1: Write failing tests for required fields, unique IDs, deterministic same-seed planning and label/profile overlap.**
- [ ] **Step 2: Run focused tests and confirm failure.**
- [ ] **Step 3: Implement dataclass, planner and Parquet/JSONL writer.**
- [ ] **Step 4: Run focused tests and confirm pass.**
- [ ] **Step 5: Record scenario distributions in `PLAN.md` and commit.**

### Task 3: Safe isolated network topology

**Files:**
- Create: `remote-admin-anomaly-lab/scripts/setup_topology.sh`
- Test: `remote-admin-anomaly-lab/tests/test_topology_contract.py`

**Interfaces:**
- `setup_topology.sh up <topology.yaml>` creates bridge `br-adminlab`, namespaces and veths.
- `setup_topology.sh verify <topology.yaml>` fails if a simulated endpoint has a default route or if expected lab IPs/interfaces are missing.
- `setup_topology.sh down <topology.yaml>` removes created resources idempotently.

- [ ] **Step 1: Add static contract tests that require `set -euo pipefail`, explicit lab CIDR and a verify path checking `ip netns exec <ns> ip route show default` is empty.**
- [ ] **Step 2: Run tests and confirm failure.**
- [ ] **Step 3: Implement up/verify/down with cleanup trap support and no external forwarding/NAT.**
- [ ] **Step 4: Run contract tests locally/CI.**
- [ ] **Step 5: Record namespace count and isolation result in `PLAN.md`; commit.**

### Task 4: Real SSH and SMB services plus bounded scenario execution

**Files:**
- Create: `remote-admin-anomaly-lab/scripts/install_runner.sh`
- Create: `remote-admin-anomaly-lab/scripts/start_services.sh`
- Create: `remote-admin-anomaly-lab/scripts/run_scenarios.py`
- Test: `remote-admin-anomaly-lab/tests/test_runner_contract.py`

**Interfaces:**
- SSH server listens only on lab namespace address/port 22.
- Samba server listens only in lab namespace on TCP 445.
- `run_scenarios.py --stage <A-H> --count N --seed S --out DIR` executes only catalogued commands against lab IPs.
- Suspicious SMB transfer uses generated inert marker bytes; it never executes transferred files.

- [ ] **Step 1: Write contract tests that forbid public target hosts, shell interpolation from manifest values, unrestricted proxy commands and malware/C2 package names.**
- [ ] **Step 2: Run tests and confirm failure.**
- [ ] **Step 3: Implement package installation, per-namespace service configs and SSH/SMB scenario adapters.**
- [ ] **Step 4: Run a 20-session smoke in CI and assert TCP 22/445 evidence exists.**
- [ ] **Step 5: Record successful/failed sessions and protocol counts in `PLAN.md`; commit.**

### Task 5: Capture and immutable Bronze packaging

**Files:**
- Create: `remote-admin-anomaly-lab/scripts/capture_shard.sh`
- Create: `remote-admin-anomaly-lab/src/adminlab/quality.py`
- Test: `remote-admin-anomaly-lab/tests/test_bronze_contract.py`

**Interfaces:**
- `capture_shard.sh <stage> <shard> <count> <seed> <root>` writes `release/bronze/<shard>/captures/<shard>.pcap.zst` plus manifests/reproducibility/checksums.
- Bronze PCAP is never deleted after feature extraction.

- [ ] **Step 1: Write failing tests for required Bronze paths, SHA256 checksums and non-empty PCAP.**
- [ ] **Step 2: Run tests and confirm failure.**
- [ ] **Step 3: Implement tcpdump lifecycle, zstd compression, manifest copy and reproducibility metadata.**
- [ ] **Step 4: Run smoke capture and `tcpdump -nn -r`/`capinfos` validation.**
- [ ] **Step 5: Record PCAP packet/byte counts in `PLAN.md`; commit.**

### Task 6: Suricata/Zeek Silver pipeline

**Files:**
- Create: `remote-admin-anomaly-lab/scripts/build_silver.sh`
- Test: `remote-admin-anomaly-lab/tests/test_silver_contract.py`

**Interfaces:**
- Consumes Bronze PCAP.
- Writes `release/silver/<shard>/suricata/eve.json.zst`, Zeek logs, `parser_versions.json` and normalized metadata.

- [ ] **Step 1: Write failing tests for expected paths and non-empty parser output.**
- [ ] **Step 2: Run tests and confirm failure.**
- [ ] **Step 3: Implement offline Suricata and Zeek execution with explicit non-zero failure handling.**
- [ ] **Step 4: Parse smoke PCAP and assert `flow`/connection events plus SSH/SMB app evidence where available.**
- [ ] **Step 5: Record parser versions, event counts and protocol visibility in `PLAN.md`; commit.**

### Task 7: Extended protocol fidelity adapters

**Files:**
- Modify: `remote-admin-anomaly-lab/scripts/install_runner.sh`
- Modify: `remote-admin-anomaly-lab/scripts/start_services.sh`
- Modify: `remote-admin-anomaly-lab/scripts/run_scenarios.py`
- Create: `remote-admin-anomaly-lab/docs/FIDELITY_MATRIX.md`
- Test: `remote-admin-anomaly-lab/tests/test_fidelity_contract.py`

**Interfaces:**
- Protocol adapters report one of `available`, `unavailable`, `partial` with evidence.
- Required fidelity values include `real_rdp_linux`, `real_rfb`, `real_dcerpc_samba`, `partial_dcom`, `partial_winrm` when the fixture succeeds.

- [ ] **Step 1: Write tests requiring honest fidelity status and prohibiting a failed adapter from being labelled high fidelity.**
- [ ] **Step 2: Run tests and confirm failure.**
- [ ] **Step 3: Add best-effort xrdp/FreeRDP, VNC/RFB, rpcclient/DCE-RPC and bounded WS-Man fixtures.**
- [ ] **Step 4: Run smoke and record exactly which adapters are wire-real, partial or unavailable on `ubuntu-24.04`.**
- [ ] **Step 5: Update `FIDELITY_MATRIX.md` and `PLAN.md`; commit.**

### Task 8: Gold features, grouped splits and leakage audit

**Files:**
- Create: `remote-admin-anomaly-lab/src/adminlab/features.py`
- Create: `remote-admin-anomaly-lab/src/adminlab/splits.py`
- Create: `remote-admin-anomaly-lab/scripts/build_gold.py`
- Test: `remote-admin-anomaly-lab/tests/test_features.py`
- Test: `remote-admin-anomaly-lab/tests/test_splits.py`

**Interfaces:**
- `build_flow_features(...) -> DataFrame` emits only allowlisted production-safe columns plus labels kept separately for training.
- `assign_grouped_splits(...) -> DataFrame` keeps campaigns and pairs intact and enforces user/host/time holdouts.
- `audit_leakage(...) -> dict` fails on forbidden columns or group leakage.

- [ ] **Step 1: Write failing tests for forbidden-column rejection, campaign/pair integrity, held-out users and held-out host pairs.**
- [ ] **Step 2: Run tests and confirm failure.**
- [ ] **Step 3: Implement flow/window/novelty/graph aggregates and split assignment.**
- [ ] **Step 4: Build Gold from smoke Silver; assert Parquet outputs and leakage audit pass.**
- [ ] **Step 5: Record feature count/split sizes in `PLAN.md`; commit.**

### Task 9: HF persistence and recoverability

**Files:**
- Create: `remote-admin-anomaly-lab/scripts/upload_hf.py`
- Test: `remote-admin-anomaly-lab/tests/test_storage_contract.py`

**Interfaces:**
- `upload_hf.py --root RELEASE --repo Maksim123321/remote-admin-anomaly-v1 --path releases/<run>/<shard>` uploads the full shard tree when `HF_TOKEN` exists.
- If token is absent, exit code is zero only when Actions artifact retention path is explicitly reported; never print token contents.

- [ ] **Step 1: Write tests ensuring Bronze is included and no `releases/` GitHub publication path is used.**
- [ ] **Step 2: Run tests and confirm failure.**
- [ ] **Step 3: Implement Hugging Face upload via `huggingface_hub` using environment token only.**
- [ ] **Step 4: Add a non-secret credential probe and record `HF enabled/disabled` status.**
- [ ] **Step 5: Record final remote path or credential blocker in `PLAN.md`; commit.**

### Task 10: Push-triggered smoke workflow

**Files:**
- Create: `.github/workflows/remote-admin-smoke.yml`

**Interfaces:**
- Triggers on branch `remote-admin-anomaly-lab-v1` when lab/workflow files change.
- Runs tests, topology isolation, 20–100 real sessions, Bronze/Silver/Gold build and artifact retention.

- [ ] **Step 1: Add workflow with `timeout-minutes`, minimal permissions and concurrency guard.**
- [ ] **Step 2: Trigger via commit to branch.**
- [ ] **Step 3: Inspect all job logs and artifacts; fix failures rather than bypassing gates.**
- [ ] **Step 4: Require non-empty PCAP, Suricata EVE, Zeek conn log and Gold Parquet.**
- [ ] **Step 5: Record workflow run ID and artifact names in `PLAN.md`; commit.**

### Task 11: Dataset fan-out workflow and staged corpus

**Files:**
- Create: `.github/workflows/remote-admin-dataset.yml`
- Create: `remote-admin-anomaly-lab/.full-run-v1` only after smoke passes.

**Interfaces:**
- Push of `.full-run-v1` launches staged matrix shards.
- Matrix uses bounded `max-parallel` and stage/count inputs embedded in the matrix.
- Every shard uploads Actions artifact first, then HF when enabled.

- [ ] **Step 1: Define Stage B–H matrix with deterministic seeds and counts; start with a validation tranche before the full ~200k target.**
- [ ] **Step 2: Add per-shard quality gates and Actions artifact upload with 90-day retention.**
- [ ] **Step 3: After smoke PASS, commit `.full-run-v1` and inspect shard outcomes.**
- [ ] **Step 4: Fix any systematic protocol/parser failure and re-run failed jobs only.**
- [ ] **Step 5: Record completed shards, session counts, Bronze/Silver/Gold sizes and HF paths in `PLAN.md`.**

### Task 12: M0/M1/M2 training and challenge evaluation

**Files:**
- Create: `remote-admin-anomaly-lab/src/adminlab/models.py`
- Create: `remote-admin-anomaly-lab/scripts/train_eval.py`
- Create: `.github/workflows/remote-admin-train-eval.yml`
- Test: `remote-admin-anomaly-lab/tests/test_models.py`

**Interfaces:**
- M1: LightGBM calibrated binary classifier.
- M2: robust quantile/MAD score plus Isolation Forest trained on benign train rows only.
- Reports separate validation, test and challenge.

- [ ] **Step 1: Write tests that M2 never fits attack rows and that challenge metrics are emitted separately.**
- [ ] **Step 2: Run tests and confirm failure.**
- [ ] **Step 3: Implement model training, probability calibration, threshold selection on validation only and campaign bootstrap intervals.**
- [ ] **Step 4: Run train/eval on assembled Gold corpus and retain model/report artifacts.**
- [ ] **Step 5: Record PR-AUC, Recall, Precision, FPR, hard-benign FPR and hard-suspicious/unseen holdout recall in `PLAN.md`; commit.**

### Task 13: Final documentation and production integration contract

**Files:**
- Create: `remote-admin-anomaly-lab/README.md`
- Create: `remote-admin-anomaly-lab/docs/NGFW_INTEGRATION.md`
- Update: `remote-admin-anomaly-lab/PLAN.md`

**Interfaces:**
- Documents Suricata deterministic layer + EVE ML sidecar + alert-only V1 decision flow.
- Documents exact Bronze/Silver/Gold HF and Actions artifact locations.

- [ ] **Step 1: Document reproducible commands and workflow names.**
- [ ] **Step 2: Document fidelity limits and explicitly defer Sliver/C2 challenge work.**
- [ ] **Step 3: Document exact storage/rebuild path from Bronze to Gold.**
- [ ] **Step 4: Run final test/quality suite and compare branch against main.**
- [ ] **Step 5: Mark only evidence-backed items complete in `PLAN.md` and publish final result summary.**

## Self-review checklist

- [x] Every design requirement maps to a task.
- [x] Bronze persistence is implemented before ML.
- [x] Ground truth is independent from Suricata.
- [x] Hard benign, hard suspicious, counterfactual and challenge stages exist.
- [x] Cross-repository secret extraction is not attempted.
- [x] No task requires malware/C2 or public attack targets.
- [x] Model evaluation separates ordinary test from challenge.
- [x] No PCAP publication through GitHub Releases exists in the plan.
