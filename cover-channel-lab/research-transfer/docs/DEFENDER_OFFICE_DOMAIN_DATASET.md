# Domain-aware NDR dataset preparation (immutable PCAP)

The purpose of this standalone defensive pipeline is to make an **ML model**
usable across a lab-source/office-source distribution shift, not to make
packets evade a network detector. Uploaded traffic is never rewritten,
retimed, encrypted differently, blended into PCAP or presented as office
traffic. The original input checksum is recorded and checked again.

## Input and outputs

Input: classic Ethernet `.pcap` captured from an authorized environment,
or the production feature `.parquet`. PCAP uses the existing production
office_sessions extractor; no second packet parser is introduced.

Office: two approved, pseudonymized, hash-verified Parquet reference days:
22 and 28 September 2026. On these releases the labels are **unverified**,
and therefore remain `-1`. No benign ground truth is invented.

Output: `train_candidates.parquet`, `office_holdout.parquet`,
`user_input.parquet`, `manifest.json`; optionally
`baseline_report.json`.

All tables preserve measured numerical feature values and retain separate
`domain`, `group_id`, `label`, `label_policy`, and `capture_day`
metadata. None of these metadata columns enters the model feature matrix.
The verified-input label (`0` for explicitly verified benign, `1` for
explicitly verified malicious) only applies to the uploaded source.
Office labels stay unknown.

## Usage

From `cover-channel-lab/research-transfer`:

```bash
export PYTHONPATH=code
python -m pip install pandas pyarrow numpy scipy scikit-learn scapy

python -m natural_traffic.defender_domain prepare \
  --input /secure/path/capture.pcap \
  --office-dir datasets/office-additional-days-20261008 \
  --source-label unlabeled \
  --out /secure/output/ndrdomain-001

python -m natural_traffic.defender_domain baseline \
  --prepared /secure/output/ndrdomain-001 \
  --alert-budget 0.01
```

For a labeled source use `--source-label verified_malicious` **only if its
label was actually independently verified**. `--source-label verified_benign`
likewise requires genuine benign verification. You may also supply a
compatible Parquet feature file instead of PCAP. The output directory must
not exist, preventing accidental overwrite of an earlier run.

The baseline is a scikit-learn IsolationForest anomaly detector trained
**only on the earlier office training day** with a train-only imputation,
scaling and alert threshold. The later office day is never used to fit
a model, choose features by scores, calibrate a threshold or transform
uploaded traffic. This is a **diagnostic** of shifts in alert rates, not
a verified FPR: the office reference labels are unknown and their traffic
may include attacks. A single uploaded capture cannot validate attack recall.

## Guardrails

- No copying real office data to client hosts, no PCAP editing, NAT/IP/port
  relabeling, protocol spoofing, timing shaping or C2-camouflage logic.
- Unknown reference content is never relabeled benign.
- Training and holdout reference groups must be disjoint. User source gets
  a separate origin namespace; repeated segments within the same source
  session get the same group ID.
- Only a predeclared list of common observed numeric transport features is
  used; no origin, identities, HMAC, ports, TLS unobserved on 22 September,
  date, user metadata or label enters model input.
- Fail closed if too few fields or groups are comparable. Data is
  not repaired to obtain a favorable AUC.
- Input and output hashes, extractor choice, label policy, group counts and
  source-specific caveats are retained in the manifest.
- Derived output can still be sensitive. Store privately; no automatic
  upload of raw PCAP, original strings or record-level tables to Actions.
- Office day 28 has already been inspected; it is a regression holdout, **not
  a truly pristine final evaluation set**. Collect a new held-out day
  before claiming deployment readiness.

## Research rationale

Cross-domain IDS performance frequently degrades when the collection
environment changes. In a 2023 evaluation across four common datasets,
the same source-to-target swap affected generalization substantially;
TAN-IDS evaluates a common NetFlow feature interface and compares direct
transfer, mixed-domain training and limited target-domain fine tuning.

- Explainable Cross-domain Evaluation of ML-based Network Intrusion Detection
  Systems, *Computers & Electrical Engineering*, 2023:
  https://doi.org/10.1016/j.compeleceng.2023.108692
- TAN-IDS, *PLOS ONE*, 2026:
  https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0346801
- DI-NIDS, *Knowledge-Based Systems*, 2023:
  https://www.sciencedirect.com/science/article/pii/S0950705123003763

**Status:** this makes the analysis and training-data interfaces usable,
not the PCAP indistinguishable from office traffic. An actual supervised
classifier requires independently verified source **and target** labels
and an independent target-domain test. `production_ready=false` until then.
