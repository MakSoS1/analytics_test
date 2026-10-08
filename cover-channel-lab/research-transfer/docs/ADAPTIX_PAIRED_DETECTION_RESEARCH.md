# Adaptix vs matched isolated control: measured-feature detector

This is a **research diagnostic**, not a release-ready office intrusion
detector. It uses six paired captures (three isolated runtime profiles ×
TCP/mTLS), each with one bounded Adaptix scenario and one laboratory telemetry
control. No original PCAP, receipt content, fitted model or per-session score
is uploaded to public CI artifacts.

## Reproducible command

The `adaptix-research` job of
`.github/workflows/isolated-cover-adaptix-research.yml` runs after it has
verified and extracted the original 12 capture files:

```bash
cd cover-channel-lab/research-transfer
PYTHONPATH=code python -m natural_traffic.adaptix_detector_research \
  --extraction-root /tmp/adaptix-extract \
  --office-dir datasets/office-additional-days-20261008 \
  --out /tmp/adaptix-detector-report.json
```

The paths above are illustrative **paths to actual, newly extracted capture
tables**; the CI uses `$RUNNER_TEMP/adaptix-extract` and reports only aggregate
JSON under `$RUNNER_TEMP/safe-evidence/adaptix-detector-report.json`.

## Protocol

1. Each source capture (not each extracted flow) contributes one median
   measured transport-feature vector. A source producing many rows cannot
   inflate the apparent number of independent experiments.
2. Only predeclared numeric transport features are eligible; addresses,
   identity/provenance fields, ports, TLS identifiers, labels and source IDs
   are excluded from model X.
3. `leave_one_profile_out` tests on the entire withheld runtime profile;
   `leave_one_transport_out` separately withholds all TCP or mTLS pairs.
   Every pair remains together inside the train or test partition.
4. The classifier is regularized logistic regression. Within each training
   fold it selects at most three features based on sign-consistent paired
   scenario-minus-control differences, never using held-out features or labels
   for selection. Selection frequency and outer-held-out feature ablation
   effects are reported separately.
5. A provenance-only diagnostic using profile/transport is evaluated. Missing
   stable training signal yields a neutral 0.5-AUC report rather than an
   invented success or a green-research assertion.
6. The JSON includes fold-level and mean/worst ROC-AUC and average precision,
   feature names and support counts. Existing 22/28 September office Parquet
   is scored only after feature selection against the exploratory training-
   control 99th-percentile threshold; the report calls this an `alert_fraction`,
   never FPR. No threshold has been calibrated for a production alert budget;
   six pairs cannot establish a low false-alarm rate.

## Interpretation and nonclaims

The control is **not representative office background**; it is a local,
fixed telemetry task in a matched but limited network namespace. The model
therefore distinguishes `Adaptix-vs-isolated-paired-telemetry-control`, **not**
Adaptix-vs-all-benign-office traffic. Even a measured AUC of 1.0 with six
independent pairs is high-variance and insufficient for validation. The
observable effect may reflect bounded fixture/task differences or the
client stack, not an invariant technique mechanism.

To evaluate generalization credibly, obtain more independently verified
scenario/control executions across distinct client stacks, scenarios, server
implementations and observation points, reserve an untouched target-network
split, include application-matched hard negatives, and seek expert-reviewed
benign labels before estimating FPR. Office-day observations already released
are unlabeled and cannot establish specificity.

`technique_research_validated=false`, `office_naturalness_proven=false` and
`production_ready=false` intentionally remain unchanged regardless of the
research diagnostic AUC. The model is not exported for operational use.
