# Corrected V3 deployment on an NGFW / Suricata sensor

The production unit of corrected V3 is a **Suricata EVE flow**, not a synthetic orchestrator session. The deployment sidecar therefore needs only:

- Suricata `eve.json` with `flow` events;
- `M1-lightgbm.joblib` and `M1-lightgbm.metrics.json` from the verified V3 release;
- the repository's `score_eve_sidecar.py` and `adminlab.online_features.EveFeatureState` implementation;
- writable persistent state storage.

It does not require Zeek, `session_id`, campaign IDs, personas, ground-truth labels, EDR telemetry or raw PCAP at inference time.

## 1. Install

From the `remote-admin-anomaly-lab` repository directory, with the verified release extracted locally:

```bash
sudo bash deploy/ngfw/install_v3.sh /path/to/extracted/release
```

The installer fails closed unless the release contains:

```text
gold/V3-1k/models/M1-lightgbm.joblib
gold/V3-1k/models/M1-lightgbm.metrics.json
```

It installs the Python package in the exact layout expected by the sidecar:

```text
/opt/remote-admin-v3/
├── src/
│   └── adminlab/
├── scripts/
│   └── score_eve_sidecar.py
├── models/
│   ├── M1-lightgbm.joblib
│   └── M1-lightgbm.metrics.json
└── venv/
```

Before installing the systemd unit, the installer loads the serialized model, creates a synthetic EVE `flow` through `EveFeatureState`, and verifies that every `model.feature_names_in_` column is produced by the runtime extractor.

## 2. Suricata requirement

Suricata must emit `flow` records to `/var/log/suricata/eve.json`. The sidecar ignores non-flow records and, for its rolling baseline, consumes only the remote-administration candidate stream (SSH, SMB, RDP, VNC and WinRM endpoints/parser protocols).

Unrelated DNS/HTTP/TLS flows do not change this detector's `connections_*`, pair, protocol or graph state. This is identical to the stream used to build production Gold.

## 3. Bootstrap the baseline

Before enabling live alerting for a new sensor, initialize state from retained EVE history if available:

```bash
sudo -u remoteadminml \
  /opt/remote-admin-v3/venv/bin/python \
  /opt/remote-admin-v3/scripts/score_eve_sidecar.py \
  --model /opt/remote-admin-v3/models/M1-lightgbm.joblib \
  --metrics /opt/remote-admin-v3/models/M1-lightgbm.metrics.json \
  --eve /var/log/suricata/eve.json \
  --state-file /var/lib/remote-admin-v3/state.json \
  --checkpoint-every 100 >/dev/null
```

The state contains raw network identities only as operational state keys. Raw IPs are never model features. Protect `/var/lib/remote-admin-v3/state.json` as network telemetry.

If there is no historical EVE file, the model can start cold, but novelty features will be elevated until the baseline matures. Treat cold-start scores as enrichment rather than enforcement.

## 4. Start live scoring

```bash
sudo systemctl enable --now remote-admin-v3.service
sudo systemctl status remote-admin-v3.service --no-pager
sudo tail -F /var/log/remote-admin-v3/alerts.jsonl
```

The service:

- follows live Suricata EVE;
- scores completed remote-admin candidate flows;
- calculates every feature before inserting the current flow into history;
- loads `/var/lib/remote-admin-v3/state.json` after a restart;
- atomically checkpoints state during operation and on clean EOF/shutdown;
- writes `remote_admin_ml` JSON alerts/enrichment events.

## 5. Response mode

Do not turn a research score directly into an inline `drop` rule merely because deployment is technically possible. Promotion to blocking must additionally pass the corrected V3 low-FPR challenge, hard-benign, shortcut and target-environment gates.

Recommended first deployment:

```text
Suricata EVE flow
       ↓
remote-admin candidate filter
       ↓
EveFeatureState (persistent prior-only state)
       ↓
M1 LightGBM flow-primary
       ↓
remote_admin_ml JSON
       ↓
SIEM / NDR correlation
```

The deterministic Suricata rules remain an independent visibility/policy layer; they do not supply labels to the ML model.
