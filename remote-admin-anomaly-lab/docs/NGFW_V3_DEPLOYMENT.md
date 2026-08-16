# Remote Admin Anomaly V3 — Direct NGFW Deployment

## Production contract

The corrected V3 production model scores one completed Suricata EVE `flow` event at a time. It does **not** require orchestrator session boundaries, scenario IDs, personas, usernames, EDR telemetry, Zeek logs or raw IP values as model features.

Production inputs:

1. Suricata EVE `flow` records.
2. Only the remote-admin candidate stream: SSH/22, SMB/445, RDP/3389, VNC/5900, WinRM/5985/5986 and parser-recognized equivalents.
3. Prior-only rolling state maintained by `adminlab.online_features.EveFeatureState`.
4. The generated `M1-lightgbm.joblib` and `M1-lightgbm.metrics.json` files.

Raw source/destination IPs are used only as keys inside the rolling state. They are never passed to LightGBM.

## Why the production unit is a flow

The old session-primary V3 depended on synthetic orchestrator session boundaries that an NGFW does not know. Corrected V3 promotes `flow-primary` instead. The same `EveFeatureState` class is used by offline Gold extraction and the online scorer, so training and serving share one feature implementation.

Session and campaign models remain research/SOC analysis views and are not required to alert on the NGFW.

## Required Suricata EVE output

`eve-log` must include `flow` events. The relevant portion of `suricata.yaml` is:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - flow
        - ssh
        - smb
        - rdp
        - http
        - dns
        - tls
```

The V3 scorer ignores non-flow records and does not insert unrelated HTTP/DNS/TLS flows into the remote-admin rolling baseline.

## Files from the V3 release

After extracting the verified V3 release, the deployment model is:

```text
gold/V3-1k/models/M1-lightgbm.joblib
gold/V3-1k/models/M1-lightgbm.metrics.json
```

`M1-lightgbm.joblib` is byte-identical to the authoritative `flow-primary.joblib` generated in the same run.

## Install layout

Use this fixed layout on the NGFW or analysis sidecar host:

```text
/opt/remote-admin-v3/
├── venv/
├── scripts/
│   └── score_eve_sidecar.py
├── adminlab/
│   └── online_features.py
└── models/
    ├── M1-lightgbm.joblib
    └── M1-lightgbm.metrics.json

/var/lib/remote-admin-v3/
└── state.json

/var/log/remote-admin-v3/
├── alerts.jsonl
└── service.log
```

Create the runtime account and directories:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin remoteadminml || true
sudo install -d -o remoteadminml -g suricata -m 0750 /opt/remote-admin-v3
sudo install -d -o remoteadminml -g suricata -m 0750 /var/lib/remote-admin-v3
sudo install -d -o remoteadminml -g suricata -m 0750 /var/log/remote-admin-v3
sudo python3 -m venv /opt/remote-admin-v3/venv
sudo /opt/remote-admin-v3/venv/bin/pip install --upgrade pip
sudo /opt/remote-admin-v3/venv/bin/pip install pandas scikit-learn lightgbm joblib
```

Copy these repository files into `/opt/remote-admin-v3`:

```text
scripts/score_eve_sidecar.py          -> /opt/remote-admin-v3/scripts/score_eve_sidecar.py
src/adminlab/online_features.py       -> /opt/remote-admin-v3/adminlab/online_features.py
src/adminlab/__init__.py              -> /opt/remote-admin-v3/adminlab/__init__.py
```

Copy the two verified release model files to `/opt/remote-admin-v3/models/`.

Set ownership:

```bash
sudo chown -R remoteadminml:suricata /opt/remote-admin-v3 /var/lib/remote-admin-v3 /var/log/remote-admin-v3
```

## Baseline bootstrap

On the first installation, replay already collected EVE traffic once to initialize the behavioral state before switching to live tailing:

```bash
sudo -u remoteadminml PYTHONPATH=/opt/remote-admin-v3 \
  /opt/remote-admin-v3/venv/bin/python /opt/remote-admin-v3/scripts/score_eve_sidecar.py \
  --model /opt/remote-admin-v3/models/M1-lightgbm.joblib \
  --metrics /opt/remote-admin-v3/models/M1-lightgbm.metrics.json \
  --eve /var/log/suricata/eve.json \
  --state-file /var/lib/remote-admin-v3/state.json \
  --checkpoint-every 100 >/dev/null
```

The state snapshot includes prior network identities because they are required as state keys. It must therefore be protected as operational telemetry. Those identities are not model columns.

## Live service

Install the repository unit:

```bash
sudo cp deploy/ngfw/remote-admin-v3.service /etc/systemd/system/remote-admin-v3.service
sudo systemctl daemon-reload
sudo systemctl enable --now remote-admin-v3.service
```

The service follows `/var/log/suricata/eve.json`, scores only remote-admin candidate flows, appends alerts to `/var/log/remote-admin-v3/alerts.jsonl`, and checkpoints state every 100 candidate flows plus on clean shutdown/EOF.

Check it with:

```bash
sudo systemctl status remote-admin-v3.service --no-pager
sudo tail -n 50 /var/log/remote-admin-v3/alerts.jsonl
```

Each output record is JSON with this shape:

```json
{
  "alert": true,
  "candidate_stream": "remote-admin",
  "context": {
    "app_proto": "ssh",
    "dest_ip": "10.20.30.40",
    "dest_port": 22,
    "flow_id": 123456789,
    "src_ip": "10.20.10.15",
    "timestamp": "2026-08-16T12:00:00.000000+0000"
  },
  "event_type": "remote_admin_ml",
  "model": "M1-lightgbm-flow",
  "risk_score": 0.91,
  "state_persistent": true,
  "threshold": 0.73
}
```

The numbers above illustrate the JSON schema only; the deployed threshold comes from the verified `M1-lightgbm.metrics.json` and is never hard-coded in the service.

## Runtime features

The production model can use current-flow context such as duration, bytes/packets, `app_proto` and destination port, but the corrected signal is designed around prior relation state:

- connections over 1m/5m/15m/1h/24h/7d/30d;
- unique destinations over multiple windows;
- pair seen count and pair recency;
- pair frequency over 24h/7d/30d;
- new destination/new pair state;
- source-protocol familiarity and protocol novelty;
- source-pair-protocol familiarity;
- destination prior prevalence;
- prior source out-degree and destination in-degree;
- new-edge rate;
- recent protocol switches;
- protocol entropy.

The current flow is scored before it is inserted into state.

## Failure and restart behavior

The scorer writes the rolling state atomically using a temporary file followed by `os.replace`. A restart reloads `/var/lib/remote-admin-v3/state.json`; the 7d/30d baseline is therefore not reset by service restarts.

If the state file is intentionally removed, the detector starts cold. During cold start, novelty features are expected to be elevated. Bootstrap from retained EVE history before treating scores as production alerts.

## Response policy

Corrected V3 should first run in alert/enrichment mode. Recommended output routing:

```text
Suricata EVE flow
      ↓
EveFeatureState
      ↓
M1 flow-primary
      ↓
remote_admin_ml JSON
      ↓
SIEM / NDR correlation
```

Do not convert the score directly into an inline Suricata `drop` action unless the corrected V3 release decision passes its low-FPR challenge and hard-benign promotion gates in the target environment.
