#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: sudo bash deploy/ngfw/install_v3.sh RELEASE_ROOT [REPO_ROOT]

RELEASE_ROOT must contain:
  gold/V3-1k/models/M1-lightgbm.joblib
  gold/V3-1k/models/M1-lightgbm.metrics.json

REPO_ROOT defaults to the remote-admin-anomaly-lab directory containing this script.
EOF
  exit 2
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "installer must run as root" >&2; exit 2; }
[[ $# -ge 1 && $# -le 2 ]] || usage

RELEASE_ROOT="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${2:-$(realpath "$SCRIPT_DIR/../..")}"; REPO_ROOT="$(realpath "$REPO_ROOT")"
MODEL_SRC="$RELEASE_ROOT/gold/V3-1k/models/M1-lightgbm.joblib"
METRICS_SRC="$RELEASE_ROOT/gold/V3-1k/models/M1-lightgbm.metrics.json"
SIDECAR_SRC="$REPO_ROOT/scripts/score_eve_sidecar.py"
PACKAGE_SRC="$REPO_ROOT/src/adminlab"
UNIT_SRC="$REPO_ROOT/deploy/ngfw/remote-admin-v3.service"

for path in "$MODEL_SRC" "$METRICS_SRC" "$SIDECAR_SRC" "$PACKAGE_SRC/online_features.py" "$UNIT_SRC"; do
  [[ -e "$path" ]] || { echo "required input missing: $path" >&2; exit 2; }
done

SURICATA_GROUP="suricata"
if ! getent group "$SURICATA_GROUP" >/dev/null; then
  groupadd --system "$SURICATA_GROUP"
fi
if ! id remoteadminml >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$SURICATA_GROUP" remoteadminml
else
  usermod -a -G "$SURICATA_GROUP" remoteadminml
fi

install -d -o remoteadminml -g "$SURICATA_GROUP" -m 0750 \
  /opt/remote-admin-v3 \
  /opt/remote-admin-v3/src \
  /opt/remote-admin-v3/scripts \
  /opt/remote-admin-v3/models \
  /var/lib/remote-admin-v3 \
  /var/log/remote-admin-v3

rm -rf /opt/remote-admin-v3/src/adminlab
cp -a "$PACKAGE_SRC" /opt/remote-admin-v3/src/adminlab
install -o remoteadminml -g "$SURICATA_GROUP" -m 0750 "$SIDECAR_SRC" /opt/remote-admin-v3/scripts/score_eve_sidecar.py
install -o remoteadminml -g "$SURICATA_GROUP" -m 0640 "$MODEL_SRC" /opt/remote-admin-v3/models/M1-lightgbm.joblib
install -o remoteadminml -g "$SURICATA_GROUP" -m 0640 "$METRICS_SRC" /opt/remote-admin-v3/models/M1-lightgbm.metrics.json

python3 -m venv /opt/remote-admin-v3/venv
/opt/remote-admin-v3/venv/bin/python -m pip install --disable-pip-version-check --upgrade pip
/opt/remote-admin-v3/venv/bin/python -m pip install --disable-pip-version-check \
  'pandas>=2.2,<3' 'scikit-learn>=1.5,<2' 'lightgbm>=4.5,<5' 'joblib>=1.4,<2'

chown -R remoteadminml:"$SURICATA_GROUP" /opt/remote-admin-v3 /var/lib/remote-admin-v3 /var/log/remote-admin-v3
chmod 0750 /opt/remote-admin-v3 /opt/remote-admin-v3/src /opt/remote-admin-v3/scripts /opt/remote-admin-v3/models

# Fail closed before installing the service: prove the exact serialized model can
# load with the target runtime and that its expected columns are available from
# the production EveFeatureState implementation.
PYTHONPATH=/opt/remote-admin-v3/src /opt/remote-admin-v3/venv/bin/python - <<'PY'
import json
from pathlib import Path
import joblib
from adminlab.online_features import EveFeatureState
model_path=Path('/opt/remote-admin-v3/models/M1-lightgbm.joblib')
metrics_path=Path('/opt/remote-admin-v3/models/M1-lightgbm.metrics.json')
model=joblib.load(model_path)
metrics=json.loads(metrics_path.read_text())
columns=list(model.feature_names_in_)
event={
    'timestamp':'2026-08-16T12:00:00+00:00','event_type':'flow','flow_id':1,
    'src_ip':'10.0.0.10','src_port':55000,'dest_ip':'10.0.0.20','dest_port':22,
    'proto':'TCP','app_proto':'ssh',
    'flow':{'start':'2026-08-16T11:59:59+00:00','end':'2026-08-16T12:00:00+00:00',
            'bytes_toserver':100,'bytes_toclient':200,'pkts_toserver':3,'pkts_toclient':4},
}
features=EveFeatureState().consume_flow(event)['features']
missing=[c for c in columns if c not in features]
if missing:
    raise SystemExit(f'model expects features not emitted by EveFeatureState: {missing}')
if not isinstance(metrics.get('threshold'), (int,float)):
    raise SystemExit('metrics threshold missing/non-numeric')
print(json.dumps({'model_columns':len(columns),'threshold':metrics['threshold'],'runtime_contract':'PASS'},sort_keys=True))
PY

install -o root -g root -m 0644 "$UNIT_SRC" /etc/systemd/system/remote-admin-v3.service
systemctl daemon-reload

echo "installed=/opt/remote-admin-v3"
echo "state=/var/lib/remote-admin-v3/state.json"
echo "alerts=/var/log/remote-admin-v3/alerts.jsonl"
echo "next: bootstrap state from retained Suricata EVE, then run: systemctl enable --now remote-admin-v3.service"
