#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
sudo apt-get install -y software-properties-common tcpdump zstd jq curl ca-certificates openssl mosquitto mosquitto-clients
if ! grep -Rqs 'suricata-stable' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
  sudo add-apt-repository -y ppa:oisf/suricata-stable || true
fi
sudo apt-get update -y
sudo apt-get install -y suricata
sudo suricata-update >/dev/null 2>&1 || true
python -m pip install --upgrade pip
python -m pip install -r requirements.txt 'huggingface_hub[hf_xet]>=1.0.0'
docker pull zeek/zeek:8.2.1
printf 'Suricata: '; suricata -V || true
printf 'Zeek: '; docker run --rm zeek/zeek:8.2.1 zeek --version || true
printf 'Mosquitto: '; mosquitto -h 2>&1 | head -1 || true
printf 'Chrome: '; (google-chrome --version || google-chrome-stable --version || chromium --version || true)
