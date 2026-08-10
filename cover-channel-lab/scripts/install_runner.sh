#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
sudo apt-get update -y
sudo apt-get install -y software-properties-common tcpdump zstd jq curl ca-certificates openssl mosquitto mosquitto-clients iproute2 openjdk-21-jdk-headless
if ! grep -Rqs 'suricata-stable' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
  sudo add-apt-repository -y ppa:oisf/suricata-stable || true
fi
sudo apt-get update -y
sudo apt-get install -y suricata
sudo suricata-update >/dev/null 2>&1 || true
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Independent wire clients used by the diversity stage.
mkdir -p /tmp/coverlab-java-client
javac -d /tmp/coverlab-java-client "$ROOT/clients/CoverlabJavaClient.java"
# GitHub-hosted runners ship an up-to-date rustup toolchain. Do not replace it
# with Ubuntu's older distro rustc/cargo; install stable only as a fallback.
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
  export PATH="$HOME/.cargo/bin:$PATH"
fi
( cd "$ROOT/clients/rust_client" && cargo build --release )
cp "$ROOT/clients/rust_client/target/release/coverlab-rust-client" /tmp/coverlab-rust-client
chmod +x /tmp/coverlab-rust-client

docker pull zeek/zeek:8.2.1
printf 'Suricata: '; suricata -V || true
printf 'Zeek: '; docker run --rm zeek/zeek:8.2.1 zeek --version || true
printf 'Mosquitto: '; mosquitto -h 2>&1 | head -1 || true
printf 'Java: '; java -version 2>&1 | head -1 || true
printf 'Cargo: '; cargo --version || true
printf 'Chrome: '; (google-chrome --version || google-chrome-stable --version || chromium --version || true)
