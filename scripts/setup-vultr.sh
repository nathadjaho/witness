#!/usr/bin/env bash
# One-shot setup for a fresh Vultr Cloud Compute VM (Ubuntu 22.04/24.04, 2 vCPU / 4 GB recommended).
#   git clone <repo> /opt/witness && cd /opt/witness && sudo bash scripts/setup-vultr.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Docker"
if ! command -v docker >/dev/null; then curl -fsSL https://get.docker.com | sh; fi

echo "==> gVisor (runsc) — user-space kernel between the sandbox and the host"
if ! command -v runsc >/dev/null; then
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list
  apt-get update && apt-get install -y runsc
  runsc install
  systemctl restart docker
fi

echo "==> .env"
if [ ! -f .env ]; then
  cp .env.example .env
  sed -i "s/^PROXY_ADMIN_TOKEN=.*/PROXY_ADMIN_TOKEN=$(openssl rand -hex 24)/" .env
  echo "   Edit .env and set VULTR_INFERENCE_API_KEY and PLANNER_MODEL, then re-run this script."
fi
set -a; . ./.env; set +a
mkdir -p "${DATA_DIR:-/opt/witness/data}/artifacts"

echo "==> Build sandbox image"
docker build -t witness-runner:latest runner

echo "==> Start control plane"
docker compose up -d --build

echo "==> Host firewall: the sandbox subnet may talk to the egress proxy and nothing else"
iptables -C DOCKER-USER -s 172.30.0.0/24 -d 172.30.0.2 -j ACCEPT 2>/dev/null || \
  iptables -I DOCKER-USER 1 -s 172.30.0.0/24 -d 172.30.0.2 -j ACCEPT
iptables -C DOCKER-USER -s 172.30.0.0/24 -j DROP 2>/dev/null || \
  iptables -I DOCKER-USER 2 -s 172.30.0.0/24 -j DROP
# Also stop the sandbox subnet from reaching services published on the host itself.
iptables -C INPUT -s 172.30.0.0/24 -j DROP 2>/dev/null || iptables -I INPUT 1 -s 172.30.0.0/24 -j DROP

echo "==> Smoke test"
sleep 3
curl -fsS localhost/api/health && echo && echo "Witness is up on http://$(curl -fsS ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')/"
