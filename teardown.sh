#!/usr/bin/env bash
set -euo pipefail

echo "Stopping services..."
systemctl --user disable --now vibevoice-proxy 2>/dev/null || true
systemctl --user disable --now vibevoice-server 2>/dev/null || true

if docker container inspect vibevoice-vllm &>/dev/null; then
    echo "Stopping vibevoice-vllm container..."
    docker stop vibevoice-vllm
    docker rm vibevoice-vllm
fi

echo "All services stopped. Run ./setup.sh to start again."
