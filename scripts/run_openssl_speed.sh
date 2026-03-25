#!/usr/bin/env bash
set -euo pipefail

THREADS="${1:-1}"
ALGO="${2:-aes-256-cbc}"
DURATION="${3:-30}"

echo "Running openssl speed with threads=${THREADS}, algo=${ALGO}, seconds=${DURATION}"
openssl speed -multi "${THREADS}" -seconds "${DURATION}" "${ALGO}"

