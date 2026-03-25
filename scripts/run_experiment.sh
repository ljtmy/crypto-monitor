#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <libcrypto-path> <symbol>"
  exit 1
fi

LIBCRYPTO_PATH="$1"
SYMBOL="$2"
THREADS_LIST=(1 4 8 16 64 128)
ALGO="${ALGO:-aes-256-cbc}"
DURATION="${DURATION:-30}"
OUT_DIR="${OUT_DIR:-results}"

mkdir -p "${OUT_DIR}"

for threads in "${THREADS_LIST[@]}"; do
  echo "==> threads=${threads}"
  openssl speed -multi "${threads}" -seconds "${DURATION}" "${ALGO}" \
    > "${OUT_DIR}/openssl-speed-${threads}.log" 2>&1 &
  SPEED_PID=$!

  sleep 1

  sudo ./build/crypto-monitor \
    --pid "${SPEED_PID}" \
    --binary "${LIBCRYPTO_PATH}" \
    --symbol "${SYMBOL}" \
    --duration "${DURATION}" \
    --output "${OUT_DIR}/monitor-${threads}.json" \
    --format json \
    > "${OUT_DIR}/monitor-${threads}.log" 2>&1

  wait "${SPEED_PID}" || true
done

