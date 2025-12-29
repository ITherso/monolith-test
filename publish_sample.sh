#!/usr/bin/env bash
# Example usage of merkle publish CLI route via environment variables
set -euo pipefail

if [ -z "${WEB3_RPC_URL:-}" ] || [ -z "${WEB3_PRIVATE_KEY:-}" ]; then
  echo "Please set WEB3_RPC_URL and WEB3_PRIVATE_KEY environment variables before running"
  exit 1
fi

SCAN_ID=${1:-1}

echo "Publishing merkle root for scan ${SCAN_ID} via CLI"
WEB3_PRIVATE_KEY="$WEB3_PRIVATE_KEY" WEB3_RPC_URL="$WEB3_RPC_URL" python /home/kali/Desktop/cyber.py --publish-merkle "$SCAN_ID"
