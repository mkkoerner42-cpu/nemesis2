#!/usr/bin/env bash
set -euo pipefail
TARGET=${1:-staging}
cd "$(git rev-parse --show-toplevel)"/infra
if [[ "$TARGET" == "staging" ]]; then
  docker compose -f compose.staging.yml pull
  docker compose -f compose.staging.yml up -d --remove-orphans
elif [[ "$TARGET" == "canary" ]]; then
  docker compose -f compose.staging.yml up -d --scale agent=2
else
  echo "Unknown target: $TARGET"; exit 1
fi
