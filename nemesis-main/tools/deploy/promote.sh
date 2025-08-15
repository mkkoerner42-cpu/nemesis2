#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"/infra
docker compose -f compose.prod.yml pull
docker compose -f compose.prod.yml up -d --remove-orphans
