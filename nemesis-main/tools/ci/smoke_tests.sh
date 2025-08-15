#!/usr/bin/env bash
set -euo pipefail
curl -fsS http://localhost:8081/healthz | grep '"ok"'
