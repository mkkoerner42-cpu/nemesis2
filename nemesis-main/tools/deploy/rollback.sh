#!/usr/bin/env bash
set -euo pipefail
REASON=${1:-"unknown"}
echo "Rolling back due to: $REASON"
# TODO: Tag auf letzte funktionierende Version setzen
exit 0
