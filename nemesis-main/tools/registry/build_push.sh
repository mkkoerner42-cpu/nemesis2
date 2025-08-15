#!/usr/bin/env bash
set -euo pipefail
IMAGE=${1:-agent}
REG=${REGISTRY:-ghcr.io/${GITHUB_REPOSITORY_OWNER:-mkkoerner42-cpu}/nemesis}
TAG=${IMAGE_TAG:-latest}
USER="${GH_USERNAME:-${GITHUB_REPOSITORY_OWNER:-mkkoerner42-cpu}}"

echo "$CR_PAT" | docker login ghcr.io -u "$USER" --password-stdin
docker build -t "$REG/$IMAGE:$TAG" -f agent/dockerfile .
docker push "$REG/$IMAGE:$TAG"
