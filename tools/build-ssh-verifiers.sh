#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$REPO/bin}"
# The server uses the same stages, so standalone bundles and served bundles
# have one pinned source/build definition. No device changes are performed.
docker buildx build --pull --target ssh-verifier-artifacts \
  --output "type=local,dest=$OUT" -f "$REPO/server/Dockerfile" "$REPO"
