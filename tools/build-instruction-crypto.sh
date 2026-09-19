#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$REPO/bin}"
mkdir -p "$OUT"
for arch in ${IRIS_CRYPTO_ARCHES:-amd64 arm64}; do
  case "$arch" in amd64|arm64) ;; *) exit 2 ;; esac
  scratch="$(mktemp -d)"
  docker buildx build --platform "linux/$arch" \
    --output "type=local,dest=$scratch" -f "$REPO/tools/build-instruction-crypto.Dockerfile" "$REPO"
  install -m 0755 "$scratch/iris-aead" "$OUT/iris-aead-$arch"
  install -m 0644 "$scratch/iris-aead.LICENCE" "$OUT/iris-aead.LICENCE"
  # Keep failed-build evidence; remove only successful, exact generated files.
  rm "$scratch/iris-aead" "$scratch/iris-aead.LICENCE"
  rmdir "$scratch"
done
