#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Build and stage every supported IOx package for a running Compose server.
# This only creates served artifacts; it never connects to or changes a device.
#
# Usage: tools/provision-iox-packages.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

"$HERE/stage-iox-package.sh" --arch arm64
"$HERE/stage-iox-package.sh" --arch amd64

echo ">> both IOx packages are staged: iris-arm64.tar, iris-amd64.tar"
