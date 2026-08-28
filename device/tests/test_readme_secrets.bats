#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  README="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)/README.md"
}

# The README was deliberately trimmed to references (operator decision,
# 2026-08-28): the enrollment/token content now lives in the zensical docs,
# so these guards follow the content to its real home instead of pinning a
# README section that no longer exists.
@test "docs document the short-lived enrollment token flow" {
  DOCS="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)/docs/zensical"
  grep -rq "enrollment token" "$DOCS"
}

@test "docs document the re-provision cutover" {
  DOCS="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)/docs/zensical"
  grep -rqi "re-provision" "$DOCS"
}

@test "README no longer claims the generator registers a permanent token" {
  ! grep -q "creates and registers a" "$README"
}
