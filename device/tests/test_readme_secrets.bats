#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  README="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)/README.md"
}

@test "README documents the short-lived enrollment token flow" {
  grep -q "enrollment token" "$README"
}

@test "README documents the re-provision cutover" {
  grep -qi "re-provision" "$README"
}

@test "README no longer claims the generator registers a permanent token" {
  ! grep -q "creates and registers a" "$README"
}
