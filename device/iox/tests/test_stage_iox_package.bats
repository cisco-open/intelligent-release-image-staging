#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# tools/stage-iox-package.sh validates inputs and picks the arch-correct name
# BEFORE building, so a missing cert / unwritable dir fails fast (no docker).

setup() {
  HELPER="$BATS_TEST_DIRNAME/../../../tools/stage-iox-package.sh"
  TMP="$(mktemp -d)"; ART="$TMP/artifacts"; mkdir -p "$ART"
}
teardown() { rm -rf "$TMP"; }

@test "help lists --arch and --artifacts-dir" {
  run bash "$HELPER" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"--arch"* ]]
  [[ "$output" == *"--artifacts-dir"* ]]
}

@test "rejects an invalid --arch before building" {
  run env CATALOG_PEM=/dev/null bash "$HELPER" --arch mips --artifacts-dir "$ART"
  [ "$status" -eq 2 ]
  [[ "$output" == *"--arch must be amd64 or arm64"* ]]
}

@test "fails clearly when no cert inputs are set" {
  run env -u CATALOG_PEM -u CATALOG_PEM_URL bash "$HELPER" --artifacts-dir "$ART"
  [ "$status" -eq 1 ]
  [[ "$output" == *"CATALOG_PEM"* ]]
}

@test "fails when the artifacts dir is not writable" {
  chmod -w "$ART"
  run env CATALOG_PEM=/dev/null bash "$HELPER" --artifacts-dir "$ART"
  chmod +w "$ART"
  [ "$status" -eq 1 ]
  [[ "$output" == *"not writable"* ]]
}

@test "has no syntax errors" {
  run bash -n "$HELPER"
  [ "$status" -eq 0 ]
}
