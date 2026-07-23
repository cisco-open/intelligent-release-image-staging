#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# build.sh: --amd64 is accepted and defaults the package name to iris-amd64.tar
# (naming-collision fix, gap #4). We do not run a full docker build here — we
# verify the flag is parsed and the amd64 default name is wired.

setup() { BUILD="$BATS_TEST_DIRNAME/../build.sh"; }

@test "build.sh --help lists the --amd64 flag" {
  run bash "$BUILD" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"--amd64"* ]]
}

@test "build.sh has no syntax errors" {
  run bash -n "$BUILD"
  [ "$status" -eq 0 ]
}

@test "amd64 arm defaults PACKAGE_NAME to iris-amd64.tar" {
  run grep -F "DEFAULT_PACKAGE_NAME=iris-amd64.tar" "$BUILD"
  [ "$status" -eq 0 ]
}

@test "arm64 defaults PACKAGE_NAME to iris-arm64.tar" {
  run grep -F "DEFAULT_PACKAGE_NAME=iris-arm64.tar" "$BUILD"
  [ "$status" -eq 0 ]
}

@test "rejects an unknown option" {
  run bash "$BUILD" --nope
  [ "$status" -eq 2 ]
}
