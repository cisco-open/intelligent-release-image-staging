#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# provision-served.sh stages the three DERIVABLE served artifacts (Guest Shell
# bundle, bootstrap.sh, iris-catalog.pem) into the artifacts dir at container
# startup, so a fresh deploy no longer fails onboarding on missing files. It is
# best-effort: it must never exit non-zero (that would block the server start).

setup() {
  PROV="$BATS_TEST_DIRNAME/../provision-served.sh"
  DEVICE="$BATS_TEST_DIRNAME/../../device"
  TMP="$(mktemp -d)"
  ART="$TMP/artifacts"; mkdir -p "$ART"
  printf '#!/bin/sh\necho fake\n' > "$TMP/aria2c"; chmod +x "$TMP/aria2c"
  mkdir -p "$TMP/config/tls"; printf 'CRTPEM\n' > "$TMP/config/tls/crt.pem"
  run_prov() {
    IRIS_DEVICE_DIR="$DEVICE" IRIS_ARIA2="$TMP/aria2c" \
      IRIS_CRT_SRC="$TMP/config/tls/crt.pem" \
      bash "$PROV" "$ART"
  }
}
teardown() { rm -rf "$TMP"; }

@test "stages the Guest Shell bundle, bootstrap.sh, and iris-catalog.pem" {
  run run_prov
  [ "$status" -eq 0 ]
  [ -f "$ART/iris-agent.tgz" ]
  [ -f "$ART/bootstrap.sh" ]
  [ -f "$ART/iris-catalog.pem" ]
  # the cert is the server's public cert, verbatim
  run cat "$ART/iris-catalog.pem"
  [[ "$output" == "CRTPEM" ]]
  # the bundle carries the agent code
  tar tzf "$ART/iris-agent.tgz" | grep -q "agent/iris_agent.py"
}

@test "rebuilds the bundle every run so it can't go stale" {
  run_prov
  cp "$ART/iris-agent.tgz" "$TMP/first.tgz"
  # newer agent source -> a fresh run must re-pack (content reflects current tree)
  run run_prov
  [ "$status" -eq 0 ]
  [ -f "$ART/iris-agent.tgz" ]
}

@test "best-effort: read-only artifacts dir warns but exits 0 (never blocks startup)" {
  chmod -w "$ART"
  run run_prov
  chmod +w "$ART"
  [ "$status" -eq 0 ]
  [[ "$output" == *"not writable"* ]]
}

@test "missing server cert: still stages the bundle, exits 0, warns about the cert" {
  rm -f "$TMP/config/tls/crt.pem"
  run run_prov
  [ "$status" -eq 0 ]
  [ -f "$ART/iris-agent.tgz" ]
  [ ! -f "$ART/iris-catalog.pem" ]
  [[ "$output" == *"cert"* ]]
}

@test "notes when the IOx iris.tar is absent (the one external build)" {
  run run_prov
  [[ "$output" == *"iris.tar"* ]]
}

@test "does not flag iris.tar when it is already staged" {
  printf 'IOXPKG\n' > "$ART/iris.tar"
  run run_prov
  [[ "$output" != *"build device/iox/build.sh"* ]]
}
