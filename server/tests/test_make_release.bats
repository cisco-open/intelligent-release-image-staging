#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# The release tarball ships NOTICE, which points at tools/aria2c-patches/ as
# the corresponding source for the handed-in (GPL) aria2c binary. The
# assembler must therefore include that directory — a release whose NOTICE
# and checksum manifest reference patches that are absent does not actually
# ship corresponding source.

@test "release assembler ships the aria2c corresponding-source patches" {
  script="$BATS_TEST_DIRNAME/../../tools/make-release.sh"
  grep -q 'aria2c-patches' "$script"
}

@test "NOTICE points at the patches directory the release must carry" {
  grep -q 'tools/aria2c-patches/' "$BATS_TEST_DIRNAME/../../NOTICE"
}

@test "release archive carries linked docs and every current device package builder" {
  repo="$BATS_TEST_DIRNAME/../.."
  run env SCRUB_PASS= SCRUB_USER= bash "$repo/tools/make-release.sh"
  [ "$status" -eq 0 ]

  for path in \
    iris/docs/zensical/index.md \
    iris/zensical.toml \
    iris/requirements-docs.txt \
    iris/CHANGELOG.md \
    iris/DEVELOPMENT.md \
    iris/CONTRIBUTING.md \
    iris/TESTING.md \
    iris/lab/device-run.sh \
    iris/lab/xr-run.sh \
    iris/tools/provision-iox-packages.sh \
    iris/tools/build-xr-package.sh \
    iris/tools/check-package-freshness.sh; do
    tar tzf "$repo/release/iris.tgz" | grep -qx "$path" || return 1
  done
}
