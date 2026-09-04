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

@test "release assembler ships the aria2c build scripts NOTICE promises" {
  # GPLv2 section 3 wants the scripts used to control compilation, not only
  # the source, and NOTICE now states they ship in this repository rather
  # than being available on request. A release that drops them would make
  # that statement false, which is worse than the old written offer.
  script="$BATS_TEST_DIRNAME/../../tools/make-release.sh"
  grep -q 'aria2c-build' "$script"
  grep -q 'tools/aria2c-build/' "$BATS_TEST_DIRNAME/../../NOTICE"
  [ -f "$BATS_TEST_DIRNAME/../../tools/aria2c-build/Dockerfile" ]
  [ -f "$BATS_TEST_DIRNAME/../../tools/aria2c-build/build.sh" ]
  # the patch set must NOT be duplicated into the build directory
  run bash -c 'ls "$1"/tools/aria2c-build/*.patch 2>/dev/null' _ "$BATS_TEST_DIRNAME/../.."
  [ "$status" -ne 0 ]
}

@test "release archive carries linked docs and every current device package builder" {
  repo="$BATS_TEST_DIRNAME/../.."
  # The assembler ships TRACKED files only and refuses when an allowlisted
  # input is missing from the index, so a brand-new shipped file must be
  # `git add`ed before this live-checkout case can pass.
  for new_input in lab/iris-ssh-policy.sh requirements-dev.txt; do
    git -C "$repo" ls-files --error-unmatch "$new_input" >/dev/null 2>&1 \
      || skip "$new_input is not tracked yet (git add it): the release ships tracked files only"
  done
  run env SCRUB_PASS= SCRUB_USER= bash "$repo/tools/make-release.sh"
  [ "$status" -eq 0 ]

  for path in \
    iris/docs/zensical/index.md \
    iris/zensical.toml \
    iris/requirements-docs.txt \
    iris/requirements-dev.txt \
    iris/CHANGELOG.md \
    iris/DEVELOPMENT.md \
    iris/CONTRIBUTING.md \
    iris/TESTING.md \
    iris/lab/device-run.sh \
    iris/lab/xr-run.sh \
    iris/lab/iris-ssh-policy.sh \
    iris/tools/provision-iox-packages.sh \
    iris/tools/build-xr-package.sh \
    iris/tools/check-package-freshness.sh; do
    tar tzf "$repo/release/iris.tgz" | grep -qx "$path" || return 1
  done
}

# ── the release is assembled from TRACKED files only ──────────────────────────
# make-release.sh used to `cp -R` whole directory trees from the live checkout,
# so anything gitignored inside them (server/.env with a collector bearer
# token, private keys under server/certs/, the Cisco-licensed console
# typeface, the host-specific compose override, device/xr/out/iris-xr.rpm)
# shipped in the tarball. The assembler now copies `git ls-files` output only,
# builds under a temp dir, and publishes atomically with a sha256 + manifest.

# Build a small throwaway git repo that has every top-level input the
# assembler requires, with the WORKING-TREE copy of make-release.sh dropped in
# (so the test exercises the edited script, not the committed one).
_make_release_fixture() {
  repo="$BATS_TEST_DIRNAME/../.."
  FIX="$BATS_TEST_TMPDIR/fixture"
  mkdir -p "$FIX"
  git -C "$FIX" init -q
  git -C "$FIX" config user.email t@example.com
  git -C "$FIX" config user.name t
  mkdir -p "$FIX/docs/zensical" "$FIX/server/certs" "$FIX/server/webroot/fonts" \
           "$FIX/device/xr/out" "$FIX/tools/aria2c-patches" "$FIX/lab" \
           "$FIX/kubernetes" "$FIX/fleet"
  for f in README.md CHANGELOG.md DEVELOPMENT.md CONTRIBUTING.md TESTING.md \
           LICENSE NOTICE SECURITY.md CODE_OF_CONDUCT.md zensical.toml \
           requirements-docs.txt requirements-dev.txt; do echo "$f" > "$FIX/$f"; done
  echo "0.0.0-test" > "$FIX/VERSION"
  cp "$repo/.gitignore" "$repo/.dockerignore" "$FIX/"
  echo "# index" > "$FIX/docs/zensical/index.md"
  echo "# server" > "$FIX/server/tracker.py"
  echo "PUBLIC CERT" > "$FIX/server/certs/cisco_bulkhash_verify.pem"
  echo "# device" > "$FIX/device/bootstrap.sh"
  for f in get-aria2c.sh aria2c.sha256 make-torrent.sh make-agent-bundle.sh \
           gen-device-installers.sh apply-assignments.sh get-ioxclient.sh \
           stage-iox-package.sh provision-iox-packages.sh build-xr-package.sh \
           check-package-freshness.sh start-compose-server.sh; do
    echo "# $f" > "$FIX/tools/$f"
  done
  cp "$repo/tools/make-release.sh" "$FIX/tools/make-release.sh"
  echo "patch" > "$FIX/tools/aria2c-patches/0001.patch"
  echo "# run" > "$FIX/lab/device-run.sh"; echo "# run" > "$FIX/lab/xr-run.sh"
  echo "# policy" > "$FIX/lab/iris-ssh-policy.sh"
  echo "kind: Namespace" > "$FIX/kubernetes/namespace.yaml"
  echo "# fleet" > "$FIX/fleet/README.md"
  for f in devices.csv.example assignments.csv.example; do
    echo "example" > "$FIX/fleet/$f"
  done
  git -C "$FIX" add -A
  git -C "$FIX" commit -q -m fixture

  # Plant the gitignored material a live lab checkout carries.
  echo 'IRIS_OTLP_HEADERS="Authorization=Bearer planted-collector-token"' > "$FIX/server/.env"
  echo "PLANTED PRIVATE KEY" > "$FIX/server/certs/lab-private.key"
  echo "services: {}" > "$FIX/server/docker-compose.override.yml"
  echo "woff2" > "$FIX/server/webroot/fonts/SharpSans-Bold.woff2"
  echo "rpm" > "$FIX/device/xr/out/iris-xr.rpm"
  echo "planted" > "$FIX/fleet/devices.csv"
  # every planted file must really be ignored by the repo's own rules
  for f in server/.env server/certs/lab-private.key server/docker-compose.override.yml \
           server/webroot/fonts/SharpSans-Bold.woff2 device/xr/out/iris-xr.rpm fleet/devices.csv; do
    git -C "$FIX" check-ignore -q "$f" || { echo "fixture: $f is not gitignored" >&2; return 1; }
  done
}

@test "release ships tracked files only: gitignored secrets, keys, font, override and XR output are absent" {
  _make_release_fixture
  run env SCRUB_PASS= SCRUB_USER= bash "$FIX/tools/make-release.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  members="$(tar tzf "$FIX/release/iris.tgz")"
  for absent in iris/server/.env iris/server/certs/lab-private.key \
                iris/server/docker-compose.override.yml \
                iris/server/webroot/fonts/SharpSans-Bold.woff2 \
                iris/device/xr/out/iris-xr.rpm iris/fleet/devices.csv; do
    if echo "$members" | grep -qx "$absent"; then
      echo "leaked into the tarball: $absent" >&2; return 1
    fi
  done
  run grep -rq planted-collector-token "$FIX/release/iris"
  [ "$status" -ne 0 ]
  # tracked material still ships, including the public verify cert and the
  # structural placeholders
  for present in iris/server/tracker.py iris/server/certs/cisco_bulkhash_verify.pem \
                 iris/tools/aria2c-patches/0001.patch iris/fleet/devices.csv.example \
                 iris/lab/iris-ssh-policy.sh \
                 iris/bin/.gitkeep iris/artifacts/.gitkeep iris/MANIFEST.txt; do
    echo "$members" | grep -qx "$present" || { echo "missing: $present" >&2; return 1; }
  done
}

@test "release emits a matching sha256 and a member manifest, and leaves no temp dir behind" {
  _make_release_fixture
  run env SCRUB_PASS= SCRUB_USER= bash "$FIX/tools/make-release.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ -f "$FIX/release/iris.tgz.sha256" ]
  ( cd "$FIX/release" && sha256sum -c --quiet iris.tgz.sha256 )
  grep -q '  iris/server/tracker.py$' "$FIX/release/MANIFEST.txt"
  # the inventory verifies against the unpacked tree
  ( cd "$FIX/release" && sha256sum -c --quiet MANIFEST.txt )
  # nothing but the published outputs remains under release/
  run ls -A "$FIX/release"
  [[ "$output" != *".iris.tmp"* ]]
}

@test "a failed release leaves the previous release/ untouched" {
  _make_release_fixture
  run env SCRUB_PASS= SCRUB_USER= bash "$FIX/tools/make-release.sh"
  [ "$status" -eq 0 ]
  before="$(cat "$FIX/release/iris.tgz.sha256")"
  echo "marker" > "$FIX/release/iris/PREVIOUS"
  # a tracked file missing from the working tree aborts the assembly
  rm "$FIX/server/tracker.py"
  run env SCRUB_PASS= SCRUB_USER= bash "$FIX/tools/make-release.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"tracked file missing"* ]]
  [ -f "$FIX/release/iris/PREVIOUS" ]
  [ "$(cat "$FIX/release/iris.tgz.sha256")" = "$before" ]
  run ls -A "$FIX/release"
  [[ "$output" != *".iris.tmp"* ]]
}

@test "release is reproducible: two runs of the same tree produce identical tarballs" {
  tar --version 2>/dev/null | grep -q 'GNU tar' || skip "needs GNU tar"
  _make_release_fixture
  run env SCRUB_PASS= SCRUB_USER= bash "$FIX/tools/make-release.sh"
  [ "$status" -eq 0 ]
  first="$(cat "$FIX/release/iris.tgz.sha256")"
  sleep 1
  touch "$FIX/server/tracker.py"
  run env SCRUB_PASS= SCRUB_USER= bash "$FIX/tools/make-release.sh"
  [ "$status" -eq 0 ]
  [ "$(cat "$FIX/release/iris.tgz.sha256")" = "$first" ]
}

# ── credential scrub + leak safety net (driven through the real script) ───────
# The scrub filter historically covered *.sh / *.conf* / *.example only, so a
# username or password in a .py or .md shipped un-redacted, and the safety net
# grepped for SCRUB_PASS alone, so a leaked operator login was never caught.
# Both tests below run tools/make-release.sh itself over the fixture tree --
# reverting either fix in the script must turn them red.

@test "release scrub redacts SCRUB_USER and SCRUB_PASS in every shipped text type" {
  command -v perl >/dev/null || skip "perl not available"
  _make_release_fixture
  # Plant the credentials in tracked files of the types the old *.sh-only
  # filter skipped, plus one *.sh as a control.
  echo "# operator testuser_secret / testpass_secret" >> "$FIX/server/tracker.py"
  echo "log in as testuser_secret with testpass_secret" >> "$FIX/docs/zensical/index.md"
  echo "HOST_USER=testuser_secret HOST_PASS=testpass_secret" >> "$FIX/tools/get-aria2c.sh"

  # A miss anywhere is fatal on its own: the leak net refuses to package, so a
  # zero exit already proves every planted secret was rewritten.
  run env SCRUB_PASS=testpass_secret SCRUB_USER=testuser_secret \
    bash "$FIX/tools/make-release.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }

  for shipped in server/tracker.py docs/zensical/index.md tools/get-aria2c.sh; do
    run grep -F testuser_secret "$FIX/release/iris/$shipped"
    [ "$status" -ne 0 ] || return 1
    run grep -F testpass_secret "$FIX/release/iris/$shipped"
    [ "$status" -ne 0 ] || return 1
  done
  # ...and the replacements really landed, rather than the files vanishing.
  run grep -F admin "$FIX/release/iris/server/tracker.py"
  [ "$status" -eq 0 ] || return 1
  run grep -F changeme "$FIX/release/iris/docs/zensical/index.md"
  [ "$status" -eq 0 ]
}

@test "release aborts when a scrub secret survives into the tree, SCRUB_USER included" {
  command -v perl >/dev/null || skip "perl not available"
  _make_release_fixture
  # The username rewrite is word-anchored, so an occurrence glued to another
  # word survives it. The safety net greps for the raw substring and must
  # refuse to package -- and it must check SCRUB_USER, not SCRUB_PASS alone.
  echo "ssh testuser_secretadmin@host" >> "$FIX/server/tracker.py"

  run env SCRUB_PASS= SCRUB_USER=testuser_secret bash "$FIX/tools/make-release.sh"
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"scrub secret found in the release tree"* ]] || return 1
  # nothing was published
  [ ! -e "$FIX/release/iris.tgz" ]
}
