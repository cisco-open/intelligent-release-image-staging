#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Build + package the IRIS XR agent for appmgr delivery to Cisco IOS-XR
# (Cisco 8000 series, e.g. 8010/8201 -- x86_64 only).
#
#   tools/build-xr-package.sh [--out DIR] [--dry-run]
#
# Pipeline (hardware-proven end to end on 8010-R1, IOS-XR 25.4.2 LNT -- see
# agentinfo/xr-support/LAB-RESULTS-2026-08-27.md, the 2026-08-28 addendum):
#   1. assemble the device/xr/ build context (agent python + x86_64 aria2c +
#      the pinned catalog cert) and `docker build` the image.
#   2. `docker save` that image to a tar.
#   3. reuse (or clone, pinned commit) ios-xr/xr-appmgr-build, and write its
#      build.yaml (name iris-xr, release ThinXR_7.3.15).
#   4. run its ./appmgr_build.
#   5. BEWARE: that tool prints "Done building" EVEN ON FAILURE -- a lab
#      incident on 192.0.2.10 lost time to trusting it. This script does
#      NOT trust the message or the exit code: it verifies an RPM actually
#      landed under RPMS/ and fails honestly, with the tool's own log tail,
#      when it did not. RPMS/ is cleared before every run so a stale RPM
#      left over from an earlier failed attempt can never be mistaken for
#      this run's output.
#   6. copy the RPM found under RPMS/ to OUT/iris-xr.rpm.
#
# The build.yaml schema written below (packages list; name / release /
# target-release / version / sources / config-dir / data-dir /
# copy_hostname / copy_ems_cert) is the one hardware-proven by the
# 2026-08-28 spike and by every lab RPM since (Cisco 8201 and 8010-R1, see
# docs/zensical/validation.md). Do not "adjust" a key here without
# re-proving the RPM on real hardware.
#
# Inputs (env overridable):
#   CATALOG_PEM              pinned server cert -- CERTIFICATE BLOCK ONLY.
#                             Default: fetched from CATALOG_PEM_URL. A file
#                             carrying a PRIVATE KEY block (the combined
#                             cert+key shape IRIS_CERT points at server-side)
#                             is refused outright; device/iox/build.sh
#                             applies the same refusal to the IOx package.
#   CATALOG_PEM_URL           required when CATALOG_PEM is not supplied.
#   CATALOG_PEM_FINGERPRINT   expected SHA-256 fingerprint of the catalog
#                             cert (format "SHA256:AA:BB:..."). Required
#                             when CATALOG_PEM is not supplied. The build
#                             aborts on a mismatch, so a MITM cannot bake a
#                             rogue cert into the fleet image. Obtain it once
#                             with:
#                               openssl x509 -noout -fingerprint -sha256 -in iris-catalog.pem
#   ARIA2C_BIN                architecture-matched (x86_64) aria2c override.
#                             Default: deliverables/aria2c-x86_64 (checksum-
#                             verified against tools/aria2c.sha256) or the
#                             matching local agent bundle artifacts/iris-agent.tgz
#                             (its aria2c is still checksum-verified). This
#                             build does NOT download aria2c -- see
#                             tools/get-aria2c.sh for how the deliverable is
#                             produced and verified. Cisco 8000 is x86_64
#                             only, so (unlike device/iox/build.sh, which
#                             juggles two target arches) there is no file(1)
#                             architecture sanity check here: an explicit
#                             ARIA2C_BIN is trusted the way the checksum-
#                             verified paths already are.
#   IMAGE_TAG                 docker tag (default iris-xr:amd64).
#   RPM_NAME                  app/package name (default iris-xr) -- written
#                             into build.yaml's `name` and used for the
#                             saved image tar's filename.
#   APPMGR_RELEASE             appmgr release config (default ThinXR_7.3.15,
#                             the lab-proven value -- do not change without
#                             re-proving against real hardware).
#   APPMGR_BUILD_REPO_URL      ios-xr/xr-appmgr-build git remote.
#   APPMGR_BUILD_COMMIT        pinned commit (default 37d79607 -- the commit
#                             proven end to end in the lab). Do not bump
#                             without re-proving the pipeline.
#   APPMGR_BUILD_DIR           where the xr-appmgr-build clone lives.
#                             Default ${XDG_CACHE_HOME:-$HOME/.cache}/iris/xr-appmgr-build.
#                             Reused idempotently: if it already holds an
#                             executable ./appmgr_build, this script does
#                             NOT re-clone (a mismatched pinned commit only
#                             warns -- it does not block a local override).
#                             The clone only ever goes into a path that does
#                             not exist yet or is an empty directory; an
#                             existing non-empty directory without
#                             ./appmgr_build is refused, never deleted.
#   APPMGR_BUILD_CMD            the build tool's entry point, run from inside
#                             APPMGR_BUILD_DIR (default ./appmgr_build).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
XR_DIR="$REPO/device/xr"
DOCKERFILE="$XR_DIR/Dockerfile"
ENTRYPOINT="$XR_DIR/entrypoint.sh"

OUT="$XR_DIR/out"
DRY_RUN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:?--out needs a value}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help)
      echo "usage: $0 [--out DIR] [--dry-run]"
      exit 0
      ;;
    -*) echo "!! unknown option: $1" >&2; exit 2 ;;
    *) echo "!! unexpected argument: $1" >&2; exit 2 ;;
  esac
done

IMAGE_TAG="${IMAGE_TAG:-iris-xr:amd64}"
RPM_NAME="${RPM_NAME:-iris-xr}"
APPMGR_RELEASE="${APPMGR_RELEASE:-ThinXR_7.3.15}"
APPMGR_BUILD_REPO_URL="${APPMGR_BUILD_REPO_URL:-https://github.com/ios-xr/xr-appmgr-build.git}"
APPMGR_BUILD_COMMIT="${APPMGR_BUILD_COMMIT:-37d79607}"
APPMGR_BUILD_DIR="${APPMGR_BUILD_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/iris/xr-appmgr-build}"
APPMGR_BUILD_CMD="${APPMGR_BUILD_CMD:-./appmgr_build}"
PKG_VERSION="$(cat "$REPO/VERSION" 2>/dev/null || echo 0.0.0)"

[ -r "$DOCKERFILE" ] || { echo "!! missing $DOCKERFILE (device/xr/Dockerfile -- build Task 1 first)" >&2; exit 1; }
[ -r "$ENTRYPOINT" ] || { echo "!! missing $ENTRYPOINT (device/xr/entrypoint.sh -- build Task 1 first)" >&2; exit 1; }

# Staleness guard (issue #72, same mechanism device/iox/build.sh guards
# against): this build bakes in device/agent AS IT SITS IN THIS CHECKOUT
# ($REPO) -- a worktree that has fallen behind main under device/agent,
# device/verify_image.py or device/xr ships an older agent with nothing in
# the built RPM saying so. See tools/agent-source-freshness.sh. Sourcing is
# ITSELF best-effort -- a checkout old enough to predate this guard has no
# tools/agent-source-freshness.sh to source, and that must degrade to "the
# check is skipped," never to a raw "No such file or directory" abort.
if [ -r "$REPO/tools/agent-source-freshness.sh" ]; then
  # shellcheck source=tools/agent-source-freshness.sh
  . "$REPO/tools/agent-source-freshness.sh"
  iris_check_agent_freshness "$REPO" "device/agent device/verify_image.py device/xr" \
    || exit 1
fi

CTX="$(mktemp -d)"
trap 'rm -rf "$CTX"' EXIT
mkdir -p "$CTX/agent" "$CTX/agent_bin" "$OUT"

echo ">> staging pinned catalog cert"
if [ -n "${CATALOG_PEM:-}" ]; then
  cp "$CATALOG_PEM" "$CTX/iris-catalog.pem"
else
  # Fetch with --insecure (-k) because the catalog server is self-signed and
  # cannot be verified by a public CA. The fingerprint pin below is the sole
  # trust mechanism.
  : "${CATALOG_PEM_URL:?set CATALOG_PEM_URL or provide CATALOG_PEM}"
  : "${CATALOG_PEM_FINGERPRINT:?set CATALOG_PEM_FINGERPRINT to the expected SHA256 fingerprint of the catalog cert (openssl x509 -noout -fingerprint -sha256 -in iris-catalog.pem)}"
  curl -fsS --insecure "$CATALOG_PEM_URL" -o "$CTX/iris-catalog.pem"
  grep -q "BEGIN CERTIFICATE" "$CTX/iris-catalog.pem" || { echo "!! bad cert from $CATALOG_PEM_URL"; exit 1; }
  # openssl emits: "SHA256 Fingerprint=AA:BB:..."; operators may supply
  # "SHA256:AA:BB:..." or bare "AA:BB:...". Normalize both sides to
  # uppercase bare hex before comparing.
  got="$(openssl x509 -noout -fingerprint -sha256 -in "$CTX/iris-catalog.pem" \
         | sed 's/.*Fingerprint=//' | tr -d ' \r' | tr '[:lower:]' '[:upper:]')"
  want="$(echo "$CATALOG_PEM_FINGERPRINT" \
          | sed 's/^[Ss][Hh][Aa]256[: ]*[Ff][Ii][Nn][Gg][Ee][Rr][Pp][Rr][Ii][Nn][Tt]=//
                 s/^[Ss][Hh][Aa]256://' \
          | tr -d ' \r' | tr '[:lower:]' '[:upper:]')"
  if [ "$got" != "$want" ]; then
    echo "!! catalog cert fingerprint mismatch" >&2
    echo "   expected: $CATALOG_PEM_FINGERPRINT" >&2
    echo "   got:      $got" >&2
    exit 1
  fi
  echo ">> cert fingerprint verified: $got"
fi
grep -q "BEGIN CERTIFICATE" "$CTX/iris-catalog.pem" || { echo "!! bad cert: no certificate block found" >&2; exit 1; }
# CATALOG_PEM discipline (device/iox/build.sh enforces the same): bake ONLY
# the certificate block into the image. A combined cert+key file (the shape
# server/setup_status.py reads for IRIS_CERT, server-side) must never be
# handed to CATALOG_PEM -- refuse outright rather than silently shipping
# private key material to devices.
if grep -q "BEGIN.*PRIVATE KEY" "$CTX/iris-catalog.pem"; then
  cat >&2 <<EOF
!! CATALOG_PEM contains a PRIVATE KEY block -- refusing to build.
   CATALOG_PEM must be the certificate block ONLY (the public cert IRIS
   hands to devices at onboard time), never a combined cert+key file such
   as the one IRIS_CERT points at server-side. Extract just the
   certificate, e.g.:
     openssl x509 -in combined.pem -out iris-catalog.pem
EOF
  exit 1
fi

IMAGE_TAR_NAME="${RPM_NAME}.tar.gz"

if [ "$DRY_RUN" -eq 1 ]; then
  cat <<PLAN
>> [dry-run] would stage x86_64 aria2c + agent python + Dockerfile/entrypoint.sh into a build context
>> [dry-run] would run: docker build --pull --platform linux/amd64 -t $IMAGE_TAG <context>
>> [dry-run] would reuse an existing xr-appmgr-build clone at $APPMGR_BUILD_DIR
   or clone $APPMGR_BUILD_REPO_URL @ $APPMGR_BUILD_COMMIT there (only into a
   missing or empty directory -- an existing non-empty one is refused, never deleted)
>> [dry-run] would run: docker save $IMAGE_TAG -o $APPMGR_BUILD_DIR/$IMAGE_TAR_NAME
>> [dry-run] would clear $APPMGR_BUILD_DIR/RPMS/ and write $APPMGR_BUILD_DIR/build.yaml:
packages:
- name: "$RPM_NAME"
  release: "$APPMGR_RELEASE"
  target-release: "$APPMGR_RELEASE"
  version: "$PKG_VERSION"
  sources:
    - name: $RPM_NAME
      file: iris-src/$IMAGE_TAR_NAME

>> [dry-run] would run: (cd $APPMGR_BUILD_DIR && $APPMGR_BUILD_CMD -b build.yaml)
>> [dry-run] would verify an RPM landed under $APPMGR_BUILD_DIR/RPMS/*.rpm -- its own
   "Done building" message is not trusted, on either exit code or output --
   and copy that RPM to $OUT/iris-xr.rpm (via $OUT/.iris-xr.rpm.tmp + mv, so a
   served path is never read half-written)
PLAN
  exit 0
fi

echo ">> staging x86_64 aria2c"
SUMS="$REPO/tools/aria2c.sha256"
DELIVERABLE="$REPO/deliverables/aria2c-x86_64"
LOCAL_BUNDLE="$REPO/artifacts/iris-agent.tgz"

verify_aria2_checksum() {
  # $1 = candidate binary path, $2 = description for error output
  local candidate="$1" desc="$2" expected actual
  [ -f "$SUMS" ] || { echo "!! missing $SUMS -- cannot verify $desc" >&2; exit 1; }
  expected="$(awk '$2 == "x86_64" { print $1 }' "$SUMS")"
  [ -n "$expected" ] || { echo "!! no checksum recorded for x86_64 in $SUMS" >&2; exit 1; }
  actual="$( (shasum -a 256 "$candidate" 2>/dev/null || sha256sum "$candidate") | awk '{print $1}')"
  if [ "$actual" != "$expected" ]; then
    cat >&2 <<EOF
!! CHECKSUM MISMATCH for $desc (x86_64) -- refusing to build.
   expected: $expected   (tools/aria2c.sha256)
   actual:   $actual     ($candidate)

This usually means the deliverable is stale, or a newer client was produced
and tools/aria2c.sha256 has not been updated to adopt it. Do not "fix" this
by editing the checksum unless you intend to adopt that exact binary.
EOF
    exit 1
  fi
}

if [ -n "${ARIA2C_BIN:-}" ]; then
  cp "$ARIA2C_BIN" "$CTX/agent_bin/aria2c"
elif [ -f "$LOCAL_BUNDLE" ]; then
  tar xzf "$LOCAL_BUNDLE" -C "$CTX/agent_bin" aria2c
  verify_aria2_checksum "$CTX/agent_bin/aria2c" "$LOCAL_BUNDLE (extracted aria2c)"
elif [ -f "$DELIVERABLE" ]; then
  verify_aria2_checksum "$DELIVERABLE" "$DELIVERABLE"
  cp "$DELIVERABLE" "$CTX/agent_bin/aria2c"
else
  cat >&2 <<EOF
!! no aria2c available for x86_64.

This build does not download aria2c. Provide one of:
  1. ARIA2C_BIN=/path/to/aria2c-x86_64  (architecture-matched binary)
  2. $DELIVERABLE
     (handed in and verified against tools/aria2c.sha256 -- see
     tools/get-aria2c.sh amd64)
EOF
  exit 1
fi
chmod +x "$CTX/agent_bin/aria2c"

echo ">> staging agent python (incl. cli_ssh.py) + peer-transfer hook + VERSION"
cp "$REPO"/device/agent/*.py "$CTX/agent/"
cp "$REPO/device/agent/peer-transfer-hook.sh" "$CTX/agent/" \
  || { echo "!! missing device/agent/peer-transfer-hook.sh (the aria2"
       echo "   --on-bt-download-complete program the Dockerfile COPYs)"; exit 1; } >&2
cp "$REPO"/device/verify_image.py "$CTX/agent/verify_image.py"   # lives in device/, agent imports it
cp "$REPO/VERSION" "$CTX/agent/VERSION"
cp "$DOCKERFILE" "$ENTRYPOINT" "$CTX/"

echo ">> docker build ($IMAGE_TAG)"
# --pull for the same reason device/iox/build.sh gives: a floating base tag
# is only as current as the build host's cache (issue #13). IRIS_NO_PULL=1
# keeps the cached base for an A/B build.
PULL_FLAG="--pull"; [ -n "${IRIS_NO_PULL:-}" ] && PULL_FLAG="--pull=false"
docker build "$PULL_FLAG" --platform linux/amd64 -t "$IMAGE_TAG" "$CTX"

echo ">> resolving ios-xr/xr-appmgr-build"
mkdir -p "$(dirname "$APPMGR_BUILD_DIR")"
if [ ! -x "$APPMGR_BUILD_DIR/appmgr_build" ]; then
  # Never delete a path taken from the environment: APPMGR_BUILD_DIR is
  # operator-overridable, and a typo (a parent directory, a clone whose
  # script lost its exec bit) must not cost the operator its contents.
  if [ -e "$APPMGR_BUILD_DIR" ]; then
    if [ ! -d "$APPMGR_BUILD_DIR" ] || [ -n "$(ls -A "$APPMGR_BUILD_DIR" 2>/dev/null)" ]; then
      cat >&2 <<EOF
!! APPMGR_BUILD_DIR=$APPMGR_BUILD_DIR exists but holds no executable ./appmgr_build,
   and it is not an empty directory -- refusing to clone over it. Point
   APPMGR_BUILD_DIR at a fresh path (or an existing xr-appmgr-build clone),
   or remove that directory yourself if it is disposable.
EOF
      exit 1
    fi
  fi
  echo ">> cloning $APPMGR_BUILD_REPO_URL @ $APPMGR_BUILD_COMMIT -> $APPMGR_BUILD_DIR"
  git clone "$APPMGR_BUILD_REPO_URL" "$APPMGR_BUILD_DIR"
  git -C "$APPMGR_BUILD_DIR" checkout "$APPMGR_BUILD_COMMIT"
else
  echo ">> reusing existing xr-appmgr-build clone/tool at $APPMGR_BUILD_DIR"
  if [ -d "$APPMGR_BUILD_DIR/.git" ]; then
    head="$(git -C "$APPMGR_BUILD_DIR" rev-parse HEAD 2>/dev/null || echo "")"
    case "$head" in
      "$APPMGR_BUILD_COMMIT"*|"") : ;;
      *) echo "!! warning: $APPMGR_BUILD_DIR is at $head, not the pinned $APPMGR_BUILD_COMMIT -- reusing anyway (set APPMGR_BUILD_DIR to a fresh path to reclone)" >&2 ;;
    esac
  fi
fi

echo ">> docker save $IMAGE_TAG -> $APPMGR_BUILD_DIR/iris-src/$IMAGE_TAR_NAME"
mkdir -p "$APPMGR_BUILD_DIR/iris-src/config" "$APPMGR_BUILD_DIR/iris-src/data"
docker save "$IMAGE_TAG" | gzip > "$APPMGR_BUILD_DIR/iris-src/$IMAGE_TAR_NAME"

BUILD_YAML="$APPMGR_BUILD_DIR/build.yaml"
cat > "$BUILD_YAML" <<EOF
# Written by tools/build-xr-package.sh -- regenerated on every build, do not
# hand-edit. Schema is the one hardware-proven by the 2026-08-28 spike
# (probe-build.yaml): a top-level packages list; the source name MUST equal
# the tar.gz file's stem; paths are relative to the xr-appmgr-build root.
packages:
- name: "$RPM_NAME"
  release: "$APPMGR_RELEASE"
  target-release: "$APPMGR_RELEASE"
  version: "$PKG_VERSION"
  sources:
    - name: $RPM_NAME
      file: iris-src/$IMAGE_TAR_NAME
  config-dir:
    - dir: iris-src/config
  data-dir:
    - dir: iris-src/data
  copy_hostname: false
  copy_ems_cert: false
EOF
echo ">> wrote $BUILD_YAML"

# Clear any RPM left by a previous (possibly failed) run FIRST, so the
# presence check below can only ever be satisfied by an RPM this run
# actually produced -- a stale artifact must never read as success.
# Recreated immediately (empty, not absent): under `set -euo pipefail`,
# `find` on a MISSING directory exits 1, and since the pipeline below sits
# on the RHS of a plain assignment (not an `if` condition), pipefail+set -e
# would kill the script right there -- BEFORE the honest "did not produce
# an RPM" diagnostic + log tail ever print. That is exactly the scenario
# this script exists to guard (every failure mode leaves RPMS/ absent,
# since it's only ever recreated by a successful RPM build). An empty
# existing directory makes `find` exit 0 with no matches, so the
# `[ -z "$RPM_FILE" ]` check below is what actually decides success.
rm -rf "$APPMGR_BUILD_DIR/RPMS"
mkdir -p "$APPMGR_BUILD_DIR/RPMS"

LOG="$APPMGR_BUILD_DIR/.iris-appmgr-build.log"
echo ">> running $APPMGR_BUILD_CMD -b build.yaml in $APPMGR_BUILD_DIR"
( cd "$APPMGR_BUILD_DIR" && $APPMGR_BUILD_CMD -b build.yaml ) >"$LOG" 2>&1 || true
cat "$LOG"

# xr-appmgr-build prints "Done building" EVEN ON FAILURE (lab-confirmed on
# 192.0.2.10) -- neither that message nor a zero exit code above is
# treated as success. The only trustworthy signal is an RPM actually
# sitting in RPMS/.
RPM_FILE="$(find "$APPMGR_BUILD_DIR/RPMS" -type f -name '*.rpm' 2>/dev/null | sort | tail -n1)"
if [ -z "$RPM_FILE" ] || [ ! -f "$RPM_FILE" ]; then
  cat >&2 <<EOF
!! xr-appmgr-build did not produce an RPM.
   Its "Done building" message and exit code are not proof of success (it
   prints that even on failure -- confirmed on 192.0.2.10). No file
   matched $APPMGR_BUILD_DIR/RPMS/*.rpm after the run. Last 40 lines of its
   output:
EOF
  tail -n 40 "$LOG" >&2
  exit 1
fi

echo ">> found RPM: $RPM_FILE"
# Placed atomically: --out artifacts/ is the SERVED directory, and
# device/xr-install.sh scp's artifacts/iris-xr.rpm to the router -- a copy
# in progress must never be readable as a (truncated) package.
cp "$RPM_FILE" "$OUT/.iris-xr.rpm.tmp"
mv -f "$OUT/.iris-xr.rpm.tmp" "$OUT/iris-xr.rpm"
echo ">> done: $OUT/iris-xr.rpm"
ls -la "$OUT/iris-xr.rpm"
