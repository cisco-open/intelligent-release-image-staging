#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Behaviour of device/agent/peer-transfer-hook.sh itself, run as aria2 runs it:
# a bare execlp with (gid, numFiles, firstFilename) and no shell in between
# (util.cc:2320-2342). The wiring that gets it onto a device is a different
# file -- test_peer_transfer_hook_wiring.bats.
#
# What these tests defend:
#   * the snapshot the agent reads is bounded BEFORE it touches flash. The hook
#     embeds the RPC response verbatim, so a size bound on the reader alone
#     writes the oversized body first and rejects it second, on the one
#     resource a Catalyst guest has least of.
#   * every failure path stays a silent `exit 0` with nothing left behind.
#     aria2 does not waitpid() us and stdout/stderr are /dev/null in daemon
#     mode (daemon.cc:69-73), so a noisy failure is an invisible failure that
#     leaves junk in the stage dir.

setup() {
  REPO="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  HOOK="$REPO/device/agent/peer-transfer-hook.sh"
  TMPD="$BATS_TEST_TMPDIR/w"
  STAGE="$TMPD/stage"
  mkdir -p "$TMPD/bin" "$STAGE"
  FILE="$STAGE/cat9k_iosxe.26.01.01.SPA.bin"
  : > "$FILE"
  # A curl stub that records its own argv and answers with a valid batch reply.
  cat > "$TMPD/bin/curl" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" > "$TMPD/curl-argv.txt"
printf '[{"id":"peers","result":[{"ip":"10.0.0.2","port":"6881","downloaded":"200","uploaded":"0","seeder":"false"}]}]'
EOF
  chmod +x "$TMPD/bin/curl"
}

run_hook() {
  PATH="$TMPD/bin:$PATH" IRIS_RPC_SECRET=s3cret IRIS_RPC_PORT=6800 \
    run sh "$HOOK" 0f1e2d3c 1 "$FILE"
}

# ---------------------------------------------------------------------------
# The size bound
# ---------------------------------------------------------------------------

@test "curl is given a size bound, not just time bounds" {
  run_hook
  [ "$status" -eq 0 ]
  grep -qx -- '--max-filesize' "$TMPD/curl-argv.txt"
  grep -qx -- '1000000' "$TMPD/curl-argv.txt"
  grep -qx -- '--connect-timeout' "$TMPD/curl-argv.txt"
  grep -qx -- '--max-time' "$TMPD/curl-argv.txt"
}

@test "the size bound leaves room for the envelope under the reader's cap" {
  # telemetry_report.PEER_TRANSFER_MAX_BYTES refuses a sidecar over 1 MiB. The hook
  # wraps the body in a fixed envelope, so the bound on the BODY has to sit
  # below that cap by at least the envelope -- otherwise the hook can write a
  # file the agent will always throw away.
  limit="$(sed -n 's/^MAX_BODY=\([0-9]*\)$/\1/p' "$HOOK")"
  [ -n "$limit" ]
  cap="$(python3 - "$REPO" <<'PY'
import re, sys
src = open(sys.argv[1] + "/device/agent/telemetry_report.py").read()
m = re.search(r"PEER_TRANSFER_MAX_BYTES\s*=\s*(.+?)\s*#", src)
print(eval(m.group(1)))
PY
)"
  [ "$limit" -lt "$cap" ]
  [ "$((cap - limit))" -gt 1024 ]
}

@test "an oversized body never lands in the stage dir" {
  # Real curl exits 63 on --max-filesize and writes no body. Nothing may be
  # left for the agent to read, and nothing may be left half-written.
  printf '#!/usr/bin/env bash\nexit 63\n' > "$TMPD/bin/curl"
  chmod +x "$TMPD/bin/curl"
  run_hook
  [ "$status" -eq 0 ]
  [ -z "$output" ]
  [ ! -e "$FILE.peers.json" ]
  [ "$(find "$STAGE" -name '*.peers.json*' | wc -l | tr -d ' ')" -eq 0 ]
}

@test "an oversized body is refused even when curl could not bound it" {
  # curl enforces --max-filesize only where the length is declared up front. A
  # chunked answer from something that is not aria2 slips past it, so the hook
  # checks what it is about to write as well -- the file has to be bounded
  # whoever answered.
  cat > "$TMPD/bin/curl" <<'EOF'
#!/usr/bin/env bash
printf '[{"id":"peers","result":['
head -c 1200000 /dev/zero | tr '\0' 'A'
printf ']}]'
EOF
  chmod +x "$TMPD/bin/curl"
  run_hook
  [ "$status" -eq 0 ]
  [ -z "$output" ]
  [ ! -e "$FILE.peers.json" ]
  [ "$(find "$STAGE" -name '*.peers.json*' | wc -l | tr -d ' ')" -eq 0 ]
}

# ---------------------------------------------------------------------------
# Everything else about the write stays as it was
# ---------------------------------------------------------------------------

@test "a good response is published as one atomic snapshot" {
  run_hook
  [ "$status" -eq 0 ]
  [ -f "$FILE.peers.json" ]
  grep -q '"source":"aria2_session_counters"' "$FILE.peers.json"
  grep -q '"gid":"0f1e2d3c"' "$FILE.peers.json"
  grep -q '"downloaded":"200"' "$FILE.peers.json"
  # no temp left behind: the reader must never see a half-written document
  [ "$(find "$STAGE" -name '*.tmp.*' | wc -l | tr -d ' ')" -eq 0 ]
}

@test "an error object is dropped rather than stored as a measurement" {
  printf '#!/usr/bin/env bash\nprintf %s '"'"'[{"id":"peers","error":{"code":1}}]'"'"'\n' \
    > "$TMPD/bin/curl"
  chmod +x "$TMPD/bin/curl"
  run_hook
  [ "$status" -eq 0 ]
  [ -z "$output" ]
  [ ! -e "$FILE.peers.json" ]
}

@test "no clock means no snapshot, never a fabricated timestamp" {
  printf '#!/usr/bin/env bash\nexit 1\n' > "$TMPD/bin/date"
  chmod +x "$TMPD/bin/date"
  run_hook
  [ "$status" -eq 0 ]
  [ ! -e "$FILE.peers.json" ]
}

@test "the hook claims no ability to identify the origin" {
  # aria2's seeder flag means "holds a complete copy" (RpcMethodImpl.cc:1166),
  # which in a wave is every device that finished early. A comment claiming it
  # separates the origin is how a peer share ends up counting the server.
  run grep -q 'tells the origin apart' "$HOOK"
  [ "$status" -ne 0 ]
  grep -q 'service:seeder' "$HOOK"
}
