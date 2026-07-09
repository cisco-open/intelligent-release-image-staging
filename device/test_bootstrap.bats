#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# bootstrap.sh must reconcile aria2c's RPC secret with the one the agent fetched
# on its first token-refresh. The installer bakes rpc-secret EMPTY; the agent
# writes the real value into iris-agent.conf. If bootstrap does not sync the
# rpc-secret file from the conf (and bounce a stale aria2c), aria2c runs with the
# wrong secret and the agent's addTorrent fails — the device never downloads.

setup() {
  TMP="$(mktemp -d)"
  SRC="$TMP/guest-share"; STAGE="$SRC/iris"
  mkdir -p "$STAGE"
  # stub guestshell-start so bootstrap never launches a real aria2c
  printf '#!/usr/bin/env bash\necho started >> "%s/gss.log"\n' "$TMP" > "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  # stub pgrep (aria2c "not running") + pkill (record the bounce) on PATH
  BIN="$TMP/bin"; mkdir -p "$BIN"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$BIN/pgrep"
  printf '#!/usr/bin/env bash\necho "$@" >> "%s/pkill.log"\n' "$TMP" > "$BIN/pkill"
  chmod +x "$BIN/pgrep" "$BIN/pkill"
}

teardown() { rm -rf "$TMP"; }

@test "bootstrap syncs rpc-secret from conf and bounces aria2c when it changed" {
  printf 'rpc_secret = REALSECRET123\nrpc_port = 6800\n' > "$STAGE/iris-agent.conf"
  printf '\n' > "$STAGE/rpc-secret"   # baked empty
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  # the file aria2c reads now holds the agent's real secret
  [ "$(tr -d '[:space:]' < "$STAGE/rpc-secret")" = "REALSECRET123" ]
  # aria2c was bounced so it relaunches with the new secret
  [ -f "$TMP/pkill.log" ]
}

@test "bootstrap does NOT bounce aria2c when rpc-secret already matches the conf" {
  printf 'rpc_secret = REALSECRET123\n' > "$STAGE/iris-agent.conf"
  printf 'REALSECRET123\n' > "$STAGE/rpc-secret"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ ! -f "$TMP/pkill.log" ]
}
