#!/bin/sh

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# aria2 --on-bt-download-complete hook: capture EXACT per-peer received bytes.
#
# WHY THIS EXISTS
#   aria2-next 2.5.6 keeps a cumulative per-peer session counter for the life of
#   the download (peer->getSessionDownloadLength() / getSessionUploadLength(),
#   surfaced by aria2.getPeers as "downloaded"/"uploaded"). This hook READS those
#   counters ONCE. It does not integrate rates over samples -- that is the
#   discredited machinery removed in release 2026.08.20, and nothing here revives
#   it. What lands in the report is the client's own tally, not an estimate.
#
# WHY --on-bt-download-complete AND NOT --on-download-complete
#   DefaultPieceStorage.cc:502 fires the BT hook the instant the last piece lands
#   and the very next statement is group->enableSeedOnly(): the peers that just
#   fed us are still connected, so this is the one instant when the knowledge is
#   complete. RequestGroupMan.cc:270 fires the generic hook from executeStopHook,
#   i.e. after seeding ENDS, when those peers are long gone.
#
# HOW aria2 INVOKES US (util.cc:2320-2342)
#   execlp(command, command, gid, numFiles, firstFilename, NULL) -- a bare
#   execlp: no /bin/sh, no word splitting, no quoting anywhere on this path (so
#   the `guestshell run` quoting trap does not apply). We therefore get exactly:
#     $1 = GID of the completed download   (feeds aria2.getPeers directly)
#     $2 = number of files
#     $3 = absolute path of the first file (the staged image -- self-keys $OUT)
#   The parent never waitpid()s us and SIGCHLD is SIG_IGN
#   (MultiUrlRequestInfo.cc:382), so we cannot block aria2 or leak a zombie.
#   In daemon mode stdout/stderr are /dev/null (daemon.cc:69-73): nothing we
#   print is ever visible, which is why every failure path here is a silent
#   `exit 0` and the agent treats an absent snapshot as an ordinary outcome.
#
# CONTRACT WITH THE AGENT
#   Writes "$3.peers.json" atomically (temp + mv) into the stage dir, which is
#   guest-writable by construction. The agent's stale-artifact sweep
#   (iris_agent purge_others) KEEPS the sidecar of every image still assigned
#   and removes only those of images that have left the set, so a snapshot
#   waiting for its own image's completion tick survives the sweep. That
#   one-shot EEM tick folds it into the terminal report and deletes it -- see
#   telemetry_report.parse_peer_transfer_snapshot() for the reader.
#   The RPC response body is embedded VERBATIM: this script parses no JSON, so
#   there is nothing here to get wrong about numbers. Validation is the agent's.
#
# ENVIRONMENT (exported by the launcher -- guestshell-start.sh / entrypoint.sh)
#   IRIS_RPC_SECRET or RPC_SECRET  aria2's --rpc-secret, INHERITED rather than
#       re-read from a file: a conf file and the running daemon can disagree,
#       and that skew was the 2026-08-20 silent-device incident. An empty value
#       legitimately means the daemon is on the "iris" placeholder.
#   IRIS_RPC_PORT or RPC_PORT      aria2's --rpc-listen-port (default 6800).
#   No new secret exposure: the value is already on aria2c's own argv.
#
# POSIX sh only (/bin/sh is dash in the IOx container, bash in Guest Shell) and
# no python3: interpreter start-up is the one thing that would widen the race
# against peers disconnecting, and both runtimes are CPU-capped.

GID="$1"
FILE="$3"
[ -n "$GID" ] || exit 0
[ -n "$FILE" ] || exit 0

PORT="${IRIS_RPC_PORT:-${RPC_PORT:-6800}}"
SECRET="${IRIS_RPC_SECRET:-${RPC_SECRET:-iris}}"
[ -n "$SECRET" ] || SECRET=iris

# Capture instant, from the hook itself. Deliberately not the agent's ingest
# time (minutes later, on the next EEM tick) and not the report time.
NOW=`date +%s 2>/dev/null` || NOW=""
case "$NOW" in
  ""|*[!0-9]*) exit 0 ;;   # no usable clock -> no snapshot, never a fake one
esac

# One HTTP round trip, batched (HttpServerBodyCommand.cc:291). getPeers keys are
# opt-in in our build (patches/0001-getpeers-keys-filter.patch, requested_key()
# at RpcMethodImpl.cc:754), so downloaded/uploaded/seeder must be asked for by
# name; the agent's own sampler deliberately does NOT ask for them -- the
# sampled path stays byte-free. "seeder" records whether that peer held a
# COMPLETE copy (RpcMethodImpl.cc:1166 emits peer->isSeeder()) -- in a wave that
# is every device that finished early, so it does NOT identify the origin. The
# device cannot tell the origin from another device by itself and does not try:
# that split is the server's, which knows the service:seeder principal.
REQ='[{"jsonrpc":"2.0","id":"peers","method":"aria2.getPeers","params":["token:'"$SECRET"'","'"$GID"'",["ip","port","downloaded","uploaded","seeder"]]},{"jsonrpc":"2.0","id":"session","method":"aria2.getSessionInfo","params":["token:'"$SECRET"'"]}]'

# SIZE bound on the answer, alongside the time bounds. It belongs here and not
# only on the reader: the response is embedded VERBATIM below, so a reader-only
# cap writes an oversized body to the flash-constrained stage dir first and
# rejects it second (telemetry_report.PEER_TRANSFER_MAX_BYTES = 1 MiB) -- backwards
# on a device whose flash is the scarce resource. MAX_BODY leaves room for the
# envelope printf wraps around the body and still lands under that reader cap,
# so a snapshot this hook writes is always one the agent can read.
MAX_BODY=1000000

BODY=`curl -s -f --connect-timeout 1 --max-time 2 --max-filesize "$MAX_BODY" \
  -H 'Content-Type: application/json' --data-binary "$REQ" \
  "http://127.0.0.1:$PORT/jsonrpc" 2>/dev/null` || exit 0

# Time-bounded for the same reason: aria2 is local and already holds the answer
# in memory, so a stall means something is wrong, and a bounded delay before
# enableSeedOnly() is the worst this can ever cost a transfer. Over any bound
# curl exits non-zero and the `|| exit 0` drops the snapshot -- no file, no
# partial write, no output, like every other failure path here.

# Second size check, on what is about to be WRITTEN. curl enforces
# --max-filesize only where the length is declared up front; aria2's RPC does
# declare it (HttpServerBodyCommand builds the whole body before sending), but
# an answer from something that is not aria2 -- a captive portal, a proxy on a
# hijacked port -- may arrive chunked, and the bound has to hold whoever
# answered. ${#BODY} is POSIX and costs nothing: the body is already in memory.
[ "${#BODY}" -le "$MAX_BODY" ] || exit 0

case "$BODY" in
  *'"result"'*) ;;
  *) exit 0 ;;             # error object, empty body, captive garbage -> drop
esac

OUT="$FILE.peers.json"
TMP="$OUT.tmp.$$"
# GID is hex from aria2 and needs no escaping; the file path is deliberately NOT
# echoed into the document (a path is not guaranteed JSON-safe and the reader
# already knows it -- it opened the file by that name).
printf '{"schema":1,"source":"aria2_session_counters","captured_at":%s,"gid":"%s","rpc":%s}\n' \
  "$NOW" "$GID" "$BODY" > "$TMP" 2>/dev/null \
  || { rm -f "$TMP" 2>/dev/null; exit 0; }

# Atomic publish: the agent must never read a half-written document. A rename
# inside the stage dir is atomic; cp/> onto $OUT would not be.
mv -f "$TMP" "$OUT" 2>/dev/null || rm -f "$TMP" 2>/dev/null

exit 0
