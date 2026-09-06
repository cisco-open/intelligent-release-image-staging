#!/bin/sh

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Functional probe of a container entrypoint's REAL aria2c supervisor
# functions (proc_stat / aria2_alive / stop_aria2c / start_aria2c, extracted
# from the script under test, not re-implemented) with a stub aria2c, under
# whichever POSIX shell runs this file: dash on the host and in the Debian
# images, busybox ash when run inside an Alpine container, bash for the XR
# fixture that drives the entrypoint through `bash`.
#
#   aria2_supervision_probe.sh <entrypoint.sh> [scratch-dir]
#
# Prints one line per check and "PROBE OK" at the end; any FAIL line exits 1.
# Driven by device/tests/test_aria2_supervision.bats.
set -eu

EP="$1"
T="${2:-/tmp}"
STUB="$T/aria2c-stub.$$"
printf '#!/bin/sh\nexec sleep 300\n' > "$STUB"
chmod +x "$STUB"
trap 'rm -f "$STUB"' EXIT

eval "$(awk '/^(proc_stat|aria2_alive|stop_aria2c|start_aria2c)\(\)/,/^}/' "$EP")"
ARIA2="$STUB"; RPC_PORT=6800; MAX_PEERS=10; MAX_CONCURRENT=100
STAGE_DIR="$T"; HOOK=""; IRIS_LOG=off; LOG_FILE="$T/aria2c.log"
ARIA2_CONF="$T/aria2.conf"
TRACKER_CA="$T/iris-catalog.pem"
ARIA2_PID=""; ARIA2_START=""

fail() { echo "FAIL: $*"; exit 1; }
now() { date +%s; }
echo "probe: $EP under pid $$"

# 1. launch -> the recorded child is alive and carries a starttime
start_aria2c s1 >/dev/null
p1=$ARIA2_PID
[ -n "$ARIA2_START" ] || fail "no starttime recorded"
aria2_alive || fail "freshly launched child not alive"
echo "1 launched pid=$p1 starttime=$ARIA2_START alive=yes"

# 2. crash: kill -9 -> not alive at once (zombie until reaped, then gone);
#    builtins only in the poll, so the zombie is observed if the timing allows
kill -9 "$p1"
i=0; while aria2_alive && [ "$i" -lt 200000 ]; do i=$((i + 1)); done
aria2_alive && fail "killed child still reported alive"
if proc_stat "$p1"; then st="$PROC_STATE"; else st=gone; fi
echo "2 after kill -9: alive=no state=$st (polls=$i)"
if [ "$st" = Z ]; then
  if kill -0 "$p1" 2>/dev/null; then
    echo "2 kill -0 on the zombie: success -- which is why kill -0 is not liveness"
  else
    echo "2 kill -0 on the zombie: failure"
  fi
fi
t0=$(now); stop_aria2c; t1=$(now)
[ -d "/proc/$p1" ] && fail "/proc/$p1 still present after stop_aria2c (not reaped)"
[ -z "$ARIA2_PID" ] || fail "ARIA2_PID not cleared"
echo "2 stop_aria2c reaped pid $p1 in $((t1 - t0))s"

# 3. relaunch -> a new, live pid
start_aria2c s2 >/dev/null
p2=$ARIA2_PID
[ "$p2" != "$p1" ] || fail "relaunch reused the pid"
aria2_alive || fail "relaunched child not alive"
echo "3 relaunched pid=$p2 alive=yes"

# 4. unhealthy-but-alive stand-in: a STOPPED child is still alive (state T),
#    and stop_aria2c replaces it via TERM+CONT well inside the KILL bound
kill -STOP "$p2"
proc_stat "$p2" || fail "stopped child vanished"
aria2_alive || fail "stopped child not reported alive"
echo "4 after STOP: state=$PROC_STATE alive=yes"
t0=$(now); stop_aria2c; t1=$(now)
[ -d "/proc/$p2" ] && fail "stopped child survived stop_aria2c"
[ $((t1 - t0)) -le 3 ] || fail "stopped child took $((t1 - t0))s (TERM+CONT should beat the 5s KILL bound)"
echo "4 stopped child gone and reaped in $((t1 - t0))s"

# 5. recycled-PID guard: a live process that is not the one we started (its
#    starttime differs) is neither alive to us, nor signalled, nor waited on
#    (a wait on a running re-parented process would stall the supervisor)
sleep 300 </dev/null >/dev/null 2>&1 &
other=$!
ARIA2_PID=$other; ARIA2_START=bogus
aria2_alive && fail "foreign pid reported alive"
t0=$(now); stop_aria2c; t1=$(now)
[ -d "/proc/$other" ] || fail "stop_aria2c signalled a pid that is not ours"
[ $((t1 - t0)) -le 2 ] || fail "stop_aria2c blocked ${t1}-${t0}s on a pid that is not ours"
echo "5 foreign pid $other with a different starttime: alive=no, untouched, no wait ($((t1 - t0))s)"
kill "$other" 2>/dev/null || true
wait "$other" 2>/dev/null || true

# 6. plain TERM path on a healthy child: gone and reaped inside the bound
start_aria2c s3 >/dev/null
p3=$ARIA2_PID
t0=$(now); stop_aria2c; t1=$(now)
[ -d "/proc/$p3" ] && fail "TERMed child still present"
echo "6 TERM: pid $p3 gone and reaped in $((t1 - t0))s"

# 7. a launch that fails outright (no binary) neither hangs nor aborts the
#    caller under set -eu, and is simply not alive on the next look
ARIA2="$T/no-such-aria2c.$$"
start_aria2c s4 >/dev/null
p4=$ARIA2_PID
sleep 1
aria2_alive && fail "missing binary reported alive"
stop_aria2c
echo "7 missing binary: pid $p4 not alive, stop_aria2c clean, script still running"

echo "PROBE OK"
