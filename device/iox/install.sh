#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Repeatable IRIS installer for Catalyst devices with IOx app hosting. It
# deploys the agent as an architecture-matched IOx Docker app (iris-arm64.tar) instead
# of into Guest Shell, but uses the SAME transport as
# device/device-install.sh: the catalog trustpoint is pasted over the
# already-authenticated SSH session FIRST, then the DEVICE fetches the
# package, the public catalog certificate and its sealed instruction
# envelope with `copy https:` from the artifact server, authenticating with
# its own enrollment credential (`ip http client username` / `password`,
# configured for the span of each copy and removed right after it). Nothing
# is pushed to the device and no service is enabled on it for onboarding's
# sake; the enrollment token never enters a URL or a process argument. The
# agent then pulls its assigned image over
# the swarm and copies it to an IOS-visible disk via a plain `copy`, such as
# sdflash: on IE-3x00 or usbflash1: on C9300. Distribute/stage
# ONLY; never install/activate/reload the IOS image.
#
# Idempotent: re-running tears down any existing iris app and redeploys (fresh
# runtime certificate, package, and token) — safe to run repeatedly.  The
# certificate is application data, not part of the signed package.
#
# Dry-run inputs:
#   DEVICE_IP VLAN SVI_IP SVI_MASK GUEST_IP DEVICE_ID STAGE_HOST
#   Router types (MANAGEMENT_TYPE=router-routed|router-nat) take, instead of
#   VLAN/SVI: VPG_NUMBER APP_IP APP_MASK APP_GATEWAY, plus NAT_INTERFACE and
#   BT_LISTEN_PORT (default 6881) for router-nat; PKG then defaults to
#   iris-amd64.tar and PKG_FS/TARGET_FS to bootflash:.
# Real execution receives its plan and credential references only through the
# inherited private controller channel; it does not invoke the legacy runner.
# Optional (defaults):
#   CATALOG_URL=https://STAGE_HOST:8443  APP_INTF=AppGigabitEthernet1/1
#   GW_IP=$SVI_IP  CPU=400  MEM=768  DISK=2048  PKG=iris-arm64.tar  PKG_FS=flash:
#   DEVICE_SSH_USER=dnac  TARGET_FS=sdflash:  IRIS_TELEMETRY=on
#   IRIS_CRT_FILE=$IRIS_ARTIFACTS_DIR/iris-catalog.pem (the public server cert)
#   IRIS_LOG=off -- device-side aria2c.log opt-in (see device/container/entrypoint.sh);
#     off by default for flash write endurance. Forwarded verbatim as an
#     -e run-opts value so the container actually sees an operator's opt-in --
#     previously this script dropped it silently and the entrypoint's own
#     default always won.
#   INSTALL_TIMEOUT=300  ACTIVATE_TIMEOUT=300  START_TIMEOUT=300  STATE_POLL=5
#     (seconds; the app-hosting lifecycle polls -- see the note by their
#     defaults below)
set -euo pipefail

DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1

# Real execution is a deliberately small recipe.  The controller owns device
# transport, command rendering, identity, verification authority, deadlines,
# and durable recovery.  The inherited socket is the recipe's only execution
# path; environment values never stand in for a controller ready frame.
if [ "$DRY" -eq 0 ]; then
  [ -n "${IRIS_IOX_CONTROL_FD:-}" ] &&
    [[ "$IRIS_IOX_CONTROL_FD" =~ ^[0-9]+$ ]] && [ "$IRIS_IOX_CONTROL_FD" -ge 3 ] || {
      echo "ERROR: real IOx install requires the private controller channel" >&2
      exit 2
    }

  PROTOCOL_BROKEN=0
  FINALIZING=0
  SIGNAL_REASON=""
  REQUEST_IN_FLIGHT=0
  PENDING_SIGNAL_REASON=""
  PENDING_SIGNAL_RC=0
  IPC_BOUND=0
  IPC_SEQUENCE=0
  IPC_ATTEMPT="" IPC_ACTION="" IPC_MODE="" IPC_RECORD=""
  IPC_TRANSACTION="" IPC_REVISION="" IPC_PHASE="" IPC_BOARD="" IPC_WRAPPER=""
  if [ "${IRIS_IOX_RECIPE_LIBRARY:-0}" = 1 ] && [ "${BASH_SOURCE[0]}" != "$0" ]; then
    [ "${IRIS_IOX_RECIPE_ACTION:-}" = uninstall ] || {
      echo "ERROR: invalid private IOx recipe library use" >&2
      return 2
    }
  else
    IRIS_IOX_RECIPE_ACTION=install
  fi
  # What the job log shows. By default a request prints nothing of the device
  # session it drove: the recipe's "[n/N]" headers, its PREREQ notices and
  # poll outcomes, the controller's per-step lines and, on a failed step, the
  # device's own '% ...' verdicts are the log. The session itself is in the
  # controller's persisted transcript. The job's IRIS_LOG opt-in (the same
  # device-logging switch the app receives, exported here by the controller
  # as on/off) turns the raw echo on for a debugging run.
  case "${IRIS_LOG:-off}" in
    [Oo][Nn]|1|[Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]) RAW_ECHO=1 ;;
    *) RAW_ECHO=0 ;;
  esac
  raw_echo() {
    [ "$RAW_ECHO" -eq 1 ] && [ -n "$1" ] && printf '%s\n' "$1"
    return 0
  }

  iox_request() {
    python3 - "$IRIS_IOX_CONTROL_FD" "$IRIS_IOX_RECIPE_ACTION" "$@" --bind \
      "$IPC_BOUND" "$IPC_SEQUENCE" "$IPC_ATTEMPT" "$IPC_ACTION" "$IPC_MODE" \
      "$IPC_RECORD" "$IPC_TRANSACTION" "$IPC_REVISION" "$IPC_BOARD" "$IPC_WRAPPER" \
      "$IPC_PHASE" <<'PY'
import base64
import json
import os
import re
import socket
import struct
import sys

MAXINT = (1 << 63) - 1
READY_KEYS = set("version type next_sequence attempt_id action teardown_mode record_id transaction_id expected_revision board_identity wrapper_sha256".split())
RESULT_KEYS = set("version type sequence ok operation_code revision phase returncode timed_out stdout_truncated stderr_truncated framing_complete error_category detail transcript_ref recipe_returncode recovery_code".split())
OUTPUT_KEYS = set("version type sequence stream index data_b64".split())
PHASES = set("observed disable_intent disabled_confirmed installing ownership_probe restore_intent restored unchanged relinquished indeterminate".split())
ERRORS = set("rejected unsupported_syntax unsupported_response silence timeout ssh_authentication host_key connection transport caf_transient readback_unknown readback_mismatch wrapper_unreadable wrapper_not_regular wrapper_oversize wrapper_copy_timeout wrapper_changed wrapper_archive_invalid wrapper_archive_limit wrapper_scan_failed journal_unreadable journal_durability stale_cas invalid_transition authority_mismatch identity_mismatch board_busy cancelled transcript_limit descendant_unreaped reconciliation_required".split())
CODES = {0, 2, 3, 4, 5, 130}
HEX32 = re.compile(r"^[0-9a-f]{32}$")
RECORD = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
BOARD = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

def integer(value, low=0, high=MAXINT):
    return type(value) is int and low <= value <= high

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result

def read_exact(peer, count):
    result = bytearray()
    while len(result) < count:
        part = peer.recv(count - len(result))
        if not part:
            raise ValueError("partial frame")
        result.extend(part)
    return bytes(result)

def receive(peer):
    size = struct.unpack("!I", read_exact(peer, 4))[0]
    if not 1 <= size <= 65536:
        raise ValueError("frame length")
    raw = read_exact(peer, size)
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=lambda unused: (_ for _ in ()).throw(ValueError("non-finite")))

def transcript_ref(value, attempt):
    if value is None:
        return True
    keys = set("id attempt_id stored_bytes observed_bytes dropped_bytes truncated".split())
    return (type(value) is dict and set(value) == keys and
            type(value["id"]) is str and HEX32.fullmatch(value["id"]) and
            value["id"] == attempt and value["attempt_id"] == attempt and
            integer(value["stored_bytes"], 1, 1048576) and
            integer(value["observed_bytes"]) and integer(value["dropped_bytes"]) and
            value["dropped_bytes"] <= value["observed_bytes"] and
            type(value["truncated"]) is bool)

def valid_ready(value):
    if type(value) is not dict or set(value) != READY_KEYS:
        return False
    common = (value["version"] == 1 and type(value["version"]) is int and
            value["type"] == "ready" and integer(value["next_sequence"], 1) and
            type(value["attempt_id"]) is str and HEX32.fullmatch(value["attempt_id"]) and
            value["action"] == action and
            type(value["board_identity"]) is str and BOARD.fullmatch(value["board_identity"]))
    if not common:
        return False
    if action == "install":
        return (value["teardown_mode"] == "none" and
                type(value["record_id"]) is str and RECORD.fullmatch(value["record_id"]) and
                type(value["transaction_id"]) is str and HEX32.fullmatch(value["transaction_id"]) and
                integer(value["expected_revision"]) and
                type(value["wrapper_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["wrapper_sha256"]) is not None)
    if action == "uninstall" and value["teardown_mode"] in ("recorded", "force_agent_only"):
        return (value["transaction_id"] is None and value["expected_revision"] is None and
                value["wrapper_sha256"] is None and
                ((value["teardown_mode"] == "recorded" and type(value["record_id"]) is str and RECORD.fullmatch(value["record_id"])) or
                 (value["teardown_mode"] == "force_agent_only" and value["record_id"] is None)))
    return False

def valid_result(value, sequence, attempt, operation, ready, previous_phase):
    if type(value) is not dict or set(value) != RESULT_KEYS:
        return False
    nullable_int = lambda item: item is None or integer(item)
    nullable_code = lambda item: item is None or item in CODES and type(item) is int
    nullable_return = lambda item: item is None or integer(item, -255, 255)
    valid = (value["version"] == 1 and type(value["version"]) is int and
            value["type"] == "result" and value["sequence"] == sequence and
            type(value["sequence"]) is int and type(value["ok"]) is bool and
            value["operation_code"] in CODES and type(value["operation_code"]) is int and
            value["ok"] == (value["operation_code"] == 0) and
            nullable_int(value["revision"]) and
            (value["phase"] is None or value["phase"] in PHASES) and
            ((value["revision"] is None) == (value["phase"] is None)) and
            nullable_return(value["returncode"]) and
            all(type(value[name]) is bool for name in ("timed_out", "stdout_truncated", "stderr_truncated", "framing_complete")) and
            (value["error_category"] is None or value["error_category"] in ERRORS) and
            type(value["detail"]) is str and len(value["detail"].encode("utf-8")) <= 1024 and
            transcript_ref(value["transcript_ref"], attempt) and
            value["recipe_returncode"] is None and nullable_code(value["recovery_code"]))
    if not valid:
        return False
    control = operation in (
        "begin_install", "deployed", "stage_instructions", "cleanup", "finish")
    if control and value["returncode"] is not None:
        return False
    if value["ok"]:
        if (value["timed_out"] or not value["framing_complete"] or
                value["error_category"] is not None or
                value["returncode"] not in (None, 0)):
            return False
        if control != (value["returncode"] is None):
            return False
    if action == "install":
        if not integer(value["revision"]) or type(value["phase"]) is not str:
            return False
        expected_revision = ready["expected_revision"]
        if value["revision"] < expected_revision:
            return False
        prior = previous_phase or "observed"
        if value["ok"]:
            if operation in ("command", "upload_wrapper", "upload_certificate"):
                if value["revision"] != expected_revision or value["phase"] != prior:
                    return False
            elif operation == "stage_instructions":
                if (value["revision"] != expected_revision + 2 or
                        value["phase"] != prior):
                    return False
            elif operation == "begin_install":
                if (value["revision"] <= expected_revision or
                        value["phase"] not in ("disabled_confirmed", "installing", "unchanged")):
                    return False
            elif operation == "deployed":
                if prior in ("disabled_confirmed", "installing"):
                    if (value["revision"] <= expected_revision or
                            value["phase"] not in ("restored", "relinquished")):
                        return False
                elif prior == "unchanged":
                    if value["phase"] != "unchanged":
                        return False
                else:
                    return False
            elif operation in ("cleanup", "finish"):
                if (value["revision"] == expected_revision and value["phase"] != prior):
                    return False
                if (value["revision"] > expected_revision and
                        value["phase"] not in ("restored", "unchanged", "relinquished", "indeterminate")):
                    return False
    return True

try:
    fd = int(sys.argv[1])
    action = sys.argv[2]
    split = sys.argv.index("--bind", 3)
    call = sys.argv[3:split]
    binding = sys.argv[split + 1:]
    if len(binding) != 11 or not call:
        raise ValueError("binding")
    operation = call[0]
    if action not in ("install", "uninstall") or operation not in ("command", "upload_wrapper", "upload_certificate", "begin_install", "deployed", "stage_instructions", "cleanup", "finish"):
        raise ValueError("operation")
    peer = socket.socket(fileno=os.dup(fd))
    if peer.family != socket.AF_UNIX or peer.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
        raise ValueError("socket")
    peer.settimeout(7200)
    ready = receive(peer)
    if not valid_ready(ready):
        raise ValueError("ready")
    if binding[0] == "0" and ready["next_sequence"] != 1:
        raise ValueError("initial sequence")
    if binding[0] == "1":
        expected = [int(binding[1]) + 1, binding[2], binding[3], binding[4],
                    None if binding[5] == "-" else binding[5],
                    None if binding[6] == "-" else binding[6],
                    binding[8], None if binding[9] == "-" else binding[9]]
        actual = [ready["next_sequence"], ready["attempt_id"], ready["action"],
                  ready["teardown_mode"], ready["record_id"], ready["transaction_id"],
                  ready["board_identity"], ready["wrapper_sha256"]]
        if actual != expected:
            raise ValueError("ready binding changed")
        if action == "install" and ready["expected_revision"] != int(binding[7]):
            raise ValueError("ready revision changed")
    elif binding[0] != "0":
        raise ValueError("binding state")
    emit_mode = False
    if operation == "command":
        if len(call) != 2 or call[1] not in set("iox_status app_list routing_prereq storage_prereq clock prepare_iox_scp configure_network mkdir_share app_stop app_deactivate app_uninstall remove_app_config configure_app app_install app_activate copy_certificate app_start save remove_wrapper remove_certificate cleanup_config cleanup_files cleanup_config_probe cleanup_stage_probe".split()):
            raise ValueError("command")
        arguments = {"name": call[1]}
    elif operation == "cleanup":
        if len(call) != 3 or call[1] not in ("success", "error", "term", "int", "hup", "cancel"):
            raise ValueError("cleanup")
        intent = None if call[2] == "null" else int(call[2])
        if intent is not None and not integer(intent, 0, 255):
            raise ValueError("intent")
        arguments = {"reason": call[1], "exit_intent": intent}
    elif operation == "finish":
        if len(call) != 2:
            raise ValueError("finish")
        intent = int(call[1])
        if not integer(intent, 0, 255):
            raise ValueError("intent")
        arguments = {"exit_intent": intent}
    else:
        if len(call) != 1:
            raise ValueError("arguments")
        arguments = {}
    sequence = ready["next_sequence"]
    request = {key: ready[key] for key in ("attempt_id", "action", "teardown_mode", "record_id", "transaction_id", "expected_revision", "board_identity", "wrapper_sha256")}
    request.update(version=1, sequence=sequence, operation=operation, arguments=arguments)
    body = json.dumps(request, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if not 1 <= len(body) <= 65536:
        raise ValueError("request length")
    peer.sendall(struct.pack("!I", len(body)) + body)
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    indexes = {"stdout": 0, "stderr": 0}
    short = {"stdout": False, "stderr": False}
    while True:
        response = receive(peer)
        if type(response) is dict and response.get("type") == "output":
            if set(response) != OUTPUT_KEYS or response.get("version") != 1 or type(response.get("version")) is not int or response.get("sequence") != sequence or type(response.get("sequence")) is not int:
                raise ValueError("output")
            stream = response.get("stream")
            if stream not in streams or response.get("index") != indexes[stream] or type(response.get("index")) is not int or short[stream]:
                raise ValueError("output order")
            encoded = response.get("data_b64")
            if type(encoded) is not str:
                raise ValueError("base64")
            raw = base64.b64decode(encoded.encode("ascii"), validate=True)
            if not 1 <= len(raw) <= 4096 or base64.b64encode(raw).decode("ascii") != encoded:
                raise ValueError("chunk")
            if len(streams[stream]) + len(raw) > 32768 or indexes[stream] >= 8:
                raise ValueError("output bound")
            streams[stream].extend(raw)
            indexes[stream] += 1
            short[stream] = len(raw) < 4096
            continue
        if not valid_result(response, sequence, ready["attempt_id"], operation,
                            ready, binding[10] if binding[10] != "-" else None):
            raise ValueError("result")
        break
    fields = [str(ready["next_sequence"]), ready["attempt_id"], ready["action"],
              ready["teardown_mode"], ready["record_id"] or "-",
              ready["transaction_id"] or "-",
              str(response["revision"]) if response["revision"] is not None else "-",
              ready["board_identity"], ready["wrapper_sha256"] or "-",
              response["phase"] or "-"]
    os.write(1, ("IRIS-READY\t" + "\t".join(fields) + "\n").encode("ascii"))
    os.write(1, bytes(streams["stdout"]))
    if os.environ.get("IRIS_LOG", "").strip().lower() in ("on", "1", "true", "yes"):
        os.write(2, bytes(streams["stderr"]))
    elif response["operation_code"] != 0:
        # A failed step: quote the device's own verdicts, the '% ...' lines,
        # from both streams; the rest of the session is in the transcript.
        refusals = [line.strip() for line in
                    (bytes(streams["stdout"]) + b"\n" + bytes(streams["stderr"])).splitlines()
                    if line.lstrip().startswith(b"%")]
        if refusals:
            os.write(2, b"\n".join(refusals[:16]) + b"\n")
    if response["detail"]:
        os.write(2, (response["detail"] + "\n").encode("utf-8"))
    raise SystemExit(response["operation_code"])
except SystemExit:
    raise
except BaseException:
    os.write(2, b"ERROR: invalid private IOx controller protocol\n")
    raise SystemExit(200)
PY
  }

  request_capture() {
    local __name="$1" __value __rc
    shift
    REQUEST_IN_FLIGHT=1
    # The controller cancels the whole recipe process group. Keep this
    # subshell and its Python helper alive until the current frame is consumed;
    # the parent shell records the signal and owns ordered finalization.
    if __value="$(trap '' TERM INT HUP; iox_request "$@")"; then
      __rc=0
    else
      __rc=$?
    fi
    [ "$__rc" -eq 200 ] && PROTOCOL_BROKEN=1
    if [ "$__rc" -ne 200 ]; then
      if ! consume_ready "$__name" "$__value"; then
        PROTOCOL_BROKEN=1
        __rc=200
        printf -v "$__name" '%s' ""
      fi
    else
      printf -v "$__name" '%s' ""
    fi
    REQUEST_IN_FLIGHT=0
    if [ "$PENDING_SIGNAL_RC" -ne 0 ] && [ "$FINALIZING" -eq 0 ]; then
      SIGNAL_REASON="$PENDING_SIGNAL_REASON"
      # Exit here so a caller's error branch cannot issue another ordinary
      # command or replace the first signal with a response parsing failure.
      exit "$PENDING_SIGNAL_RC"
    fi
    return "$__rc"
  }

  request_plain() {
    local __rc __output
    if request_capture __output "$@"; then __rc=0; else __rc=$?; fi
    raw_echo "$__output"
    return "$__rc"
  }

  consume_ready() {
    local __name="$1" raw="$2" header body marker sequence attempt action mode record transaction revision board wrapper phase extra
    if [[ "$raw" == *$'\n'* ]]; then header="${raw%%$'\n'*}"; body="${raw#*$'\n'}"; else header="$raw"; body=""; fi
    IFS=$'\t' read -r marker sequence attempt action mode record transaction revision board wrapper phase extra <<<"$header"
    [ "$marker" = IRIS-READY ] && [ -z "$extra" ] && [[ "$sequence" =~ ^[0-9]+$ ]] || return 1
    if [ "$IPC_BOUND" -eq 0 ]; then
      IPC_ATTEMPT="$attempt" IPC_ACTION="$action" IPC_MODE="$mode" IPC_RECORD="$record"
      IPC_TRANSACTION="$transaction" IPC_REVISION="$revision" IPC_PHASE="$phase" IPC_BOARD="$board" IPC_WRAPPER="$wrapper"
      IPC_BOUND=1
    fi
    [ "$sequence" -eq "$((IPC_SEQUENCE + 1))" ] || return 1
    IPC_SEQUENCE="$sequence"
    IPC_REVISION="$revision"
    IPC_PHASE="$phase"
    printf -v "$__name" '%s' "$body"
  }

  recipe_finalize() {
    local reason="$1" primary="$2" cleanup_rc finish_rc
    [ "$FINALIZING" -eq 0 ] || return "$primary"
    FINALIZING=1
    if [ "$PROTOCOL_BROKEN" -eq 1 ]; then
      [ "$primary" -ne 0 ] && return "$primary"
      return 4
    fi
    if request_plain cleanup "$reason" "$primary"; then cleanup_rc=0; else cleanup_rc=$?; fi
    if [ "$PROTOCOL_BROKEN" -eq 1 ]; then
      [ "$primary" -ne 0 ] && return "$primary"
      return 4
    fi
    if [ "$primary" -eq 0 ] && [ "$cleanup_rc" -ne 0 ]; then primary="$cleanup_rc"; fi
    if request_plain finish "$primary"; then finish_rc=0; else finish_rc=$?; fi
    if [ "$PROTOCOL_BROKEN" -eq 1 ]; then
      [ "$primary" -ne 0 ] && return "$primary"
      return 4
    fi
    [ "$primary" -ne 0 ] && return "$primary"
    return "$finish_rc"
  }

  # uninstall.sh sources this private helper block so both recipes enforce one
  # byte-for-byte protocol validator.  An environment variable alone cannot
  # activate library mode in a directly executed installer.
  if [ "${IRIS_IOX_RECIPE_LIBRARY:-0}" = 1 ] && [ "${BASH_SOURCE[0]}" != "$0" ]; then
    return 0
  fi

  on_signal() {
    if [ "$PENDING_SIGNAL_RC" -eq 0 ]; then
      PENDING_SIGNAL_REASON="$1"
      PENDING_SIGNAL_RC="$2"
    fi
    if [ "$REQUEST_IN_FLIGHT" -eq 1 ]; then
      return 0
    fi
    SIGNAL_REASON="$PENDING_SIGNAL_REASON"
    exit "$PENDING_SIGNAL_RC"
  }
  on_exit() {
    local primary=$? reason final
    trap '' TERM INT HUP
    trap - EXIT
    reason="${SIGNAL_REASON:-$([ "$primary" -eq 0 ] && echo success || echo error)}"
    if recipe_finalize "$reason" "$primary"; then final=0; else final=$?; fi
    if [ "$final" -eq 0 ]; then
      echo "onboard complete: ${DEVICE_IP:-device}"
    fi
    exit "$final"
  }
  trap on_exit EXIT
  trap 'on_signal term 143' TERM
  trap 'on_signal int 130' INT
  trap 'on_signal hup 129' HUP

  install_recipe() {
    local out year state rc i
    echo "[1/8] fetch package and certificate"
    request_plain upload_wrapper || return $?
    request_plain upload_certificate || return $?

    echo "[2/8] check prerequisites: routing, storage, clock, IOx services"
    if request_capture out command routing_prereq; then raw_echo "$out"; else rc=$?; raw_echo "$out"; return "$rc"; fi
    if printf '%s\n' "$out" | grep -qE '^no ip routing[[:space:]]*$|^Default gateway'; then
      echo "PREREQ: ip routing is disabled; the IOx application cannot reach the staging service" >&2
      return 4
    fi
    if request_capture out command storage_prereq; then raw_echo "$out"; else rc=$?; raw_echo "$out"; return "$rc"; fi
    case "$out" in *"IOx Partition Exists"*) ;; *)
      echo "PREREQ: no IOx partition on the SD card" >&2; return 4 ;;
    esac
    if request_capture out command clock; then
      raw_echo "$out"
      year="$(printf '%s' "$out" | grep -oE '[0-9]{4}' | tail -1 || true)"
      if [ -n "$year" ] && [ "$year" -lt 2024 ]; then
        echo "PREREQ WARNING: device clock is $year — TLS certificate validation may fail"
      fi
    else rc=$?; return "$rc"; fi
    request_plain command prepare_iox_scp || return $?

    for i in $(seq 1 24); do
      if request_capture out command iox_status; then raw_echo "$out"; else rc=$?; raw_echo "$out"; return "$rc"; fi
      # The app runtime is Dockerd on IE-3x00/C9300 and Libvirtd on a
      # Catalyst 8000V (KVM-based IOx); either being Running, with CAF, means
      # the app-hosting infrastructure is ready. Requiring Dockerd alone hung
      # every C8000V install here until the lifecycle deadline elapsed.
      if printf '%s' "$out" | grep -q 'IOx service (CAF).*Running' &&
         printf '%s' "$out" | grep -qE 'Dockerd.*Running|Libvirtd.*Running'; then
        echo "IOx services ready (poll $i/24)"
        break
      fi
      [ "$i" -lt 24 ] || { echo "ERROR: IOx services are not ready" >&2; return 4; }
    done

    echo "[3/8] remove any existing app"
    request_plain begin_install || return $?
    request_plain command app_stop || return $?
    request_plain command app_deactivate || return $?
    request_plain command app_uninstall || return $?
    request_plain command remove_app_config || return $?
    echo "[4/8] configure networking and app"
    request_plain command configure_network || return $?
    request_plain command mkdir_share || return $?
    request_plain command configure_app || return $?
    echo "[5/8] install app (waiting for DEPLOYED)"
    if request_capture out command app_install; then raw_echo "$out"; else rc=$?; raw_echo "$out"; return "$rc"; fi

    state=""
    for i in $(seq 1 24); do
      if request_capture out command app_list; then raw_echo "$out"; else
        rc=$?
        raw_echo "$out"
        echo "ERROR: Application deployment did not complete; onboarding aborted." >&2
        return "$rc"
      fi
      state="$(printf '%s\n' "$out" | awk '$1=="iris"{print $2; exit}')"
      [ "$state" = DEPLOYED ] && { echo "app is DEPLOYED (poll $i/24)"; break; }
      [ "$i" -lt 24 ] || {
        echo "ERROR: Application deployment did not complete; onboarding aborted." >&2
        return 4
      }
    done
    request_plain deployed || return $?
    echo "[6/8] activate app (waiting for ACTIVATED)"
    if request_capture out command app_activate; then raw_echo "$out"; else rc=$?; raw_echo "$out"; return "$rc"; fi
    state=""
    for i in $(seq 1 24); do
      if request_capture out command app_list; then raw_echo "$out"; else rc=$?; raw_echo "$out"; return "$rc"; fi
      state="$(printf '%s\n' "$out" | awk '$1=="iris"{print $2; exit}')"
      [ "$state" = ACTIVATED ] && { echo "app is ACTIVATED (poll $i/24)"; break; }
      [ "$i" -lt 24 ] || return 4
    done
    echo "[7/8] stage instructions, copy certificate, remove uploads, start app (waiting for RUNNING)"
    request_plain stage_instructions || return $?
    request_plain command copy_certificate || return $?
    request_plain command remove_certificate || return $?
    request_plain command remove_wrapper || return $?
    request_plain command app_start || return $?
    state=""
    for i in $(seq 1 24); do
      if request_capture out command app_list; then raw_echo "$out"; else rc=$?; raw_echo "$out"; return "$rc"; fi
      state="$(printf '%s\n' "$out" | awk '$1=="iris"{print $2; exit}')"
      [ "$state" = RUNNING ] && { echo "app is RUNNING (poll $i/24)"; break; }
      [ "$i" -lt 24 ] || { echo "ERROR: IRIS application did not reach RUNNING" >&2; return 4; }
    done
    echo "[8/8] save configuration"
    request_plain command save || return $?
    return 0
  }

  set +e
  install_recipe
  exit $?
fi

: "${DEVICE_IP:?set DEVICE_IP}"
CATALOG_TOKEN="${CATALOG_TOKEN:-dry-run-token}"; : "${DEVICE_ID:?set DEVICE_ID}"
: "${STAGE_HOST:?set STAGE_HOST}"; DEVICE_SSH_PASS="${DEVICE_SSH_PASS:-dry-run-password}"
# Management type model. routed: IRIS creates a dedicated VLAN/SVI and the app SSHes
# to that SVI. inband: the app attaches to an EXISTING operator-owned VLAN that
# IRIS never creates/changes/removes, and SSHes to the existing IOS management
# SVI (IOS_SSH_HOST) for its plain-copy placement. The AppGig trunk is the one inband
# touch: IRIS ADDs the inband VLAN to its allowed list (additive only, never
# replaced, never removed on uninstall).
if [ -n "${NETWORK_ATTACHMENT:-}" ] && [ -z "${MANAGEMENT_TYPE:-}" ]; then
  echo "ERROR: NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE; refusing to fall back to the routed default" >&2
  exit 1
fi
MANAGEMENT_TYPE="${MANAGEMENT_TYPE:-routed}"
case "$MANAGEMENT_TYPE" in
  routed)
    : "${VLAN:?set VLAN}"; : "${SVI_IP:?set SVI_IP}"; : "${SVI_MASK:?set SVI_MASK}"; : "${GUEST_IP:?set GUEST_IP}"
    GW_IP="${GW_IP:-$SVI_IP}"; IOS_SSH_HOST="${IOS_SSH_HOST:-$SVI_IP}" ;;
  inband)
    : "${INBAND_VLAN:?set INBAND_VLAN}"; : "${APP_IP:?set APP_IP}"; : "${APP_MASK:?set APP_MASK}"; : "${APP_GATEWAY:?set APP_GATEWAY}"
    : "${IOS_SSH_HOST:?set IOS_SSH_HOST — the existing IOS management SVI the app SSHes to}"
    VLAN="$INBAND_VLAN"; GUEST_IP="$APP_IP"; SVI_MASK="$APP_MASK"; GW_IP="$APP_GATEWAY" ;;
  router-routed|router-nat)
    # A Catalyst 8000 router has no AppGigabitEthernet: the app attaches to an
    # IRIS-owned VirtualPortGroup exactly as the Guest Shell recipe
    # (device/router-install.sh) does, and SSHes to the VPG address. The VPG,
    # its NAT rules and the app are the whole footprint; no VLAN, SVI or trunk.
    : "${VPG_NUMBER:?set VPG_NUMBER}"; : "${APP_IP:?set APP_IP}"; : "${APP_MASK:?set APP_MASK}"; : "${APP_GATEWAY:?set APP_GATEWAY}"
    [[ "$VPG_NUMBER" =~ ^[0-9]+$ ]] && [ "$VPG_NUMBER" -ge 0 ] && [ "$VPG_NUMBER" -le 31 ] \
      || { echo "ERROR: VPG_NUMBER must be between 0 and 31" >&2; exit 1; }
    if [ "$MANAGEMENT_TYPE" = "router-nat" ]; then
      : "${NAT_INTERFACE:?set NAT_INTERFACE}"; BT_LISTEN_PORT="${BT_LISTEN_PORT:-6881}"
      [[ "$NAT_INTERFACE" =~ ^[A-Za-z][A-Za-z0-9./_-]{0,127}$ ]] \
        || { echo "ERROR: NAT_INTERFACE must be an interface name" >&2; exit 1; }
      [[ "$BT_LISTEN_PORT" =~ ^[0-9]+$ ]] && [ "$BT_LISTEN_PORT" -ge 1 ] && [ "$BT_LISTEN_PORT" -le 65535 ] \
        || { echo "ERROR: BT_LISTEN_PORT must be between 1 and 65535" >&2; exit 1; }
    fi
    # The same address check device/router-install.sh makes: the app and its
    # gateway are two distinct usable addresses of one subnet.
    python3 - "$APP_IP" "$APP_MASK" "$APP_GATEWAY" <<'SUBNET' || { echo "ERROR: APP_IP and APP_GATEWAY must be distinct usable addresses in the same subnet" >&2; exit 1; }
import ipaddress, sys
network = ipaddress.IPv4Network("%s/%s" % (sys.argv[1], sys.argv[2]), strict=False)
ip, gateway = ipaddress.IPv4Address(sys.argv[1]), ipaddress.IPv4Address(sys.argv[3])
unusable = (network.network_address, network.broadcast_address)
sys.exit(0 if (network.prefixlen <= 30 and gateway in network and gateway != ip
               and ip not in unusable and gateway not in unusable) else 1)
SUBNET
    # A Catalyst 8000 stages to bootflash: and runs the amd64 package.
    PKG="${PKG:-iris-amd64.tar}"; PKG_FS="${PKG_FS:-bootflash:}"; TARGET_FS="${TARGET_FS:-bootflash:}"
    VLAN=""; GUEST_IP="$APP_IP"; SVI_MASK="$APP_MASK"; GW_IP="$APP_GATEWAY"
    IOS_SSH_HOST="${IOS_SSH_HOST:-$APP_GATEWAY}"; APP_VNIC="vpg" ;;
  *) echo "ERROR: MANAGEMENT_TYPE must be routed, inband, router-routed, or router-nat" >&2; exit 1 ;;
esac
APP_VNIC="${APP_VNIC:-trunk}"

CATALOG_URL="${CATALOG_URL:-https://$STAGE_HOST:8443}"
APP_INTF="${APP_INTF:-AppGigabitEthernet1/1}"
# C9k share-mount transfer (Route B): bind-mount the app-hosting SSD share into
# the container so the agent lands its scratch at disk speed and IOS places it
# with an internal disk-to-disk copy — no scp, no CoPP-policed punt traffic.
# Both or neither: SHARE_HOST_PATH is the host-side dir (/vol/usb1/...),
# SHARE_IOS_PATH the same dir as IOS sees it (usbflash1:iox_host_data_share).
SHARE_HOST_PATH="${SHARE_HOST_PATH:-}"; SHARE_IOS_PATH="${SHARE_IOS_PATH:-}"
if [ -n "$SHARE_HOST_PATH$SHARE_IOS_PATH" ] && \
   { [ -z "$SHARE_HOST_PATH" ] || [ -z "$SHARE_IOS_PATH" ]; }; then
  echo "ERROR: SHARE_HOST_PATH and SHARE_IOS_PATH must be set together" >&2
  exit 2
fi
CPU="${CPU:-400}"; MEM="${MEM:-768}"; DISK="${DISK:-2048}"
PKG="${PKG:-iris-arm64.tar}"; PKG_FS="${PKG_FS:-flash:}"
DEVICE_SSH_USER="${DEVICE_SSH_USER:-dnac}"
TARGET_FS="${TARGET_FS:-sdflash:}"
IRIS_TELEMETRY="${IRIS_TELEMETRY:-on}"
IRIS_TELEMETRY_STREAM="${IRIS_TELEMETRY_STREAM:-off}"
# Same fail-closed default as device/container/entrypoint.sh's IRIS_LOG parsing
# -- this is only the plumbing that lets an operator's opt-in actually reach
# it; the default stays off either way.
IRIS_LOG="${IRIS_LOG:-off}"
# App-hosting lifecycle poll budgets, in seconds. The FIRST install of a new
# package version is far slower than a repeat install of the same one: the IOx
# runtime has to load the package's docker layers into its image cache before
# the app can activate, and a byte-identical package the box has run before
# activates in seconds because those layers are already cached. The old flat
# 90 s activate budget was shorter than that first-time load on an IE-3400, so
# a first install reported failure while the activation actually completed a
# minute or two later -- and the failed run left the app-hosting config behind,
# so the console's retry was refused by preflight. Same idiom and same 300 s
# default as device/xr-install.sh's ACTIVATE_TIMEOUT.
#
# Deliberately FLAT, not scaled by package size: every wait below returns as
# soon as the state is reached, so a generous ceiling costs a successful
# install nothing and only lengthens the already-failing case, while a
# size-derived budget would add a second failure mode (no size available, or a
# size read from an advisory HEAD that is allowed to fail) to a knob that only
# needs a ceiling. Override any of them per-device instead.
INSTALL_TIMEOUT="${INSTALL_TIMEOUT:-300}"
ACTIVATE_TIMEOUT="${ACTIVATE_TIMEOUT:-300}"
START_TIMEOUT="${START_TIMEOUT:-300}"
STATE_POLL="${STATE_POLL:-5}"

_single_line() {
  case "$2" in *$'\n'*|*$'\r'*)
    echo "ERROR: $1 must be a single line" >&2; exit 2 ;;
  esac
}

_safe_word() {
  _single_line "$1" "$2"
  [[ "$2" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]] \
    || { echo "ERROR: $1 contains unsafe characters" >&2; exit 2; }
}

_safe_host() {
  _single_line "$1" "$2"
  [[ "$2" =~ ^[A-Za-z0-9._:-]+$ ]] \
    || { echo "ERROR: $1 is not a safe host" >&2; exit 2; }
}

_uint_between() {
  local name="$1" value="$2" minimum="$3" maximum="$4"
  [[ "$value" =~ ^[0-9]+$ ]] && [ "${#value}" -le 9 ] \
    || { echo "ERROR: $name must be an integer from $minimum to $maximum" >&2; exit 2; }
  [ "$value" -ge "$minimum" ] && [ "$value" -le "$maximum" ] \
    || { echo "ERROR: $name must be an integer from $minimum to $maximum" >&2; exit 2; }
}

_ipv4() {
  local name="$1" value="$2" a b c d part
  _single_line "$name" "$value"
  [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] \
    || { echo "ERROR: $name must be an IPv4 address" >&2; exit 2; }
  IFS=. read -r a b c d <<<"$value"
  for part in "$a" "$b" "$c" "$d"; do
    [ "$((10#$part))" -le 255 ] \
      || { echo "ERROR: $name must be an IPv4 address" >&2; exit 2; }
  done
}

_netmask() {
  _ipv4 "$1" "$2"
  case "$2" in
    0.0.0.0|128.0.0.0|192.0.0.0|224.0.0.0|240.0.0.0|248.0.0.0|252.0.0.0|254.0.0.0|255.0.0.0|\
    255.128.0.0|255.192.0.0|255.224.0.0|255.240.0.0|255.248.0.0|255.252.0.0|255.254.0.0|255.255.0.0|\
    255.255.128.0|255.255.192.0|255.255.224.0|255.255.240.0|255.255.248.0|255.255.252.0|255.255.254.0|255.255.255.0|\
    255.255.255.128|255.255.255.192|255.255.255.224|255.255.255.240|255.255.255.248|255.255.255.252|255.255.255.254|255.255.255.255) ;;
    *) echo "ERROR: $1 must be a contiguous IPv4 netmask" >&2; exit 2 ;;
  esac
}

_boolean() {
  _single_line "$1" "$2"
  case "$2" in on|off|1|0|true|false|yes|no|ON|OFF|TRUE|FALSE|YES|NO) ;;
    *) echo "ERROR: $1 has an invalid boolean value" >&2; exit 2 ;;
  esac
}

_https_url() {
  local name="$1" value="$2"
  _single_line "$name" "$value"
  printf '%s' "$value" | python3 -c '
import sys
from urllib.parse import urlsplit
try:
    value = urlsplit(sys.stdin.read())
    port = value.port
    valid = (value.scheme == "https" and value.hostname is not None
             and value.username is None and value.password is None
             and (port is None or 1 <= port <= 65535))
except ValueError:
    valid = False
raise SystemExit(0 if valid else 1)
' >/dev/null 2>&1 \
    || { echo "ERROR: $name must be an https URL without credentials" >&2; exit 2; }
}

for _budget in INSTALL_TIMEOUT ACTIVATE_TIMEOUT START_TIMEOUT STATE_POLL; do
  _value="${!_budget}"
  _uint_between "$_budget" "$_value" 1 86400
done
unset _budget _value
# A VPG-attached app has no VLAN; the VirtualPortGroup number was range-checked
# where the router management types were parsed.
[ "$APP_VNIC" = "vpg" ] || _uint_between VLAN "$VLAN" 1 4094
_uint_between CPU "$CPU" 1 1048576
_uint_between MEM "$MEM" 1 1048576
_uint_between DISK "$DISK" 1 1048576
_ipv4 GUEST_IP "$GUEST_IP"
_ipv4 GW_IP "$GW_IP"
_netmask SVI_MASK "$SVI_MASK"
if [ "$MANAGEMENT_TYPE" = routed ]; then _ipv4 SVI_IP "$SVI_IP"; fi
_ipv4 IOS_SSH_HOST "$IOS_SSH_HOST"
_safe_host DEVICE_IP "$DEVICE_IP"
_safe_host STAGE_HOST "$STAGE_HOST"
_safe_word DEVICE_ID "$DEVICE_ID"
[[ "$APP_INTF" =~ ^[A-Za-z][A-Za-z0-9./_-]*$ ]] \
  || { echo "ERROR: APP_INTF contains unsafe characters" >&2; exit 2; }
_boolean IRIS_TELEMETRY "$IRIS_TELEMETRY"
_boolean IRIS_TELEMETRY_STREAM "$IRIS_TELEMETRY_STREAM"
_boolean IRIS_LOG "$IRIS_LOG"
[[ "$TARGET_FS" =~ ^[A-Za-z][A-Za-z0-9_-]*:$ ]] \
  || { echo "ERROR: TARGET_FS must be an IOS filesystem prefix such as sdflash:" >&2; exit 2; }
[[ "$PKG_FS" =~ ^[A-Za-z][A-Za-z0-9_-]*:$ ]] \
  || { echo "ERROR: PKG_FS must be an IOS filesystem prefix such as flash:" >&2; exit 2; }
[[ "$PKG" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
  || { echo "ERROR: PKG must be a safe basename" >&2; exit 2; }
if [ -n "$SHARE_HOST_PATH" ]; then
  _single_line SHARE_HOST_PATH "$SHARE_HOST_PATH"
  [[ "$SHARE_HOST_PATH" =~ ^/[A-Za-z0-9._/-]+$ ]] \
    && [[ "/$SHARE_HOST_PATH/" != *"/../"* ]] \
    || { echo "ERROR: SHARE_HOST_PATH must be a safe absolute path" >&2; exit 2; }
  _single_line SHARE_IOS_PATH "$SHARE_IOS_PATH"
  [[ "$SHARE_IOS_PATH" =~ ^[A-Za-z][A-Za-z0-9_-]*:[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]] \
    && [[ "/${SHARE_IOS_PATH#*:}/" != *"/../"* ]] \
    || { echo "ERROR: SHARE_IOS_PATH must be a safe IOS filesystem path" >&2; exit 2; }
fi

# The values below ride inside the double-quoted `run-opts N "-e K=V"` lines
# of the app-hosting block (appid_block). A literal double-quote or newline
# in any of them breaks out of that token or splices in extra config lines;
# the paste discards IOS's errors, so the malformed line was silently
# DROPPED, the app started without the variable, died on its entrypoint's
# required-env guard, and the installer timed out at wait_state RUNNING --
# after [1/9] had already torn down the previously working app. Same guard
# device/xr-install.sh applies to its docker-run-opts; reject early, before
# anything on the device is touched. A password is allowed to contain
# whitespace (it stays inside the quotes); the identity/URL values are not.
_no_quotes_or_newlines() {
  case "$2" in
    *'"'*|*$'\n'*|*$'\r'*)
      echo "ERROR: $1 must not contain a double quote, CR, or LF" >&2
      exit 1 ;;
  esac
  if [ "${3:-}" = "no-whitespace" ]; then
    case "$2" in *[[:space:]]*)
      echo "ERROR: $1 contains whitespace, which would split the quoted run-opts value" >&2
      exit 1 ;;
    esac
  fi
}
_no_quotes_or_newlines DEVICE_SSH_PASS "$DEVICE_SSH_PASS"
_no_quotes_or_newlines CATALOG_TOKEN "$CATALOG_TOKEN" no-whitespace
_no_quotes_or_newlines CATALOG_URL "$CATALOG_URL" no-whitespace
_no_quotes_or_newlines DEVICE_ID "$DEVICE_ID" no-whitespace
_no_quotes_or_newlines DEVICE_SSH_USER "$DEVICE_SSH_USER" no-whitespace
# IRIS_LOG rides the same quoted run-opts value as everything else above;
# reuse the one guard rather than trusting a bare on/off-shaped value.
_no_quotes_or_newlines IRIS_LOG "$IRIS_LOG" no-whitespace
_https_url CATALOG_URL "$CATALOG_URL"
[[ "$CATALOG_TOKEN" =~ ^[A-Za-z0-9._~+/-]+=*$ ]] \
  || { echo "ERROR: CATALOG_TOKEN contains unsafe characters" >&2; exit 2; }
[[ "$DEVICE_SSH_USER" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]] \
  || { echo "ERROR: DEVICE_SSH_USER is not a safe SSH username" >&2; exit 2; }
if [ -n "${DEVICE_USER:-}" ]; then
  [[ "$DEVICE_USER" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]] \
    || { echo "ERROR: DEVICE_USER is not a safe SSH username" >&2; exit 2; }
fi
if [ -n "${MODEL:-}" ]; then _safe_word MODEL "$MODEL"; fi
if [ -n "${EXPECTED_DEVICE_IDENTITY:-}" ]; then
  _safe_word EXPECTED_DEVICE_IDENTITY "$EXPECTED_DEVICE_IDENTITY"
fi
APPID=iris
# The artifact server's device-bound route (server/api_routes.py
# artifactBasic): HTTP Basic, username = device id, password = the enrollment
# token, which IOS attaches from its global HTTP client credentials.
ARTIFACT_BASE="https://$STAGE_HOST:8000/v1/devices/$DEVICE_ID/artifacts"

# The same trust block device/device-install.sh pastes, before any copy:
# non-circular (trust arrives over the SSH we already have; the bulk transfer
# rides the HTTPS it validates). The controller answers the device's two
# PKI confirmations only when they are actually asked.
trustpoint_block() {
  echo "configure terminal"
  echo "no crypto pki trustpoint IRIS"
  echo "! yes -- if the device asks to confirm the removal [yes/no]"
  echo "crypto pki trustpoint IRIS"
  echo " enrollment terminal"
  echo " revocation-check none"
  echo "exit"
  echo "crypto pki authenticate IRIS"
  if [ -n "${IRIS_CRT_FILE:-}" ] && [ -r "$IRIS_CRT_FILE" ]; then
    cat "$IRIS_CRT_FILE"
  else
    echo "! <contents of \$IRIS_CRT_FILE (the public catalog certificate) inserted here at apply time>"
  fi
  echo "quit"
  echo "! yes -- at the device's \"accept this certificate? [yes/no]\" question"
  echo "ip http client secure-trustpoint IRIS"
  echo "end"
}

http_client_credentials() {
  echo "configure terminal"
  echo "ip http client username $DEVICE_ID"
  echo "ip http client password 0 <redacted>"
  echo "end"
}

clear_http_client() {
  echo "configure terminal"
  echo "no ip http client username"
  echo "no ip http client password"
  echo "end"
}

fetch_block() {
  http_client_credentials
  printf 'copy %s/%s %siris-<transaction>.tar\n' "$ARTIFACT_BASE" "$PKG" "$PKG_FS"
  printf 'dir %s | include iris-<transaction>\\.tar\n' "$PKG_FS"
  clear_http_client
  http_client_credentials
  printf 'copy %s/iris-catalog.pem %siris-ca.pem\n' "$ARTIFACT_BASE" "$PKG_FS"
  printf 'dir %s | include iris-ca\\.pem\n' "$PKG_FS"
  clear_http_client
  echo "! after activation, the sealed instruction envelope the same way:"
  http_client_credentials
  printf 'copy %s/staging/%s/iris-instructions-<transaction>.envelope %siris-instructions-<transaction>.envelope\n' \
    "$ARTIFACT_BASE" "$DEVICE_ID" "$PKG_FS"
  printf 'dir %s | include iris-instructions-<transaction>\\.envelope\n' "$PKG_FS"
  clear_http_client
}

ios_net() {           # networking + IOx enable (idempotent)
if [ "$APP_VNIC" = "vpg" ]; then
# Router: the same VirtualPortGroup and NAT footprint device/router-install.sh
# creates for Guest Shell, described so teardown can recognise it as IRIS's.
cat <<EOF
iox
!
interface VirtualPortGroup$VPG_NUMBER
 description IRIS IOx VPG
 ip address $APP_GATEWAY $APP_MASK
EOF
if [ "$MANAGEMENT_TYPE" = "router-nat" ]; then
cat <<EOF
 ip nat inside
EOF
fi
cat <<EOF
 no shutdown
!
EOF
if [ "$MANAGEMENT_TYPE" = "router-nat" ]; then
network_values="$(python3 - "$APP_IP" "$APP_MASK" <<'NET'
import ipaddress, sys
network = ipaddress.IPv4Network("%s/%s" % (sys.argv[1], sys.argv[2]), strict=False)
print(network.network_address); print(network.hostmask)
NET
)"
APP_SUBNET="${network_values%%$'\n'*}"; APP_WILDCARD="${network_values##*$'\n'}"
cat <<EOF
interface $NAT_INTERFACE
 ip nat outside
!
ip access-list standard IRIS-NAT-$VPG_NUMBER
 permit $APP_SUBNET $APP_WILDCARD
!
ip nat inside source list IRIS-NAT-$VPG_NUMBER interface $NAT_INTERFACE overload
ip nat inside source static tcp $APP_IP $BT_LISTEN_PORT interface $NAT_INTERFACE $BT_LISTEN_PORT
!
EOF
fi
cat <<EOF
file prompt quiet
!
! SCP server: not for onboarding (the router fetches the package itself);
! the agent's runtime image hand-off scp-pushes the downloaded image to
! bootflash:guest-share/iris through it, then the plain copy places it.
ip scp server enable
!
end
EOF
return
fi
if [ "$MANAGEMENT_TYPE" = "inband" ]; then
# Inband: attach to the EXISTING operator-owned VLAN. IRIS creates NO vlan, SVI,
# route, or VRF. The ONE allowed touch is the AppGig trunk, and only ADDITIVELY —
# `allowed vlan add` never replaces the allowed list (the bare form would), and
# uninstall never removes it (operator-owned VLAN; the trunk may be shared).
# Without it the app's traffic has no L2 path off the box.
cat <<EOF
iox
!
interface $APP_INTF
 switchport mode trunk
 switchport trunk allowed vlan add $VLAN
!
file prompt quiet
!
! SCP server: the scp fallback hand-off (primary on IE-3x00; C9k uses the
! bind-mounted SSD share) pushes the scratch here, then the plain copy places it.
ip scp server enable
!
end
EOF
return
fi
cat <<EOF
iox
!
vlan $VLAN
!
interface $APP_INTF
 switchport mode trunk
 switchport trunk allowed vlan $VLAN
!
interface Vlan$VLAN
 description IRIS IOx app inline
 ip address $SVI_IP $SVI_MASK
 no shutdown
!
file prompt quiet
!
! SCP server: the scp hand-off (primary on IE-3x00, where IOx cannot
! bind-mount sdflash:; the C9k default is the SSD share) pushes the scratch to
! guest-share, then the plain copy places it.
ip scp server enable
!
end
EOF
}

appid_block() {       # app-hosting appid (NO explicit exit lines — IOS auto-pops,
cat <<EOF
app-hosting appid $APPID
EOF
if [ "$APP_VNIC" = "vpg" ]; then
cat <<EOF
 app-vnic gateway0 virtualportgroup $VPG_NUMBER guest-interface 0
  guest-ipaddress $GUEST_IP netmask $SVI_MASK
EOF
else
cat <<EOF
 app-vnic AppGigabitEthernet trunk
  vlan $VLAN guest-interface 0
   guest-ipaddress $GUEST_IP netmask $SVI_MASK
EOF
fi
cat <<EOF
 app-default-gateway $GW_IP guest-interface 0
 app-resource profile custom
  cpu $CPU
  memory $MEM
  persist-disk $DISK
  vcpu 1
 app-resource docker
  run-opts 1 "-e IRIS_DEVICE_ID=$DEVICE_ID"
  run-opts 2 "-e IRIS_DEVICE_SSH_PASS=$DEVICE_SSH_PASS"
  run-opts 3 "-e IRIS_CATALOG_TOKEN=$CATALOG_TOKEN"
  run-opts 4 "-e IRIS_CATALOG_URL=$CATALOG_URL"
  run-opts 5 "-e IRIS_DEVICE_SSH_HOST=$IOS_SSH_HOST"
  run-opts 6 "-e IRIS_DEVICE_SSH_USER=$DEVICE_SSH_USER"
  run-opts 7 "-e IRIS_DEVICE_PLATFORM=iox"
  run-opts 8 "-e IRIS_TARGET_FS=$TARGET_FS"
  run-opts 9 "-e IRIS_TELEMETRY=$IRIS_TELEMETRY"
  run-opts 10 "-e IRIS_TELEMETRY_STREAM=$IRIS_TELEMETRY_STREAM"
  run-opts 11 "-e IRIS_LOG=$IRIS_LOG"
EOF
if [ -n "$SHARE_HOST_PATH" ]; then
cat <<EOF
  run-opts 12 "-e IRIS_SHARE_DIR=/mnt/share"
  run-opts 13 "-e IRIS_SHARE_IOS_PATH=$SHARE_IOS_PATH"
  run-opts 14 "-v $SHARE_HOST_PATH:/mnt/share"
EOF
fi
echo "end"
}

appid_block_redacted() {
  # A dry run is commonly pasted into an issue or build log.  Keep the shape
  # of every run-opt visible without printing either credential.
  local DEVICE_SSH_PASS='<redacted>' CATALOG_TOKEN='<redacted>'
  appid_block
}

echo "network configuration: $MANAGEMENT_TYPE"
ios_net
echo "app configuration: $APPID"
appid_block_redacted
if [ -n "$SHARE_IOS_PATH" ]; then
  echo "create shared directory"
  echo "mkdir $SHARE_IOS_PATH"
fi
echo "catalog trustpoint (pasted over SSH before any copy)"
trustpoint_block
echo "device-side fetch over verified https (credentials set for each copy, then removed)"
fetch_block
echo "signature policy: package.sign/package.cert marker presence does not establish cryptographic validity; controller admission decides verification handling"
echo "install, activate, copy certificate, start and save: $APPID"
exit 0
