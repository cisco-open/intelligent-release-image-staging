#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""IRIS device agent — EEM-driven control plane (run with --once).
Decides what to download from the catalog, pre-checks flash, stages the torrent,
kicks aria2c, and emits DONE (sha-verified) for the native EEM copy-to-root.
All side effects are injected via Deps so the logic is testable off-box; on-box,
build_deps() wires the real cli module / aria2 RPC / filesystem."""
import collections
import errno
import hashlib
import ipaddress
import json
import math
import os
import random
import re
import shutil
import sys
import tempfile
import time
import urllib.parse
import urllib.request

import agent_config
import flashcheck
import flash_target
import telemetry_report
import verify_image

# State-file schema version. v1 came from the old agent whose copy_to_root
# returned True without verifying the flash-root copy, so its "copied"/"root_file"
# flags can't be trusted. On upgrade we drop them and re-verify (see migration
# in run_once).
_STATE_SCHEMA = 2

# The catalog filename gets interpolated into IOS commands (the copy applet, the
# delete applet). Reject anything outside this set before that happens, so a bad
# catalog value can't inject extra IOS config.
_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# The IOS filesystems a pre-existing root image may be attested on (native
# `dir` size + `verify /sha512`) before IRIS decides whether to place a copy at
# all: the C9300 Guest Shell / C9k IOx boot disks, and sdflash: — the IE-3x00
# family's IOx staging disk, where the agent's SSH-to-self vty reads it the
# same way. Anything else is refused as an invalid root path.
_IOS_ROOT_PREFIXES = ("flash:", "bootflash:", "sdflash:")

# A failed IOS copy can occupy its full 900-second applet budget. Four attempts
# bound that disruption while still tolerating several transient failures. The
# first retry runs on the next tick; subsequent retries use a five-minute
# exponential delay capped at one hour so they do not hammer a constrained ARM
# control plane.
_ROOT_COPY_MAX_ATTEMPTS = 4
_ROOT_COPY_BACKOFF_BASE = 5 * 60
_ROOT_COPY_BACKOFF_MAX = 60 * 60
# The outer announce URL is not part of a torrent's info dictionary, so moving
# the tracker from HTTP to HTTPS deliberately leaves the info hash unchanged.
# Persist the transport generation alongside the identity so every platform
# replaces an identity-equal cached torrent exactly once after the upgrade.
# Guest Shell still uses its established query credential; IOx and XR use the
# separately scoped per-download Bearer header.
_TORRENT_TRANSPORT_BEARER_HTTPS = "bearer-https-v2"
_TORRENT_TRANSPORT_QUERY_HTTPS = "legacy-query-https-v1"

_MAX_I63 = (1 << 63) - 1
_ARIA_GID_RE = re.compile(r"^[0-9a-f]{16}$")
_ARIA_GLOBAL_OPTIONS = (
    ("bt-max-peers", "bt_max_peers"),
    ("max-upload-limit", "max_upload_limit"),
    ("max-download-limit", "max_download_limit"),
    ("max-overall-upload-limit", "overall_up"),
    ("max-overall-download-limit", "overall_down"),
    ("bt-request-peer-speed-limit", "request_peer_speed_limit"),
    ("max-concurrent-downloads", "max_concurrent"),
)
_ARIA_LIVE_OPTIONS = _ARIA_GLOBAL_OPTIONS[:3] + (_ARIA_GLOBAL_OPTIONS[5],)
_FIXED_QOS = {
    "max_peers": 10,
    "seed_up_bps": 0,
    "seed_down_bps": 0,
    "leech_up_bps": 0,
    "leech_down_bps": 0,
    "overall_up_bps": 0,
    "overall_down_bps": 0,
    "max_concurrent": 100,
    "request_peer_speed_limit_bps": 51200,
}
_FIXED_CONTROL = {
    "catalog_tick_s": 60,
    "telemetry_every_ticks": 1,
    "telemetry_pause": False,
}
_ALLOW_COMPLEMENT_CACHE = {"digest": None, "rules": None}


def _normalize_tick_seconds(value):
    """Return a bounded mechanical launcher tick, compatibly defaulting to 60."""
    if isinstance(value, bool):
        return 60
    if isinstance(value, int):
        tick_seconds = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        significant = value.lstrip("0") or "0"
        if len(significant) > 5:
            return 60
        tick_seconds = int(significant)
    else:
        return 60
    return tick_seconds if 1 <= tick_seconds <= 86400 else 60

_INSTRUCTION_ARIA_ADD_PROTOCOL = "iris-instruction-aria-add/v1"


class _InstructionAriaAdd:
    """Scope one dependency instance's verified defaults to addTorrent."""

    def __init__(self, function, defaults):
        self.function = function
        self.defaults = defaults
        self.instruction_aria_add_protocol = _INSTRUCTION_ARIA_ADD_PROTOCOL

    def __call__(self, *args, **kwargs):
        import instr
        context = instr.torrent_option_context()
        marker = object()
        previous = getattr(context, "defaults", marker)
        context.defaults = self.defaults
        try:
            return self.function(*args, **kwargs)
        finally:
            if previous is marker:
                try:
                    del context.defaults
                except AttributeError:
                    pass
            else:
                context.defaults = previous

    def with_instruction_defaults(self, defaults):
        return _InstructionAriaAdd(self.function, defaults)

    def unwrap_instruction_aria_add(self):
        return self.function


def _instruction_aria_add_protocol(value):
    if (getattr(value, "instruction_aria_add_protocol", None)
            != _INSTRUCTION_ARIA_ADD_PROTOCOL):
        return None
    replace = getattr(value, "with_instruction_defaults", None)
    unwrap = getattr(value, "unwrap_instruction_aria_add", None)
    if not callable(replace) or not callable(unwrap):
        return None
    return replace, unwrap


def _choose_ios_stage_prefix(platform, filesystems, model,
                             guest_share_fs, preferred_fs, boot_path):
    """Select IOS storage while retaining the Guest Shell legacy fallback."""
    prefix = (flash_target.choose_stage_fs(
                  filesystems, model=model, guest_share_fs=guest_share_fs,
                  preferred_fs=preferred_fs)
              or flash_target.choose_target_fs(filesystems, boot_path))
    # An absent selector is Guest Shell, whose established behavior falls back
    # to flash:. The explicit IOx container profile must prove its destination.
    if not prefix and platform != "iox":
        return "flash:"
    return prefix


def _root_copy_tmp_name(fname):
    """The reserved temp name a root-copy replacement (_copy_to_root_impl /
    _copy_to_root_direct_impl) stages its new bytes under, proves by presence
    + exact size, and only then renames over the real name. Fixed suffix
    (flash_target.ROOT_COPY_TMP_SUFFIX) that no real Cisco image or
    catalog-published filename is expected to carry, so this can never
    coincide with the running image or the BOOT target — the real name is
    never deleted or overwritten until the replacement is proven good."""
    return fname + flash_target.ROOT_COPY_TMP_SUFFIX


def _guestshell_root_ios_path(stage_dir, target_prefix, fname):
    """Return a canonical IOS root path; Guest Shell mounts only guest-share.

    The container's /flash and /bootflash do not expose IOS root files. Only
    the installer-owned share can carry a native IOS hash receipt.
    """
    roots = {"flash:": "/flash", "bootflash:": "/bootflash"}
    root = roots.get(target_prefix)
    if (root is None or stage_dir != root + "/guest-share/iris"
            or not isinstance(fname, str) or not _FILENAME_RE.fullmatch(fname)):
        return None
    return target_prefix + fname


def _iox_root_ios_path(target_prefix, fname):
    """The IOS root path an IOx-app agent attests before placing `fname`.

    The IOx container has no mount of the IOS disk at all (IE-3x00 sdflash:,
    C9k flash:/bootflash:), so unlike the Guest Shell there is no local
    mount shape to cross-check — the proved staging prefix (target_fs) and a
    catalog filename that passes the IOS-command allowlist are the whole
    contract. None for any other prefix or a non-canonical name."""
    if (target_prefix not in _IOS_ROOT_PREFIXES or not isinstance(fname, str)
            or not _FILENAME_RE.fullmatch(fname)):
        return None
    return target_prefix + fname

# Board #60: a park-pass record that has no root_file AND that the catalog no
# longer answers for at all (e.g. the aria_add call site's bare
# {'download_started': True}, once its image is deleted from the catalog) can
# never be named by ANY future tick either — see _reconcile_set's PARK-DEFERRED
# arm. Ten ticks (~10 minutes at the ordinary 60 s cadence) rides out a
# transient catalog outage without spamming the log for the life of the agent.
_PARK_DEFER_MAX_ATTEMPTS = 10

# Sentinel deps.copy_to_root() returns instead of plain False when the running
# IOS image could not be confirmed (the IOx SSH-to-self `show version` scrape
# glitched) — as opposed to a genuine copy failure, or the refusal that fires
# when the target IS the confirmed running image. running_image() being
# unknown is a transient read failure, not evidence anything is wrong with the
# copy, so it must NOT consume a copy_attempts slot or advance the backoff
# schedule: run_once() special-cases this value to retry next tick exactly as
# it did before the bounded-retry schedule existed. Identity-checked (`is`),
# never truthy/falsy-compared, so it can't be mistaken for True/False.
ROOT_COPY_RUNNING_IMAGE_UNKNOWN = object()

# Sentinel returned by every copy_to_root path that gives up BEFORE any IOS
# command runs: both running-image refusals, an scp scratch push that raised, an
# applet run that never fired, a delete-first that raised. It exists because the
# terminal-state reclaim (_reclaim_failed_root_copy) is only safe when THIS
# attempt's `delete /force` actually executed — that delete is what proves a file
# sitting at the TEMP name (_root_copy_tmp_name) is our own partial. The real
# image name is never deleted or overwritten by a failed attempt at all — every
# destructive command a copy attempt issues, up to and including the final
# rename that puts proven bytes in place, targets the temp name or runs only
# once this agent's own verify has already blessed what's under it. After a
# pre-IOS failure nothing was deleted anywhere, so a file at the temp name (if
# any) is stale debris from an EARLIER attempt at most, and a file at the real
# name is the OPERATOR'S — on the running-image-refusal path it is the running
# image itself: deleting either would strand a bundle-mode box in rommon at
# the next reload.
#
# Retry/backoff accounting treats this EXACTLY like plain False — the attempt
# counts, the backoff advances, copy_terminal still eventually fires, because an
# operator must still be shown the terminal state. The only difference is that it
# never sets st["ios_copy_started"], the flag that arms the reclaim.
#
# Identity-checked (`is`), NEVER truthy/falsy-compared: it is a plain object() and
# therefore TRUTHY, so any success branch must exclude it explicitly first.
ROOT_COPY_NOT_ATTEMPTED = object()

# `boot_image` took the slot of the old `ios` field, an arbitrary IOS-exec
# passthrough that no production path ever called — the one seam through which
# any IOS command at all could have been issued. What replaced it is the single
# read-only fact the reclaim paths were missing:
#   boot_image() -> basename of the file the BOOT variable names (`show boot`),
#                   "" when IOS positively reports no BOOT target, None when
#                   the read failed. None is "unknown", and every destructive
#                   reclaim treats it exactly like an unknown running image.
#
# NOTE: an earlier revision of the crash-safety fix (temp-name copy, verify,
# rename into place) added a `root_file_size` probe here to charge the copy
# gate extra headroom for a pre-existing same-named destination file. That
# double-counted: deps.target_fs()'s `free` already excludes whatever
# currently occupies the destination name, and the corrected sequence writes
# no new bytes for that old file at all — it stays put until the final
# `rename`, a directory-entry update that moves no data. The probe and its
# surcharge were removed (scrubber #138); the gate charges exactly the bytes
# the temp copy actually writes, same as before the crash-safety fix.
_BaseDeps = collections.namedtuple(
    "Deps", "catalog emit boot_image aria_add file_size verify free_bytes "
            "version copy_to_root purge_others reclaim root_present "
            "remove_stage aria_remove detect_mode target_fs running_image "
            "reclaimable reclaim_bundle model refresh aria_stats aria_peers "
            "io_transfer checkpoint aria_session copy_in_place "
            "root_file_size verify_root")
_BaseDeps.__new__.__defaults__ = (None, None)


class Deps(_BaseDeps):
    """Established 29-field dependency tuple with an additive callback view.

    Keep the callback as per-instance metadata so older code that checks the
    tuple's exact shape remains valid, while new callers can construct and
    replace ``instruction_step`` as if it were an optional dependency.
    """

    def __new__(cls, *args, **kwargs):
        instruction_step = kwargs.pop("instruction_step", None)
        aria_rpc = kwargs.pop("aria_rpc", None)
        torrent_defaults = kwargs.pop("torrent_defaults", None)
        value = _BaseDeps.__new__(cls, *args, **kwargs)
        value._instruction_step = instruction_step
        value._aria_rpc = aria_rpc
        value._torrent_defaults = torrent_defaults
        return value

    @property
    def instruction_step(self):
        return self._instruction_step

    @property
    def aria_rpc(self):
        return self._aria_rpc

    @property
    def torrent_defaults(self):
        return self._torrent_defaults

    def _replace(self, **kwargs):
        marker = object()
        instruction_step = kwargs.pop("instruction_step", marker)
        aria_rpc = kwargs.pop("aria_rpc", marker)
        torrent_defaults = kwargs.pop("torrent_defaults", marker)
        replaced_defaults = torrent_defaults is not marker
        if instruction_step is marker:
            instruction_step = self.instruction_step
        if aria_rpc is marker:
            aria_rpc = self.aria_rpc
        if torrent_defaults is marker:
            torrent_defaults = self.torrent_defaults
        value = _BaseDeps._replace(self, **kwargs)
        wrapper = _instruction_aria_add_protocol(value.aria_add)
        if replaced_defaults and wrapper is not None:
            value = _BaseDeps._replace(
                value, aria_add=wrapper[0](torrent_defaults))
        value._instruction_step = instruction_step
        value._aria_rpc = aria_rpc
        value._torrent_defaults = torrent_defaults
        return value


def _atomic_write_state(state_path, state):
    """Durably persist agent state with the crash-safe tmp+fsync+rename+
    dir-fsync discipline.

    The sibling rename is atomic on the state filesystem. Sync both the bytes
    and the directory entry so sudden power loss cannot expose a truncated file
    or lose the completed rename. A filesystem that does not implement directory
    fsync raises EINVAL/ENOTSUP on the dir fd — that platform limitation is
    ignored, but a real I/O failure still surfaces.

    Factored out of main() (behavior unchanged) so Deps.checkpoint can persist
    identity/sequence facts BEFORE any network side effect that must survive a
    crash. Raises on a genuine write/fsync failure; callers that need
    best-effort behavior (main's outer final save) wrap it."""
    tmp = state_path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(state, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, state_path)
        dir_fd = os.open(os.path.dirname(state_path) or ".", os.O_RDONLY)
        try:
            try:
                os.fsync(dir_fd)
            except OSError as e:
                unsupported = {errno.EINVAL}
                if hasattr(errno, "ENOTSUP"):
                    unsupported.add(errno.ENOTSUP)
                if e.errno not in unsupported:
                    raise
        finally:
            os.close(dir_fd)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _heartbeat(image, deps, stage_state="staging", target_fs=None,
               tele_on=True, stage_error=None, sample=None, stream_on=False,
               observation=None, staged_image_ids=None,
               errored_image_ids=None):
    hb = {"current_image_id": image["id"] if image else None,
          "free_flash_bytes": deps.free_bytes(target_fs or "flash:"),
          "version": deps.version(),
          "model": deps.model(),
          "stage_state": stage_state,
          "stage_error": stage_error,
          "target_fs": target_fs,
          "telemetry_enabled": bool(tele_on),
          "telemetry_stream_enabled": bool(stream_on)}
    if sample is not None:
        hb["sample"] = sample
    if observation is not None:
        hb["telemetry_observation"] = observation
    if staged_image_ids is not None:
        # Which images of an assigned SET are fully staged. Sent only for a
        # real set: a one-image device (and every agent that predates the
        # field) leaves it out, and the server falls back to the
        # current_image_id/stage_state pair for those.
        hb["staged_image_ids"] = staged_image_ids
    if errored_image_ids is not None:
        # Which images of an assigned SET hit a terminal per-image failure
        # THIS tick. Same one-image-set/legacy-agent omission as
        # staged_image_ids above: paired with it, it lets the server tell
        # "everything is stuck" from "one erred, the rest are still going"
        # instead of guessing from the set's single collapsed stage_state.
        hb["errored_image_ids"] = errored_image_ids
    return hb


_INSTRUCTION_STATES = frozenset((
    "none", "applied", "lkg", "stale_expired", "allowlist_expired",
    "rollback_rejected", "floor_reset", "audience_mismatch", "key_rejected",
    "tamper_rejected", "verifier_missing", "lkg_rejected", "lkg_unreadable",
    "oversize", "reasserted", "instr_unavailable", "instr_pending",
    "instr_forbidden", "tracker-only",
))
_INSTRUCTION_REASONS = frozenset(("unknown_key", "bad_mac"))
_APPLIED_FIELDS = tuple(name for _option, name in _ARIA_GLOBAL_OPTIONS)
_QOS_DRIFT_MAX_ROWS = 47


def _public_i63(value):
    if (isinstance(value, bool) or not isinstance(value, int)
            or value < 0 or value > _MAX_I63):
        raise ValueError("invalid bounded integer")
    return value


def _public_integer_unit(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError("invalid bounded unit")
    return {name: _public_i63(value[name]) for name in fields}


def _public_drift_pair(value):
    pair = _public_integer_unit(value, ("expected", "observed"))
    if pair["expected"] == pair["observed"]:
        raise ValueError("not drift")
    return pair


def _public_drift(value):
    if (not isinstance(value, dict)
            or not set(value).issubset({
                "options", "blocklist_revision", "blocklist_rules"})
            or "options" not in value):
        raise ValueError("invalid drift")
    rows = value["options"]
    if not isinstance(rows, list) or len(rows) > _QOS_DRIFT_MAX_ROWS:
        raise ValueError("invalid drift rows")
    clean = {"options": []}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
                "option", "expected", "observed"}:
            raise ValueError("invalid drift row")
        if row["option"] not in _APPLIED_FIELDS:
            raise ValueError("invalid drift option")
        pair = _public_drift_pair({
            "expected": row["expected"], "observed": row["observed"]})
        clean["options"].append(dict(pair, option=row["option"]))
    for name in ("blocklist_revision", "blocklist_rules"):
        if name in value:
            clean[name] = _public_drift_pair(value[name])
    if not rows and len(clean) == 1:
        raise ValueError("empty drift")
    return clean


def _heartbeat_with_instruction(payload, attestation):
    """Copy only the bounded public instruction facts into a heartbeat."""
    if not isinstance(attestation, dict):
        attestation = {}
    # Wire capability is unconditional, including failed instruction/RPC
    # work. Heartbeat version continues to describe IOS software.
    clean = {"instr_protocol": 1}
    if "applied" in attestation:
        try:
            clean["applied"] = _public_integer_unit(
                attestation["applied"], _APPLIED_FIELDS)
        except (KeyError, TypeError, ValueError):
            pass
    instr_state = attestation.get("instr_state")
    instr_reason = attestation.get("instr_reason")
    if isinstance(instr_state, str) and instr_state in _INSTRUCTION_STATES:
        if instr_state == "key_rejected":
            if (isinstance(instr_reason, str)
                    and 1 <= len(instr_reason) <= 128
                    and instr_reason in _INSTRUCTION_REASONS):
                clean.update(instr_state=instr_state,
                             instr_reason=instr_reason)
        elif "instr_reason" not in attestation:
            clean["instr_state"] = instr_state
    identity_fields = ("instr_epoch", "instr_serial", "instr_policy_revision")
    identity = {name: attestation[name] for name in identity_fields
                if name in attestation}
    try:
        clean.update(_public_integer_unit(identity, identity_fields))
    except (KeyError, TypeError, ValueError):
        pass
    if type(attestation.get("pointer_skew")) is bool:
        clean["pointer_skew"] = attestation["pointer_skew"]
    verify_level = attestation.get("verify_level")
    if verify_level in ("sig", "none"):
        clean["verify_level"] = verify_level
    if ("blocklist_rules" in attestation
            or "blocklist_revision" in attestation):
        pair = {name: attestation[name] for name in (
            "blocklist_rules", "blocklist_revision")
            if name in attestation}
        try:
            clean.update(_public_integer_unit(
                pair, ("blocklist_rules", "blocklist_revision")))
        except (KeyError, TypeError, ValueError):
            pass
    if "qos_drift" in attestation:
        try:
            clean["qos_drift"] = _public_drift(attestation["qos_drift"])
        except (KeyError, TypeError, ValueError):
            pass
    result = dict(payload)
    result.update(clean)
    return result


def _instruction_unavailable_fact(state):
    """Keep detector context without claiming a failed RPC applied policy."""
    import instr
    fact = {"instr_state": "instr_unavailable"}
    fact.update(instr.pointer_skew_fact(state))
    return fact


def _send_heartbeat(deps, sid, payload, instruction_attestation=None):
    """POST a heartbeat, BEST-EFFORT — must never raise out of run_once.

    The heartbeat is the LAST step on every path, AFTER the tick has already
    committed its work (e.g. st['copied']=True / state['root_file'] on the
    copy-complete path). ANY failure on that final POST must NOT unwind
    run_once, or main()'s state-persist block never runs and the just-recorded
    progress is discarded — forcing a needless full re-copy of the ~1.2 GB image
    next tick. Losing one heartbeat (a swarm-map row) is harmless; losing the
    persisted state is not.

    Catch Exception, not just CatalogError: the client raises CatalogError on a
    5xx/unreachable, but heartbeat() also json.loads(body) on a 200 — a
    proxy/captive-portal 200-with-non-JSON body raises json.JSONDecodeError (a
    ValueError, not a CatalogError), and an http.client.IncompleteRead
    (HTTPException) from r.read() likewise escapes CatalogError. Both are
    realistic on enterprise networks and would discard progress. Mirrors
    _emit_impl's unconditional best-effort try/except."""
    try:
        return deps.catalog.heartbeat(
            sid, _heartbeat_with_instruction(payload, instruction_attestation))
    except Exception as e:
        try:
            deps.emit("HEARTBEAT-FAIL", "%s heartbeat failed (ignored): %s"
                      % (sid, type(e).__name__))
        except Exception:
            pass
        return None


# telemetry (#13): completion-jitter sleep as a module seam so tests can stub
# it (real jitter is up to JITTER_MAX seconds per send).
_SLEEP = time.sleep


def _checkpoint_or_skip(deps, state, emit_tag, emit_detail):
    """Durably persist state BEFORE an identity/sequence-bearing POST.

    Returns True on a durable checkpoint (the caller may POST), False if the
    checkpoint failed OR deps has no checkpoint wired. A FAILED checkpoint MUST
    prevent the POST: sending an identity/sequence the device could not persist
    would let a crash-after-POST restart mint a fresh id or rewind sample_seq,
    breaking server dedupe / reorder rejection. Losing the POST this tick is
    harmless — the next tick re-checkpoints and re-sends. Never raises."""
    checkpoint = getattr(deps, "checkpoint", None)
    if not callable(checkpoint):
        return False
    try:
        checkpoint(state)
        return True
    except Exception as e:
        try:
            deps.emit(emit_tag, "%s (POST skipped): %s" % (emit_detail, e))
        except Exception:
            pass
        return False


def _send_report(cfg, deps, state, img_id, report):
    """POST one telemetry report, BEST-EFFORT — never raises (mirrors
    _send_heartbeat). Jitter BEFORE the POST desynchronizes a batch of devices
    that finished together (issue #13's polite-reporting requirement). Returns
    True only on a delivered report. A fake catalog without post_telemetry
    (old client, most existing tests) is a quiet no-send."""
    try:
        post = getattr(deps.catalog, "post_telemetry", None)
        if not callable(post):
            return False
        _SLEEP(random.uniform(0, telemetry_report.JITTER_MAX))
        post(cfg["device_id"], report)
        # A delivered report proves the catalog link is healthy: reset the
        # heartbeat streak (classifier) AND the separate report streak (spec
        # §10.2 splits heartbeat_fail_streak from report_fail_streak).
        telemetry_report.record_success(state)
        telemetry_report.record_report_success(state)
        deps.emit("TELEMETRY", "%s report sent (%s)"
                  % (img_id, report.get("event")))
        return True
    except Exception as e:
        telemetry_report.record_report_failure(state)
        deps.emit("TELEMETRY-FAIL", "%s report failed (ignored): %s"
                  % (img_id, e))
        return False


def _not_active_observation(tele_on, now):
    """State-only v2 envelope for an unassigned/error device (no transfer). It
    invents no transfer_id/image_id/aria fields (spec §3A). `disabled` when the
    telemetry master toggle is off, else `not_active`."""
    try:
        return telemetry_report.build_observation(
            obs_state="disabled" if not tele_on else "not_active",
            observed_at=now, transfer_id=None, image_id=None)
    except Exception:
        return None


def _build_observation(cfg, deps, state, img_id, stage, phase, now,
                       tick_seconds=60):
    """Build the state-first v2 `telemetry_observation` envelope for an assigned
    heartbeat, and — when the state is `observed` — checkpoint the incremented
    sample_seq BEFORE returning it, so the heartbeat POST that carries the seq
    is idempotent across a crash (spec §2/§3A). Best-effort: any failure returns
    (None, None) so the heartbeat still goes out (telemetry never breaks it).

    obs_state decision (per run_once path / config):
      * telemetry master toggle off        -> disabled
      * stream toggle off / stream paused  -> paused
      * cadence not due this tick           -> not_due
      * aria RPC/no matching download       -> rpc_unavailable
      * a fresh aria snapshot taken        -> observed (+aria +peers +sampling)
    A state-only envelope invents no transfer fields. Returns (envelope, peers)
    where peers is the getPeers rows only for `observed` (reused by the tick)."""
    try:
        if not telemetry_report.enabled(cfg):
            # Telemetry master toggle off: emit a state-only `disabled` envelope
            # WITHOUT minting/persisting any transfer identity (an off device
            # has no live transfer telemetry and must not touch tele state).
            return _not_active_observation(False, now), None
        transfer_id = telemetry_report.ensure_transfer_id(state, img_id)
        st = state.setdefault(img_id, {})
        tele = st.setdefault("tele", {})

        def envelope(obs_state, sample_seq=None, aria_session_id=None,
                     sampling_class=None, stats=None, peers=None):
            return telemetry_report.build_observation(
                obs_state=obs_state, observed_at=now,
                transfer_id=transfer_id, image_id=img_id,
                sample_seq=sample_seq, aria_session_id=aria_session_id,
                sampling_class=sampling_class, stats=stats, peers=peers)

        def state_envelope(obs_state):
            seq = telemetry_report.next_sample_seq(state, img_id)
            if not _checkpoint_or_skip(
                    deps, state, "TELEMETRY-CKPT",
                    "%s sample_seq checkpoint failed" % img_id):
                tele["sample_seq"] = seq - 1
                return None
            return envelope(obs_state, sample_seq=seq)

        # Only live-transfer phases carry an aria snapshot; steady seeding uses
        # the RPC-free path and reports not_due (last value ages to stale).
        if phase not in ("downloading", "seeding-only"):
            return state_envelope("not_due"), None
        if not telemetry_report.stream_enabled(cfg):
            return state_envelope("paused"), None
        tier = telemetry_report.classify(state, tele.get("avg_bps"))
        _every, paused = telemetry_report.active_directives(
            state, now, tick_seconds=tick_seconds)
        if paused:
            return state_envelope("paused"), None
        if not telemetry_report.should_sample(
                state, tele, tier, now, tick_seconds=tick_seconds):
            return state_envelope("not_due"), None
        stats = deps.aria_stats(stage)
        peers = deps.aria_peers(stage)
        if not stats:
            # RPC unreachable / no matching download: never retain an old rate.
            return state_envelope("rpc_unavailable"), None
        session = None
        get_session = getattr(deps, "aria_session", None)
        if callable(get_session):
            session = get_session()
        sampling_class = telemetry_report.sampling_class_of(
            state, tele.get("avg_bps"))
        # Increment + CHECKPOINT sample_seq BEFORE the observed heartbeat POST
        # so a crash-after-POST restart never rewinds/reuses the seq. A failed
        # checkpoint downgrades to not_due (nothing identity-bearing shipped
        # that could not be persisted) and rolls back the un-persisted seq.
        seq = telemetry_report.next_sample_seq(state, img_id)
        if not _checkpoint_or_skip(
                deps, state, "TELEMETRY-CKPT",
                "%s sample_seq checkpoint failed" % img_id):
            tele["sample_seq"] = seq - 1
            return None, None
        tele["stream_last_ts"] = now
        obs = envelope("observed", sample_seq=seq, aria_session_id=session,
                       sampling_class=sampling_class, stats=stats, peers=peers)
        return obs, peers
    except Exception:
        return None, None


def _send_frozen_report(cfg, deps, state, img_id, now):
    """Send the completion/seeding v2 report, freezing it on the first attempt.

    The full payload (body + report_id + report_created_at) is frozen in state
    and CHECKPOINTED durably BEFORE the first POST (spec §2), so a crash after
    the POST but before the outer final save restarts with the SAME frozen
    report/id and re-sends it byte-for-byte (the server dedupes by report_id).
    Every retry re-sends the identical frozen object. Returns True on delivery.
    A checkpoint failure skips the POST (no unpersisted identity shipped)."""
    frozen = telemetry_report.frozen_report(state, img_id)
    if frozen is None:
        tele = (state.get(img_id) or {}).get("tele") or {}
        transfer_id = telemetry_report.ensure_transfer_id(state, img_id)
        report = telemetry_report.build_report_v2(
            cfg, state, img_id, tele.get("event") or "staging-complete", now,
            transfer_id, telemetry_report.mint_id())
        frozen = telemetry_report.freeze_report(state, img_id, report)
        if not _checkpoint_or_skip(
                deps, state, "TELEMETRY-CKPT",
                "%s report freeze checkpoint failed" % img_id):
            return False
    return _send_report(cfg, deps, state, img_id, frozen)


def _send_pull_report(cfg, deps, state, img_id, request_id, now):
    """Send a pull v2 report for the server's report_request_id (spec §10.2b).

    A NEW request_id mints a fresh random report_id, freezes an immutable pull
    payload keyed by that request, and CHECKPOINTS it BEFORE the POST; a repeat
    of the same request reuses the identical frozen body. Returns True on
    delivery."""
    frozen = telemetry_report.frozen_pull_report(state, request_id)
    if frozen is None:
        transfer_id = telemetry_report.ensure_transfer_id(state, img_id)
        report = telemetry_report.build_report_v2(
            cfg, state, img_id, "pull", now, transfer_id,
            telemetry_report.mint_id(), report_request_id=request_id)
        frozen = telemetry_report.freeze_pull_report(state, request_id, report)
        if not _checkpoint_or_skip(
                deps, state, "TELEMETRY-CKPT",
                "%s pull report freeze checkpoint failed" % img_id):
            return False
    return _send_report(cfg, deps, state, img_id, frozen)


def _arm_terminal_report(state, img_id, tele, event, drop_frozen):
    """Arm ONE terminal v2 report for this image and record WHICH TRANSFER it
    speaks for.

    report_transfer_id is the whole of the bookkeeping: the server matches a
    report to a plan by transfer_id alone, so "the last terminal report was
    armed under id X" is the only fact that can answer "does the server have
    completion evidence for the transfer this image is on RIGHT NOW". It is
    read back in exactly one place — the identity branch below — and it is
    carried across a plan boundary with the frozen body it describes.

    `drop_frozen` discards an armed-but-unsent payload so the report re-freezes
    under the event/id being armed now. It is False for the seeding-only arm,
    which never overwrites a body already frozen for this transfer.

    REFUSES TO ARM OVER A DIFFERENT TRANSFER'S STILL-UNDELIVERED REPORT
    (board #110). adopt_plan's plan-boundary carry (the "CARRY AN
    ARMED-BUT-UNDELIVERED TERMINAL REPORT" block) hands a still-pending,
    already-frozen report forward across the boundary specifically so it is
    not lost — but 'event' is deliberately NOT part of that carry, so the very
    same tick that crosses the boundary can also satisfy this function's own
    'copied'/'seeding-only' arming condition for the NEW transfer, land here
    with drop_frozen=True, and destroy the carried body before it was ever
    sent. That happens on the ordinary SUCCESS path of a replan re-verify (see
    test_replan_verify.py) — the mismatch sibling already avoids this only
    because a failed re-hash returns before any arm is attempted at all.

    Both repairs available have a real, disclosed cost (board #110's write-up):
    keeping a small queue of frozen bodies is a state-shape change, and
    deferring the new arm can leave a transfer's own completion unreported for
    up to MAX_ATTEMPTS backoff ticks if the carried report's link tier is
    'bad'. This picks the deferral: the carried report is already frozen and
    due to be (re)tried by THIS SAME tick's pending-report pass a few lines
    below, so the ordinary cost is one tick's delay, not the full backoff: the
    old report goes first, and the moment it clears (delivered, or gives up
    after MAX_ATTEMPTS) report_pending is False and this same call arms the
    new transfer's report normally, on the very next tick. Nothing is lost
    either way: the new transfer's 'event' is never set to a terminal value
    here, so it keeps re-offering itself on every tick until it is actually
    armed."""
    new_tid = telemetry_report.ensure_transfer_id(state, img_id)
    if (drop_frozen and tele.get("report_pending")
            and tele.get("frozen_report") is not None
            and tele.get("report_transfer_id") not in (None, new_tid)):
        return
    tele["event"] = event
    tele["report_pending"] = True
    tele["report_attempts"] = 0
    tele["report_next_ts"] = 0.0
    tele["report_transfer_id"] = new_tid
    if drop_frozen:
        tele.pop("frozen_report", None)


def _telemetry_tick(cfg, deps, state, img_id, stage, phase, hb_resp, now,
                    peers=None, tick_seconds=60):
    """Per-tick telemetry glue (issue #13). phase is which run_once path is
    calling: 'downloading' | 'seeding-only' | 'copied' | 'steady' | 'no-space'.

    BEST-EFFORT: wrapped whole, because it runs AFTER the tick's real work is
    committed and a raise here would discard the persisted state (same
    rationale as _send_heartbeat). Collection is confined to live-transfer
    phases + the one-time completion snapshot; the steady-state tick stays
    aria2-RPC-free unless the server explicitly pulled (locked minimal-churn
    behavior)."""
    try:
        if not telemetry_report.enabled(cfg):
            return
        drain = getattr(deps.catalog, "drain_rtts", None)
        if callable(drain):
            for r in drain():
                telemetry_report.record_rtt(state, r)
        # A failed heartbeat is a live link-quality signal (the spec's
        # "heartbeat-failure streak"): count it toward the bad-tier streak.
        # A DELIVERED heartbeat resets it: the streak measures the catalog
        # link, and a 200 on that same link is the proof it is back. It used
        # to be reset only by a delivered REPORT, so one three-tick catalog
        # outage left the tier `bad` for the life of the state file and every
        # later terminal report was deferred behind it until the 60-attempt
        # give-up — nothing but a console pull could clear it. The old-server
        # case that rule guarded (heartbeats fine, report POSTs 404) is carried
        # by the SEPARATE report_fail_streak and the report's own attempt
        # backoff, both untouched here.
        if hb_resp is None:
            telemetry_report.record_failure(state)
        else:
            telemetry_report.record_success(state)
        # Streaming directives ride every heartbeat response; overwrite-always
        # persistence with 3-tick freshness (spec section 5.4).
        telemetry_report.store_directives(state, hb_resp, now)
        st = state.setdefault(img_id, {})
        tele = st.setdefault("tele", {})
        if phase == "downloading" and "started_ts" not in tele:
            tele["started_ts"] = now
        if phase in ("downloading", "seeding-only"):
            telemetry_report.observe_peers(
                tele, peers if peers is not None else deps.aria_peers(stage),
                now)
        if phase in ("copied", "seeding-only") and not tele.get("done_ts"):
            # Take ONE final participation sample first so peers connected at
            # the end of a fast download still land in the observed set (the
            # seeding-only path already sampled this tick above). Best-effort:
            # a peer-RPC hiccup here must never block marking done.
            if phase == "copied":
                try:
                    telemetry_report.observe_peers(
                        tele, deps.aria_peers(stage), now)
                except Exception:
                    pass
            # Fold in the hook's exact per-peer byte snapshot BEFORE done_ts,
            # which is the point the terminal report freezes. This is the one
            # measurement the sampler above structurally cannot make: a peer
            # that connected and dropped between two 60 s ticks is invisible
            # to it, whatever keys it asks for.
            _ingest_peer_transfer_records(deps, tele, stage, now)
            tele["done_ts"] = now
            stats = deps.aria_stats(stage)
            if stats:
                completed = int(stats.get("completedLength", 0) or 0)
                tele["total_bytes"] = completed
                # v2 content-at-end fields (spec §3D): not a "bytes transferred"
                # claim. total is the torrent's declared totalLength when known.
                tele["completed_content_bytes"] = completed
                tele["total_content_bytes"] = int(
                    stats.get("totalLength", completed) or completed)
            elapsed = max(now - tele.get("started_ts", now), 0.0)
            tele["elapsed_s"] = elapsed
            if elapsed > 0 and tele.get("total_bytes"):
                # avg_bps kept ONLY as an internal classifier input; retired as
                # an authoritative v2 report field.
                tele["avg_bps"] = int(tele["total_bytes"] / elapsed)
        # Arm exactly one completion report per image. staging-complete
        # upgrades an armed-but-unsent seeding-only report (the copy gate
        # cleared on a later tick).
        if phase == "copied" and st.get("copied") \
                and tele.get("event") != "staging-complete":
            # Discard any armed-but-unsent seeding-only frozen payload so the
            # report re-freezes with the upgraded staging-complete event/id.
            _arm_terminal_report(state, img_id, tele, "staging-complete",
                                 drop_frozen=True)
        elif phase == "seeding-only" and not tele.get("event"):
            _arm_terminal_report(state, img_id, tele, "seeding-only",
                                 drop_frozen=False)
        else:
            # AN ALREADY-STAGED IMAGE ATTESTS ITSELF ONCE UNDER A NEW TRANSFER
            # IDENTITY (board #30). The two arms above are the only ones that
            # ever fire, and both are reachable only from the download path's
            # completion tick. An image that is ALREADY done AND copied when a
            # new identity lands on it takes the steady-state short-circuit
            # instead, so the server was left holding a plan it could never
            # promote: no report anywhere names that transfer, while the bytes
            # it is waiting for sit finished on the device.
            #
            # The trigger is a MEASURED difference, not a schedule: a terminal
            # report was armed under one id and the image is now on another.
            # That is why it cannot stampede. An absent report_transfer_id
            # (every state file written before this key existed) is read as
            # "already reported", the conservative answer — so the first tick
            # after an agent upgrade arms nothing for a steady device, and the
            # only devices that arm here are the ones whose identity genuinely
            # changed under an already-staged image. Even those send one small
            # POST, jittered, never a hash.
            #
            # A report still PENDING is left strictly alone: its frozen body is
            # a finished statement about whichever transfer it names, and
            # re-arming would destroy it. Once it is delivered this branch is
            # reached again on a later tick and the new identity gets its own.
            tid = telemetry_report.ensure_transfer_id(state, img_id)
            reported = tele.get("report_transfer_id")
            if (st.get("done") and st.get("copied")
                    and not tele.get("report_pending")
                    and reported is not None and reported != tid):
                _arm_terminal_report(state, img_id, tele, "staging-complete",
                                     drop_frozen=True)
                deps.emit("TELEMETRY",
                          "%s re-attesting staged image under transfer %s"
                          % (img_id, tid))
        # GUI pull: fresh report THIS tick, independent of the pending
        # report's backoff. On a steady tick the pull re-sends the COMPLETED
        # transfer's observed peer set FROZEN — deliberately NO fresh sample
        # (a steady tick never calls observe_peers). Historical rationale
        # (hardware-observed, pre-2026.07.04.7): the old rate-integrating
        # sampler took a sparse pull-time reading and extrapolated one
        # instantaneous speed across a stalled-tick clamp window, MUTATING a
        # finished transfer's table (~12 GB phantom tx on a 1.26 GB image
        # across three pulls, with the neighbor injected as a bogus rx row via
        # the even-split fallback) — the reason observe_peers no longer
        # tracks bytes at all. No local retry bookkeeping: the server keeps
        # the directive until a report ARRIVES, so a failed send is
        # re-flagged on the next heartbeat anyway.
        # GUI pull (v2): the server mints a per-request report_request_id
        # (§10.2b). On a NEW request id the agent mints a FRESH random report_id,
        # freezes an immutable pull payload for that request, CHECKPOINTS it
        # BEFORE the POST, and retries it byte-for-byte; a repeat of the SAME
        # request id reuses the identical frozen body (so repeated console pulls
        # never collide). A steady tick re-sends the completed transfer's frozen
        # observed peer set — never a fresh sample.
        request_id = telemetry_report.pull_request_id(hb_resp)
        if request_id is not None:
            _send_pull_report(cfg, deps, state, img_id, request_id, now)
        elif telemetry_report.pull_requested(hb_resp):
            # Legacy pull directive without a request_id: fall back to a fresh
            # per-tick v2 report (no freeze key available).
            transfer_id = telemetry_report.ensure_transfer_id(state, img_id)
            report = telemetry_report.build_report_v2(
                cfg, state, img_id, "pull", now, transfer_id,
                telemetry_report.mint_id())
            _send_report(cfg, deps, state, img_id, report)
        # Pending completion/seeding report (v2): tier-gated backoff, frozen once.
        if tele.get("report_pending") and now >= tele.get("report_next_ts", 0):
            if tele.get("report_attempts", 0) >= telemetry_report.MAX_ATTEMPTS:
                tele["report_pending"] = False
                deps.emit("TELEMETRY-FAIL", "%s report giving up after %d attempts"
                          % (img_id, telemetry_report.MAX_ATTEMPTS))
            else:
                tier = telemetry_report.classify(state, tele.get("avg_bps"))
                if tier == "bad":
                    tele["report_attempts"] = tele.get("report_attempts", 0) + 1
                    tele["report_next_ts"] = telemetry_report.next_backoff_ts(
                        tele["report_attempts"] - 1, now,
                        tick_seconds=tick_seconds)
                elif _send_frozen_report(cfg, deps, state, img_id, now):
                    tele["report_pending"] = False
                    tele["report_sent_ts"] = now
                else:
                    tele["report_attempts"] = \
                        tele.get("report_attempts", 0) + 1
                    tele["report_next_ts"] = telemetry_report.next_backoff_ts(
                        tele["report_attempts"] - 1, now,
                        tick_seconds=tick_seconds)
    except Exception as e:
        try:
            deps.emit("TELEMETRY-FAIL", "telemetry tick failed (ignored): %s" % e)
        except Exception:
            pass


def _protect_set(image, state):
    """Files reclaim must never delete: the running image (added by the caller,
    which is the only place that knows it), the image being staged (+ its
    torrent/aria2 sidecars), and every root copy IRIS placed for an image still
    IN the assigned set. Freeing space for one image of a set must never eat
    another image of the same set.

    PARKED root copies are deliberately NOT protected. Park keeps them, but
    keeps them the way a replaced image's copy is kept: available to the
    reclaim gate the moment a newly checked image needs the room. Protecting
    them here made the "kept until space is needed" half of the uncheck
    contract unreachable — a device with a full boot filesystem had nothing
    left it was allowed to free, so it reported flash_full forever no matter
    how many images the operator unchecked. An image that comes back into the
    set is un-parked before this runs (_reconcile_set), so it is protected
    again by its membership, not by its flag."""
    keep = {image["filename"], image["filename"] + ".aria2",
            image["id"] + ".torrent"}
    rf = state.get("root_file")
    if rf:
        keep.add(rf)
    for value in state.values():
        if (isinstance(value, dict) and value.get("root_file")
                and not value.get("parked")):
            keep.add(value["root_file"])
    return keep


def _reset_copy_failures(st):
    # copy_reclaim_tried/reclaim_tried (scrubber #139) join the reset: both are
    # once-EVER guards (nothing else ever clears them) that exist only to stop
    # a still-too-full device from stacking reclaim attempts WITHIN one
    # acquisition cycle. Every call site of this function starts a genuinely
    # NEW cycle — a content republish under the same id, an image coming back
    # from park, or this image's own placement having just succeeded — so a
    # low-space device deserves one fresh reclaim attempt for it too, exactly
    # like copy_attempts/copy_terminal get a clean slate here. Leaving them
    # set would mean a device that burned its once-guard on an EARLIER
    # image's content can never reclaim again for this id, permanently.
    for key in ("copy_attempts", "copy_next_ts", "copy_terminal", "stage_error",
                "ios_copy_started", "copy_reclaim_tried", "reclaim_tried",
                "root_adopt_checked"):
        st.pop(key, None)


def _copy_backoff(attempts):
    return min(_ROOT_COPY_BACKOFF_BASE * (2 ** max(attempts - 2, 0)),
               _ROOT_COPY_BACKOFF_MAX)


def _reclaim_failed_root_copy(deps, target_prefix, image):
    """Delete only IRIS's reserved temp root copy.

    The retry path calls this once on its transition into copy_terminal. The
    Guest Shell same-name recovery also calls it after SHA-attesting an already
    correct real destination, when an earlier no-op rename left the proven temp
    bytes beside it. Both call sites target only the reserved temp suffix.

    Why it has to happen here: after copy_terminal is set, no further copy
    fires, so the placement path's delete-first never runs again. Without this
    the leftover sits at the boot-FS root indefinitely.

    WHAT IS LEFT TO RECLAIM, under the corrected placement sequence: every
    copy attempt (_copy_to_root_impl / _copy_to_root_direct_impl) now stages
    its bytes under a RESERVED TEMP NAME (_root_copy_tmp_name) and touches the
    REAL image name only in its very last step — a rename, gated on this
    agent's own verified-good check of the temp copy, and only reached once
    that check has passed. A cycle that goes terminal can therefore only have
    left debris under the temp name: the real name is never deleted or
    overwritten by a failed attempt, so this function must never touch it —
    and does not: everything below acts on _root_copy_tmp_name(fname), never
    on fname itself.

    WHY A DELETE HERE CAN BE SAFE: a placement attempt that reached IOS begins
    with `delete /force <FS><temp name>` — the IRIS-COPYROOT applet's action
    020 on the Guest Shell path, the vty command on the direct path. So a file
    present at the temp name after such an attempt fails can only be the
    partial THAT attempt (or an earlier one that also never finished) wrote.

    THAT INVARIANT DOES NOT HOLD UNCONDITIONALLY, and this function must never
    assume it. Attempts that fail BEFORE any IOS command — the running-image
    refusals, an scp push that raised, an applet run that never fired — delete
    nothing. Two independent layers keep the real image name (and, by
    construction, the temp name too) safe:

      Layer 1 (terminal caller): run_once only calls this on terminal failure
        when at least one attempt in this image's cycle came back a genuine
        post-delete-first False (st["ios_copy_started"]);
        ROOT_COPY_NOT_ATTEMPTED never sets it. The adoption caller is narrower
        still: it has locally SHA-attested the untouched real destination and
        observed the reserved temp name left beside it.
      Layer 2 (below): defence in depth, not the primary guarantee — the temp
        name is `fname` plus a reserved suffix
        (flash_target.ROOT_COPY_TMP_SUFFIX) that no real Cisco image or
        catalog-published name is expected to carry, so it cannot coincide
        with the running image or the BOOT target by construction alone.
        These reads are kept anyway, on the same footing as every other
        destructive reclaim in this file: an unreadable fact still means
        refuse rather than guess, even for a name that should never match.

    Stage-only: this reclaims exactly one name — IRIS's own failed copy — and
    is reclamation, not install activity. Best-effort; a delete that raises is
    logged and swallowed, since the terminal state is already reported."""
    fname = image["filename"]
    tmp = _root_copy_tmp_name(fname)
    # ---- Layer 2: independent last-line check, before ANY delete is issued ----
    try:
        running = deps.running_image()
    except Exception as e:
        deps.emit("ROOTCOPY-RECLAIM-REFUSED",
                  "%s temp copy left at %s%s: running image unknown "
                  "(show version read raised: %s) — refusing a delete that "
                  "cannot be proven safe" % (fname, target_prefix, tmp, e))
        return
    if not running:
        deps.emit("ROOTCOPY-RECLAIM-REFUSED",
                  "%s temp copy left at %s%s: running image unknown — "
                  "refusing a delete that cannot be proven safe"
                  % (fname, target_prefix, tmp))
        return
    if _ios_basename(running).casefold() == tmp.casefold():
        deps.emit("ROOTCOPY-RECLAIM-REFUSED",
                  "%s temp copy left at %s%s: it IS the running image (%s) — "
                  "refusing destructive delete"
                  % (fname, target_prefix, tmp, running))
        return
    # ---- Layer 2b: the BOOT variable, same rule, same footing ----
    # An unreadable BOOT variable refuses for the reason an unknown running
    # image does: no protect set can be built, so no delete may run.
    boot = _boot_target(deps)
    if boot is None:
        deps.emit("ROOTCOPY-RECLAIM-REFUSED",
                  "%s temp copy left at %s%s: BOOT variable unknown — "
                  "refusing a delete that cannot be proven safe"
                  % (fname, target_prefix, tmp))
        return
    if _is_boot_target(boot, tmp):
        deps.emit("ROOTCOPY-RECLAIM-REFUSED",
                  "%s temp copy left at %s%s: it is the BOOT target — "
                  "refusing destructive delete; the failed copy is left for "
                  "the operator" % (fname, target_prefix, tmp))
        return
    try:
        deps.reclaim_bundle(target_prefix, [tmp])
    except Exception as e:
        deps.emit("ROOTCOPY-RECLAIM-FAIL",
                  "%s failed placement left at %s%s; delete raised: %s"
                  % (fname, target_prefix, tmp, e))
        return
    deps.emit("ROOTCOPY-RECLAIM",
              "%s placement gave up; deleted this attempt's partial copy "
              "from %s%s" % (fname, target_prefix, tmp))


def _try_adopt_guestshell_root(cfg, deps, image, target_prefix):
    """Attest a pre-existing IOS root file through native IOS size and SHA.

    Returns ``("adopted", None)`` only after the root bytes have the catalog
    size and SHA-512 and any IRIS-reserved ``.iris-tmp`` leftover is confirmed
    gone. ``("absent", None)`` means ordinary copy placement may proceed.
    ``("not-applicable", None)`` keeps noncanonical Guest Shell mounts and
    platforms without an IOS CLI (xr-appmgr) on their existing placement
    path. Every ambiguous read or content mismatch returns ``("blocked",
    <operator-facing error>)`` without touching the real destination.

    Applies to the Guest Shell AND the IOx app (`device_platform = iox`):
    both place by copying to a reserved temp name and renaming it over the
    real name, and IOS-XE `rename` refuses an existing destination outright
    — observed verbatim on an IE-3400-8T2S running 17.15.4 with `file prompt
    quiet`, staging to sdflash: (`%Error renaming ... (File exists)`), where
    every placement attempt re-pushed and re-copied the image only to have
    Phase 2 refused, until the retry budget ran out. Attesting the existing
    root file first (native size + SHA-512) adopts a byte-identical one and
    leaves a different one alone with a precise error, instead of burning
    four full copies on a rename IOS will never perform.

    The only cleanup this path can request is the established guarded reclaim
    of ``<filename>.iris-tmp`` — plus, on IOx only, IRIS's own scp-pushed
    scratch under ``<FS>guest-share/iris/`` once adoption has succeeded (the
    same source the direct copy path deletes after a verified placement; the
    swarm seeds from the CAF-persistent stage_dir, so it is a transfer
    intermediary, not the seeding file). It never submits the real filename
    to an IOS delete or rename command.
    """
    platform = cfg.get("device_platform")
    fname = image["filename"]
    if platform == "iox":
        root_path = _iox_root_ios_path(target_prefix, fname)
    elif platform:
        return "not-applicable", None
    else:
        root_path = _guestshell_root_ios_path(
            cfg.get("stage_dir"), target_prefix, fname)
    if root_path is None:
        return "not-applicable", None

    try:
        observed = deps.root_file_size(fname, target_prefix)
    except Exception as e:
        error = ("existing IOS root file could not be inspected safely: %s"
                 % e)
        deps.emit("ROOTCOPY-ADOPT-REFUSED", "%s: %s" % (fname, error))
        return "blocked", error
    if observed is None:
        return "absent", None
    expected = int(image["size"])
    if observed != expected:
        error = ("existing IOS root file has size %d, expected %d; left in place"
                 % (observed, expected))
        deps.emit("ROOTCOPY-ADOPT-REFUSED", "%s: %s" % (fname, error))
        return "blocked", error

    try:
        digest = image.get("sha512")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{128}", digest):
            raise ValueError("catalog SHA-512 is missing or malformed")
        matches = deps.verify_root(fname, target_prefix, digest)
    except Exception as e:
        error = ("existing IOS root file SHA-512 could not be verified: %s"
                 % e)
        deps.emit("ROOTCOPY-ADOPT-REFUSED", "%s: %s" % (fname, error))
        return "blocked", error
    if not matches:
        error = ("existing IOS root file SHA-512 does not match the catalog; "
                 "left in place")
        deps.emit("ROOTCOPY-ADOPT-REFUSED", "%s: %s" % (fname, error))
        return "blocked", error

    tmp_name = _root_copy_tmp_name(fname)
    try:
        if deps.root_file_size(fname, target_prefix) != expected:
            raise ValueError("IOS root size changed during SHA-512 verification")
        tmp_size = deps.root_file_size(tmp_name, target_prefix)
    except Exception as e:
        error = ("IRIS temp-copy state could not be inspected safely: %s" % e)
        deps.emit("ROOTCOPY-ADOPT-REFUSED", "%s: %s" % (fname, error))
        return "blocked", error
    if tmp_size is not None:
        _reclaim_failed_root_copy(deps, target_prefix, image)
        try:
            tmp_size = deps.root_file_size(tmp_name, target_prefix)
        except Exception as e:
            error = ("IRIS temp-copy cleanup could not be confirmed: %s" % e)
            deps.emit("ROOTCOPY-ADOPT-REFUSED", "%s: %s" % (fname, error))
            return "blocked", error
        if tmp_size is not None:
            error = ("verified IOS root file retained, but IRIS temp copy "
                     "remains; cleanup must succeed before adoption")
            deps.emit("ROOTCOPY-ADOPT-REFUSED", "%s: %s" % (fname, error))
            return "blocked", error

    if platform == "iox":
        # The IOx placement path scp-pushes the staged file to
        # <FS>guest-share/iris/<fname> ahead of every copy attempt and deletes
        # it only after a verified placement (_copy_to_root_direct_impl's
        # delete_source_on_success). Adoption IS that verified placement,
        # minus the copy, so reclaim the push the same way — otherwise the
        # failed attempts that led here leave a full duplicate image on the
        # target FS for good. IRIS's own scratch name, never the real file.
        # reclaim_bundle on this platform is a plain `delete /force` per
        # name on the vty; harmless when nothing was pushed.
        try:
            deps.reclaim_bundle(target_prefix, ["guest-share/iris/" + fname])
        except Exception:
            pass
    deps.emit("ROOTCOPY-ADOPTED",
              "%s already exists at %s with catalog size and SHA-512; "
              "adopted without replacement" % (fname, target_prefix))
    return "adopted", None


def _ios_basename(path):
    return (path or "").rsplit(":", 1)[-1].rsplit("/", 1)[-1]


def _boot_target(deps):
    """Basename of the file the device boots NEXT — the BOOT variable — or
    None when it cannot be known. This is NOT the running image: staging
    exists so an operator can point BOOT at a placed image for a later
    maintenance window, and that image may since have left the assigned set
    (parked, root copy deliberately reclaimable) or never have been IRIS's at
    all. Deleting it strands the next reload in rommon without a single boot
    or install command being issued, which is the stage-only invariant's
    outcome by another road. deps.boot_image answers "" when IOS reports no
    BOOT target; a raise or None is folded into None, which every caller
    treats exactly like an unknown running image: no destructive work."""
    try:
        boot = deps.boot_image()
    except Exception:
        return None
    if boot is None:
        return None
    return _ios_basename(str(boot))


def _is_boot_target(boot, fname):
    return bool(boot) and boot.casefold() == (fname or "").casefold()


def install_reclaim_refused(output):
    """True when IOS refused to START `install remove inactive`.

    A device that already holds the install lock answers the command itself
    with "FAILED: cannot start new install operation, some operation is
    already running" and does nothing. `show install summary` does NOT report
    that state -- verified on a C9300 stack running IOS-XE 17.18.3 whose
    summary listed only committed packages and an inactive auto-abort timer
    while the very next `install remove inactive` was refused -- so the
    pre-check cannot see it and the refusal is only visible in the output of
    the attempt.

    That matters because the caller's once-guard is burned on a True return:
    treating a refusal as a successful reclaim permanently disables reclaim
    for that image, which is exactly what _reclaim_for_mode's contract says
    must never happen. Pure and matched loosely (case-insensitive, on the two
    stable halves of the message) so a version's punctuation drift cannot
    turn a refusal back into a false success."""
    low = (output or "").casefold()
    return ("cannot start new install operation" in low
            or "operation is already running" in low)


def _reclaim_for_mode(deps, mode, target_prefix, image, state):
    """Free space by mode. Returns True ONLY if a reclaim action actually ran,
    so a caller's once-guard is never burned on a no-op (otherwise a transient
    glitch could permanently disable reclaim).

      install       -> `install remove inactive`.
      bundle        -> delete UNUSED image artifacts, but ONLY when the running
                       image is confirmable. detect_mode() can resolve "bundle"
                       from `show boot` alone, while running_image() reads only
                       `show version`; if `show version` glitched, running_image()
                       is None and we CANNOT build a safe protect-set — so we
                       skip rather than risk deleting the running image. (#4
                       safety: never delete when the running image is unknown.)
      unknown(None) -> skip (never run a destructive op when mode is uncertain).

    Bundle mode protects the BOOT variable's target on the same footing as the
    running image (_boot_target): it is the file the device boots NEXT, and a
    parked image's root copy — deliberately reclaimable — is exactly what an
    operator may have pointed BOOT at for a later maintenance window. An
    unreadable BOOT variable skips like an unknown running image does.

    A skip/no-op returns False so the next tick retries once the transient
    clears."""
    if mode == "install":
        # Report what actually happened. A device that already holds the
        # install lock refuses the command outright, and returning True there
        # burns the caller's once-guard on a no-op -- permanently disabling
        # reclaim for that image on a device whose lock will clear by itself.
        # deps.reclaim() returns False on a refusal, None on older Deps.
        return deps.reclaim() is not False
    if mode == "bundle":
        running = deps.running_image()
        if running is None:
            return False
        boot = _boot_target(deps)
        if boot is None:
            deps.emit("RECLAIM-DEFERRED",
                      "bundle reclaim skipped: BOOT variable unreadable, so "
                      "no safe protect set can be built")
            return False
        protect = _protect_set(image, state)
        protect.add(running)
        if boot:
            protect.add(boot)
        names = deps.reclaimable(target_prefix, protect)
        if names:
            deps.reclaim_bundle(target_prefix, names)
            return True
    return False


class _ImageTick:
    """One image's deferred heartbeat + telemetry work for this tick.

    The device is ONE row on the server, so an assigned set of images still
    gets ONE heartbeat per tick — but its stage_state and staged_image_ids are
    facts about the whole set, and cannot be settled until every image has been
    checked. So _stage_image() decides what it would report, exactly where it
    always did, and records the _heartbeat() arguments here; run_once()
    composes the single payload, POSTs it, and replays the telemetry against
    the response.

    For a one-image set this is a pure deferral: the same payload, built from
    the same arguments, POSTed at the same point in the tick (nothing runs
    between the end of the loop and the POST), followed by the same telemetry
    tick with the same response."""

    __slots__ = ("hb", "tele", "stage_state", "stage_error",
                 "tick_seconds")

    # Index of _telemetry_tick()'s hb_resp parameter in the recorded call.
    _HB_RESP_ARG = 6

    def __init__(self, tick_seconds=60):
        self.hb = None
        self.tele = None
        self.stage_state = None
        self.stage_error = None
        self.tick_seconds = _normalize_tick_seconds(tick_seconds)

    def heartbeat(self, *args, **kwargs):
        """Record this image's _heartbeat() call. Returns None because the
        server's answer does not exist yet — replay() substitutes the real
        response into the telemetry call that consumes it."""
        self.hb = (args, kwargs)
        # What this image would have reported on its own, kept out here so the
        # set-level aggregate never has to re-run _heartbeat's device reads.
        self.stage_state = (args[2] if len(args) > 2
                            else kwargs.get("stage_state", "staging"))
        self.stage_error = kwargs.get("stage_error")
        return None

    def telemetry(self, *args, **kwargs):
        kwargs["tick_seconds"] = self.tick_seconds
        self.tele = (args, kwargs)

    def build(self, staged_image_ids=None, errored_image_ids=None):
        args, kwargs = self.hb
        return _heartbeat(*args, staged_image_ids=staged_image_ids,
                          errored_image_ids=errored_image_ids, **kwargs)

    def replay(self, hb_resp):
        if self.tele is None:
            return
        args, kwargs = self.tele
        args = list(args)
        args[self._HB_RESP_ARG] = hb_resp
        _telemetry_tick(*args, **kwargs)


# Top-level state keys that are NOT per-image records: scalars the agent keeps
# about the device, plus telemetry's own bags. Everything else that looks like
# an image record (below) is keyed by image id.
_RESERVED_STATE_KEYS = frozenset((
    "schema_version", "image_id", "root_file", "stage_fs",
    "pending_root_deletes", "link", "frozen_pull", "stream_directives",
    "instructions"))

# Fields only a per-image record carries. Membership in the assigned set is
# not enough to recognise one: the park pass has to find records for images
# that are no longer assigned at all.
#
# 'origin' (Directive 2 / XR teardown hardening): how THIS placement's bytes
# reached the target-FS root — "downloaded" (this agent's own transfer wrote
# them) or "adopted" (attest-in-place confirmed bytes that were already
# there; nothing of ours moved them). Written once, at the same site that
# sets 'copied'/'root_file' on a successful copy_to_root. ADDITIVE: a state
# file from before this field existed simply lacks it, and every deletion
# path below treats a missing origin exactly like "adopted" — fail-safe, so
# an unproven placement is never the thing IRIS deletes.
# 'download_started' is origin's own bookkeeping, not a fact anyone outside
# this module reads: it is set the moment THIS agent's aria2 session is
# asked to fetch an image (see the aria_add call site) and is what lets the
# copy-success site tell a genuine download apart from attest-in-place
# finding bytes it never touched.
_IMAGE_ENTRY_FIELDS = ("done", "copied", "sha", "tele", "root_file", "parked",
                       "copy_attempts", "copy_terminal", "copy_reclaim_tried",
                       "ios_copy_started", "reclaim_tried", "blocked_no_space",
                       "stage_error", "origin", "download_started",
                       "root_adopt_checked")


def _is_image_entry(value):
    return isinstance(value, dict) and any(k in value
                                           for k in _IMAGE_ENTRY_FIELDS)


def _image_filename(deps, entry, img_id):
    """The staged/placed filename of an image the loop is not staging.

    Prefer what the device already recorded (free, and still right for an
    image the catalog has since dropped), then ask the catalog. Returns None
    if neither answers, or if the answer fails the filename whitelist that
    guards every interpolation into an IOS command."""
    fname = (entry or {}).get("root_file")
    if not fname:
        try:
            image = deps.catalog.get_image(img_id)
        except Exception:
            image = None
        fname = (image or {}).get("filename")
    return fname if fname and _FILENAME_RE.match(fname) else None


def _root_file_origin(state, fname):
    """The recorded provenance of the per-image record that placed `fname`
    at the target-FS root, or None when no record claims it.

    pending_root_deletes carries bare filenames (not image ids), so the
    owning record has to be found by its root_file field rather than looked
    up directly. None here means exactly what a found record's missing
    'origin' means: unproven — every deletion site treats it as adopted."""
    for value in state.values():
        if _is_image_entry(value) and value.get("root_file") == fname:
            return value.get("origin")
    return None


def _protect_adopted_root(deps, entry, fname):
    """True when `entry` names `fname` as the root-FS placement it made,
    on a platform where that must never be agent-deleted: a platform whose
    copy_to_root is attest-in-place (deps.copy_in_place) succeeded WITHOUT
    this agent writing anything — origin 'adopted', or missing/legacy
    (fail-safe).

    Keyed on `root_file == fname` — the durable fact that THIS record IS
    the placement about to be deleted — rather than `copied`. `copied` is
    RECOMPUTED every tick from a fresh root_present() call (the steady-state
    self-heal) and goes False on nothing more than a transient size drift
    or a single stat miss, while `root_file`/`origin` do not move with that
    noise (reviewer PROBE1: keying on `copied` failed OPEN exactly when a
    placement's provenance was most in doubt). An entry with no root_file
    at all — never successfully placed, or already cleared — can never
    match here, which is what preserves ordinary cleanup of an in-progress
    or failed placement. A platform that physically writes its own root
    copy (copy_in_place=False) has no adoption path — see xr_deps' module
    docstring — so it is never protected here."""
    return bool(deps.copy_in_place and entry.get("root_file") == fname
               and entry.get("origin") != "downloaded")


def _reconcile_set(deps, state, ids, stage_dir):
    """Reconcile what is on the device against the assigned set, before staging.

    PARK — an image the device has state for that is no longer in the set:
    stop its torrent, delete its stage copy, mark the record parked. Its ROOT
    copy is deliberately KEPT. An image dropped from a set is not necessarily
    gone for good (sets are edited), and a surviving root copy turns re-adding
    it into a presence-and-size check instead of another ~1.2 GB placement.
    This replaces the old single-image reassignment cleanup, which queued the
    old root copy for deletion — the opposite call. (pending_root_deletes
    itself stays: state files written by that agent can still carry a queue,
    and the drain + its whitelist re-check still run.)

    On a platform whose stage dir IS the target-FS root (deps.copy_in_place,
    e.g. XR), "delete its stage copy" above and "the root copy is kept" are
    in direct conflict — there is only one file. _protect_adopted_root
    resolves that: an origin-'adopted' (or provenance-unknown) placement is
    left in place exactly like every other platform's root copy; only a
    placement this agent proved it downloaded is freed on park. Either way,
    downloaded origin/download_started are CLEARED on park (reviewer PROBE2): the
    acquisition cycle those facts describe ends the moment the image leaves
    the set, and an operator can restage a byte-identical file under the
    SAME name while it is gone — the steady-state short-circuit that will
    greet a reassignment never revisits copy_to_root, so a stale verdict
    left behind here would silently re-arm on the NEXT park.

    UN-PARK — a parked image back in the set: clear the flag and the placement
    retry gate, then let the normal path re-confirm it.

    The aria2/stage-dir sweep is re-scoped with it: purge_others() now keeps
    the WHOLE set. Called with one survivor it would delete the other assigned
    images' staged files."""
    # The old agent kept ONE top-level root_file, for its ONE image. Migrate it
    # into that image's own record — the park pass needs to know the filename
    # an image placed, and per-image is where placement is recorded now.
    legacy_root = state.get("root_file")
    legacy_id = state.get("image_id")
    if legacy_root and legacy_id and isinstance(state.get(legacy_id, {}), dict):
        state.setdefault(legacy_id, {}).setdefault("root_file", legacy_root)

    for img_id in ids:
        entry = state.get(img_id)
        if isinstance(entry, dict) and entry.pop("parked", None):
            # Back in the set: a durable placement failure from before must not
            # outlive the reassignment, exactly as a fresh assignment cleared it.
            _reset_copy_failures(entry)
            deps.emit("UNPARKED", "%s back in the assignment set; re-checking "
                                  "its staged and root copies" % img_id)

    stale = [k for k in state
             if k not in ids and k not in _RESERVED_STATE_KEYS
             and _is_image_entry(state[k]) and not state[k].get("parked")]
    if not stale and (not legacy_id or legacy_id in ids):
        return                            # set unchanged: nothing to park or sweep

    # What the sweep must spare: for every assigned image, the name the catalog
    # gives it NOW (the file being downloaded) and the name it already placed
    # (they differ if the image was republished under a new filename). An image
    # that resolves to neither leaves the sweep disarmed, below.
    keep_files = []
    resolved = 0
    for img_id in ids:
        names = []
        try:
            image = deps.catalog.get_image(img_id)
        except Exception:
            image = None
        for fname in ((image or {}).get("filename"),
                      (state.get(img_id) or {}).get("root_file")):
            if fname and _FILENAME_RE.match(fname) and fname not in names:
                names.append(fname)
        if names:
            resolved += 1
            keep_files.extend(names)
    keep = set(keep_files)

    for key in stale:
        entry = state[key]
        fname = _image_filename(deps, entry, key)
        # Never touch a file the assigned set claims. A catalog that answers
        # for a dropped id with an assigned image's filename (or two ids
        # sharing one filename) must not cost the set its staged bytes.
        if not fname or fname in keep:
            # NOTHING was attempted for this entry, so it is NOT parked. The
            # flag is what takes a record out of `stale`, so setting it here
            # retires an image whose torrent is still running and whose partial
            # still occupies flash — permanently, with no way back short of
            # hand-editing the state file. Leave the record alone and the next
            # tick re-runs the park, once the catalog can name the file again.
            #
            # UNLESS nothing could EVER change that answer (board #60): `fname
            # in keep` really is named, just legitimately protected by the
            # assigned set — that can hold for as long as the set says so, and
            # stays unbounded. `not fname`, though, means BOTH the record's own
            # root_file is unset AND the catalog has nothing to offer for this
            # id at all — no filename this agent could ever address a torrent
            # or a stage file by, on THIS tick or any future one, unless the id
            # somehow becomes nameable again (in which case it exits `stale`
            # via the ordinary un-park path next time, not this one). Bounded
            # instead of retried forever, and retiring the BOOKKEEPING record
            # here touches no file and stops no torrent — there was never a
            # name to touch or stop.
            if not fname:
                attempts = entry.get("park_defer_attempts", 0) + 1
                entry["park_defer_attempts"] = attempts
                if attempts >= _PARK_DEFER_MAX_ATTEMPTS:
                    deps.emit("PARK-GIVEUP",
                              "%s left the assignment set and was never "
                              "nameable (no root_file, catalog cannot answer "
                              "for it); giving up tracking it after %d ticks"
                              % (key, attempts))
                    del state[key]
                    continue
            deps.emit("PARK-DEFERRED",
                      "%s left the assignment set but its staged file could "
                      "not be named this tick; park retried next tick" % key)
            continue
        try:
            deps.aria_remove(fname)
        except OSError:
            # aria2 RPC down: best-effort. The stage copy still goes, and
            # the purge sweep below drops the download once the RPC is
            # back — a parked torrent must never stall the tick.
            pass
        # On every IOS-XE platform the stage dir is IRIS's own directory and
        # the root copy lives elsewhere entirely, so deleting the stage copy
        # here is always safe — that separation is the whole reason park can
        # promise to KEEP the root copy. A platform whose stage dir IS the
        # root (deps.copy_in_place, e.g. XR: attest_in_place writes no new
        # bytes because there is nowhere else to write them) has no such
        # separation: THIS delete would be a root delete, so an adopted (or
        # provenance-unknown) placement must be left exactly where it is —
        # the 2026-08-29 incident was an unassign doing this to an
        # operator-staged ISO. Only a copy this agent proved it downloaded is
        # still fair game; an in-progress/failed placement was never proven
        # to be anyone's root copy at all and is cleaned up as always.
        protected = _protect_adopted_root(deps, entry, fname)
        if protected:
            deps.emit("ROOTCOPY-KEPT",
                      "left in place: operator-adopted %s" % fname)
        else:
            try:
                deps.remove_stage(os.path.join(stage_dir, fname))
            except OSError:
                # Best-effort for the same reason: a stage copy that cannot be
                # deleted this tick still leaves a record whose torrent IS stopped,
                # and the purge sweep collects the file later.
                pass
        # BOTH park actions have now been attempted for this entry, which is
        # exactly what the flag asserts. A park interrupted before this point
        # (anything later in the tick raising) leaves the record unflagged and
        # re-runs from the top next tick.
        entry["parked"] = True
        # The top-level root_file is the LEGACY mirror for the set's FIRST
        # image. Parking that image makes it stale: _protect_set and every
        # legacy reader would pair this file with whatever image_id the new set
        # goes on to write. Move it into the record that actually owns it.
        if state.get("root_file") == fname:
            entry.setdefault("root_file", fname)
            state.pop("root_file", None)
        # The acquisition cycle ends here (the stage copy is gone), so the
        # transfer identity must not outlive it: coming back into the set is a
        # fresh download and mints a fresh transfer_id. This pass is the
        # cycle-boundary owner the old state.pop(prev) used to be.
        telemetry_report.clear_transfer(state, key)
        # ...and with it any replan re-verify that was still owed. The flag is
        # normally raised and consumed inside a single _stage_image call, so
        # this is the durability net rather than the common path: state is only
        # checkpointed at a few points in a tick, so a process killed between
        # the raise and the consume can persist the flag, and an image that
        # then leaves the set has no staged file left to hash — park just
        # deleted it. Clearing here keeps that ghost from firing a pointless
        # ~1.2 GB pass on whatever the image re-downloads when it comes back.
        telemetry_report.take_replan_verify(state, key)
        # Provenance (Directive 2, reviewer PROBE2 fix): origin/download_started
        # describe a placement fact about this exact acquisition cycle, and
        # that cycle ends the moment the image leaves the assigned set —
        # whether the file was just deleted (nothing left to prove) or left
        # in place untouched (still fine to call it unproven going forward;
        # fail-safe is never wrong to re-derive from). The steady-state
        # short-circuit that will greet this record on reassignment never
        # revisits copy_to_root as long as done/copied read true, so an
        # operator who restages a byte-identical file under the SAME name
        # while the image is unassigned must not inherit a stale
        # 'downloaded' verdict from the PREVIOUS occupant of that name — that
        # is exactly what let the incident recur on the next unassign.
        # An explicitly adopted Guest Shell root is separate from the stage
        # copy just removed, so its protection must survive parking. The
        # legacy pending-root-delete queue drains later in this same tick;
        # unlike in-place platforms, its missing-origin rule permits deletion
        # on IOS-XE. Forgetting this adoption would turn park into a delete of
        # the untouched operator file. Downloaded provenance is still always
        # cleared, and in-place platforms retain their fail-safe unknown rule.
        if deps.copy_in_place or entry.get("origin") != "adopted":
            entry.pop("origin", None)
        entry.pop("download_started", None)
        # A real park happened (fname resolved this tick), so board #60's
        # retry counter -- only ever incremented on the "could not be named"
        # branch above -- has nothing left to count.
        entry.pop("park_defer_attempts", None)
        if protected:
            detail = "torrent stopped, root copy left in place (adopted)"
        elif deps.copy_in_place:
            # stage IS root on this platform: remove_stage above just
            # deleted the SAME file this message used to call "kept".
            detail = "torrent stopped, root copy removed"
        else:
            detail = "torrent stopped, stage copy deleted, root copy kept"
        deps.emit("PARKED",
                  "%s removed from the assignment set; %s" % (key, detail))
    # Only sweep when EVERY assigned image resolved to a filename. The sweep
    # deletes every staged artifact outside the keep set, so an image the
    # catalog merely failed to answer for this tick must never look unassigned
    # — that would discard a fully downloaded image over a transient 404.
    if resolved == len(ids):
        deps.purge_others(keep_files, list(ids))


def _staged_image_ids(state, ids):
    """The images of the set this device has fully staged: content verified
    (`done`) AND placed at the target-FS root (`copied`) — the same pair the
    steady-state short-circuit trusts."""
    staged = []
    for image_id in ids:
        entry = state.get(image_id)
        if (isinstance(entry, dict) and entry.get("done")
                and entry.get("copied")):
            staged.append(image_id)
    return staged


# Aggregate stage_state for a set of more than one image, most actionable
# first. "ready" only when every image is staged; otherwise report whichever
# gate or failure an image actually hit, rather than a bland "staging" for a
# device that is out of room or has given up placing. Which images are done
# rides staged_image_ids, and why one is not rides stage_error.
_SET_STAGE_STATES = ("flash_full_seeding_only", "flash_full", "error",
                     "copy_failed")


def _send_set_heartbeat(deps, sid, state, ids, ticks,
                        instruction_attestation=None):
    """POST the tick's single heartbeat for the whole set; return the response.

    A one-image set POSTs its recorded payload verbatim — same keys, same
    values, no staged_image_ids or errored_image_ids (the server falls back
    to current_image_id/stage_state for one-image agents, as it must for
    every agent that predates the fields)."""
    live = [t for t in ticks if t.hb is not None]
    if not live:
        # Defensive: a future path may return without a heartbeat payload.
        return None
    if len(ids) == 1:
        return _send_heartbeat(deps, sid, live[0].build(),
                               instruction_attestation)
    staged = _staged_image_ids(state, ids)
    # Which assigned images THIS TICK's own per-image status calls a
    # terminal failure -- the same _SET_STAGE_STATES vocabulary `failed`
    # below already checks each live tick's stage_state against. Paired
    # with staged_image_ids, this tells the server "N images stuck in
    # error" apart from "one erred, the rest are still in flight" instead
    # of guessing from the set's single collapsed stage_state.
    errored = [img_id for img_id, t in zip(ids, ticks)
              if t.hb is not None and t.stage_state in _SET_STAGE_STATES]
    hb = live[0].build(staged_image_ids=staged, errored_image_ids=errored)
    seen = [t.stage_state for t in live]
    # Keep the identity of the image that produced this payload: forcing a
    # different id would mislabel its observation and filesystem reading.
    #
    # `staged` is read from STATE, so it still counts an image that was staged
    # on an earlier tick but FAILED on this one (the catalog dropped it, flash
    # filled up, placement gave up). Reporting "ready" then contradicts the
    # stage_error travelling in the same payload, so this tick's own verdicts
    # have to agree before the set is called ready.
    failed = [s for s in seen if s in _SET_STAGE_STATES]
    if len(staged) == len(ids) and not failed:
        hb["stage_state"] = "ready"
    else:
        hb["stage_state"] = next((s for s in _SET_STAGE_STATES if s in seen),
                                 "staging")
    hb["stage_error"] = next((t.stage_error for t in live if t.stage_error),
                             None)
    return _send_heartbeat(deps, sid, hb, instruction_attestation)


def _stage_image(cfg, deps, state, img_id, tele_on, stream_on, tick,
                 legacy_pointer=False, plan_row=None,
                 instruction_attestation=None):
    """Stage ONE image of the assigned set and return its status string.

    This is the whole of the pre-multi-image run_once() from the catalog
    lookup down, unchanged: the same steady-state short-circuit, the same
    sha/copy-to-root gate, the same download branch, the same return-string
    vocabulary ("no-image" | "bad-filename" | "complete" | "bad-sha" |
    "seeding-only" | "no-space" | "aria2-down" | "downloading"). run_once()
    calls it once per assigned image.

    Two things it no longer owns, because they belong to the whole set rather
    than to one image:

      * the heartbeat POST and the telemetry tick. The device has ONE row on
        the server, so the set gets ONE heartbeat per tick — but its
        stage_state and staged_image_ids can only be settled after every image
        has been checked. So this function still decides exactly what it would
        report, exactly where it always did, and records it on `tick`;
        run_once composes the one payload, POSTs it, and replays the telemetry
        against the answer. (The container-mode `transferring_to_ios` publish
        is the exception: it exists to be seen BEFORE a long blocking
        transfer, so it still POSTs on the spot.)
      * parking and un-parking images as they leave and re-enter the set
        (see _reconcile_set).

    The top-level state["image_id"] pointer IS still written here, for the
    first image of the set only (`legacy_pointer`), at the point in the tick
    the single-image agent wrote it — see below.

    `plan_row` is this image's row of the policy body's `plans` map (the
    server-minted transfer identity), or None when the server sent no plan for
    it. Adoption happens here rather than in run_once because it must sit
    BEHIND the catalog lookup and the filename whitelist — see the ADOPT THE
    SERVER'S TRANSFER IDENTITY block below.
    """
    sid = cfg["device_id"]
    stage_dir = cfg["stage_dir"]
    try:
        image = deps.catalog.get_image(img_id)
    except Exception as e:
        # One image's lookup must not discard siblings' completed work or
        # suppress the whole device heartbeat. Exception text may contain an
        # authenticated URL, so only its type belongs in the diagnostic.
        deps.emit("IMAGE-UNAVAILABLE",
                  "%s catalog image unavailable (%s)"
                  % (img_id, type(e).__name__))
        tick.heartbeat({"id": img_id}, deps, "error",
                       target_fs=cfg.get("target_fs"),
                       tele_on=tele_on, stream_on=stream_on,
                       stage_error="catalog image unavailable; retrying",
                       observation=_not_active_observation(
                           tele_on, time.time()))
        return "image-unavailable"
    if image is None:
        deps.emit("ERROR", "assigned image %s not in catalog" % img_id)
        tick.heartbeat({"id": img_id}, deps, "error",
                       target_fs=cfg.get("target_fs"),
                       tele_on=tele_on, stream_on=stream_on,
                       stage_error="assigned image %s not in catalog"
                                   % img_id,
                       observation=_not_active_observation(
                           tele_on, time.time()))
        return "no-image"

    # Reject a bad catalog filename before it reaches any IOS command.
    fname = image["filename"]
    if not _FILENAME_RE.match(fname):
        deps.emit("ERROR",
                  "rejected catalog filename (must match %s): %r"
                  % (_FILENAME_RE.pattern, fname))
        tick.heartbeat({"id": img_id}, deps, "error",
                       target_fs=cfg.get("target_fs"),
                       tele_on=tele_on, stream_on=stream_on,
                       stage_error="catalog image filename is invalid",
                       observation=_not_active_observation(
                           tele_on, time.time()))
        return "bad-filename"

    stage = os.path.join(stage_dir, fname)
    size = int(image["size"])

    # The tracker transport marker has to participate in the steady-state
    # gate below.  A current-schema device can already be done+copied when it
    # upgrades from HTTP; returning early would leave that live seed on the old
    # announce forever.  Resolve the cheap cached-torrent identity here, then
    # perform the actual network/RPC migration on the ordinary staging path
    # after the existing content checks.
    torrent = os.path.join(stage_dir, img_id + ".torrent")
    st = state.setdefault(img_id, {})
    torrent_id = _torrent_identity(image)
    bearer_metainfo = (cfg.get("device_platform")
                       in agent_config.DEVICE_PLATFORMS)
    torrent_transport = (_TORRENT_TRANSPORT_BEARER_HTTPS
                         if bearer_metainfo
                         else _TORRENT_TRANSPORT_QUERY_HTTPS)
    migrate_transport = (deps.file_size(torrent) is not None
                         and st.get("torrent_id") in (None, torrent_id)
                         and st.get("torrent_auth_format")
                         != torrent_transport)

    # ADOPT THE SERVER'S TRANSFER IDENTITY. `plan_row` carries the plan_id and
    # transfer_id the server minted when it DECIDED this transfer. Adopting the
    # transfer_id here is the whole of the device's half of the change:
    # ensure_transfer_id is a get-or-mint and the ONLY writer of
    # tele['transfer_id'] in this tree, so seeding the key makes the observation
    # envelope, the heartbeat sample, both report builders and the
    # aria2-RPC-down envelope all inherit the server's id with no further
    # plumbing.
    #
    # WHY THIS EXACT CALL SITE — three constraints pin it, and moving it breaks
    # one of them:
    #   * BEFORE the steady-state short-circuit below. A plan boundary on an
    #     already-staged image raises tele['replan_verify'], and that
    #     short-circuit is the only thing that consumes it; adopting after it
    #     would defer every replan re-verify by a full tick.
    #   * BEFORE deps.aria_add() far below. The download must start under the
    #     id the server minted at assignment time, not under one this agent
    #     invents once the bytes are already moving.
    #   * AFTER the catalog lookup and the filename whitelist above. This used
    #     to run as a loop over the assigned ids up in run_once, which wrote
    #     state[img_id]['tele'] for an image the device had not yet confirmed
    #     it could stage at all. 'tele' is one of _IMAGE_ENTRY_FIELDS, so that
    #     bare {'tele': {...}} entry looks exactly like a real image record to
    #     the park pass — and a record with no 'root_file', for an id the
    #     catalog does not answer for, can be neither named nor retired, so the
    #     moment the id left the assignment set the device emitted
    #     PARK-DEFERRED for it on every tick, forever. Past both gates, any id
    #     reaching this line is one this device can genuinely stage.
    #
    # A server that sends no 'plans' (older server, legacy-bootstrap policy row,
    # captive-portal garbage) leaves plan_row None or unusable; adopt_plan
    # validates both ids and refuses everything else while touching NO state, so
    # ensure_transfer_id mints exactly as it does today.
    #
    # plan_id is stored and NEVER echoed back: the server owns the
    # transfer_id -> plan_id mapping, so no report or heartbeat field is added
    # and the ingest whitelist needs no change.
    #
    # 'adopted' is the UPGRADE case and is deliberately quiet about work: a
    # transfer this agent had already named itself (a state file written before
    # plans existed) is simply being named by the server for the first time. No
    # boundary was crossed, so nothing is reset and nothing is re-hashed — see
    # adopt_plan, board #44.
    if isinstance(plan_row, dict):
        adoption = telemetry_report.adopt_plan(
            state, img_id, plan_row.get("plan_id"),
            plan_row.get("transfer_id"))
        if adoption == "new":
            deps.emit("REPLAN", "%s adopted plan %s"
                      % (img_id, plan_row.get("plan_id")))
        elif adoption == "adopted":
            deps.emit("PLAN-ADOPTED",
                      "%s now named by plan %s; the transfer already in "
                      "progress keeps its measurements (nothing re-verified)"
                      % (img_id, plan_row.get("plan_id")))

    # steady state: image done + copied -> just heartbeat. Do NOT re-hash the
    # 1.2 GB file every tick — hashing takes longer than the 60s timer and the
    # overlapping runs double-fired the root copy (two concurrent IOS copies
    # interleave into a corrupt oversized file).
    # Self-heal: the short-circuit holds ONLY while the catalog content (sha) is
    # unchanged AND both the staged and flash-root copies still exist — all cheap
    # checks (no hashing). If content changed, or either copy went missing, fall
    # through to re-acquire (re-download a missing/stale staged file; re-copy a
    # missing root file).
    # The image's OWN record decides, not a top-level "current image" pointer:
    # every image of the set gets the same short-circuit, and an image that
    # comes back into the set after being parked gets it too (its root copy
    # survived parking, so this is the presence-and-size confirm that spares
    # it a full re-placement).
    done_st = state.get(img_id, {})
    if done_st.get("done") and done_st.get("copied"):
        content_ok = done_st.get("sha", image["sha256"]) == image["sha256"]
        staged_ok = deps.file_size(stage) is not None
        root_ok = deps.root_present(image["filename"], state.get("stage_fs", "flash:"),
                                    size)
        if content_ok and staged_ok and root_ok and not migrate_transport:
            # REPLAN RE-VERIFY. A NEW server plan landed on an image this
            # device already has staged AND placed. Without this, that plan
            # could never be attested: this short-circuit deliberately never
            # re-hashes, and _telemetry_tick arms a terminal report only on
            # phase 'copied'/'seeding-only' — and 'done'/'copied' live in the
            # IMAGE record, not in the telemetry bag, so adopt_plan's wholesale
            # reset of that bag cannot reach them. The transfer would sit at
            # 'planned' forever while the file it needs is sitting right there.
            #
            # The honest answer is evidence gathered UNDER the new transfer, so
            # hash the staged file ONCE here and arm the report under the newly
            # adopted transfer_id. Accepting the PREVIOUS transfer's checksum
            # instead would be cheaper and is exactly the thing this must not
            # do — it would attest one transfer with another's verification.
            #
            # take_replan_verify pops the flag BEFORE the hash runs, so a
            # mismatch cannot re-hash a ~1.2 GB file on every 60 s tick for the
            # life of the assignment: a failed hash is a decision already made
            # (the staged copy is discarded), not a reason to try again.
            phase = "steady"
            if telemetry_report.take_replan_verify(state, img_id):
                if deps.verify(stage, image["sha256"]):
                    # Recorded at the decision point and read back verbatim by
                    # the report, exactly as the download path does.
                    state[img_id]["tele"]["content_sha256_state"] = "verified"
                    phase = "copied"
                    deps.emit("REPLAN-VERIFY", "%s sha256-ok under the new plan"
                              % image["filename"])
                else:
                    deps.emit("ERROR", "%s sha256 MISMATCH - discarding"
                              % image["filename"])
                    state[img_id]["tele"]["content_sha256_state"] = "mismatch"
                    # Lower both flags so the next tick falls out of this
                    # short-circuit and re-acquires: the bytes on disk do not
                    # match the catalog, whatever a previous transfer believed.
                    done_st["done"] = False
                    done_st["copied"] = False
                    # Board #41: on a deps.copy_in_place platform (XR:
                    # attest-in-place, stage dir IS the target-FS root) the
                    # remove_stage() below is a ROOT delete, and it can be
                    # deleting a file the OPERATOR placed there themselves —
                    # origin "adopted", or missing/legacy origin — that IRIS
                    # only ever attested, never wrote. Every OTHER agent-side
                    # delete of that same file is guarded or announced: the
                    # park pass calls _protect_adopted_root() and leaves an
                    # adopted placement in place, and the RECHECK
                    # "staged_ok and not content_ok" path a few lines below
                    # overrides adoption but says ROOTCOPY-REPLACED first —
                    # "the one thing owed to the operator is honesty: say so
                    # before overriding it". This branch is reached from a
                    # DIFFERENT direction (a second plan's re-verify, not a
                    # RECHECK re-acquire) but ends at the exact same
                    # unconditional delete, so it owes the operator the same
                    # notice. Unlike RECHECK, this is a genuine content
                    # MISMATCH, not a routine republish -- there is no
                    # "convergence wins" argument for silence here.
                    if deps.copy_in_place and done_st.get("origin") != "downloaded":
                        deps.emit("ROOTCOPY-REPLACED",
                                  "replacing operator-adopted %s: content "
                                  "changed under image id %s (sha256 mismatch "
                                  "under the new plan)"
                                  % (image["filename"], img_id))
                    deps.remove_stage(stage)
                    tick.heartbeat(
                        image, deps, "error",
                        target_fs=state.get("stage_fs") or cfg.get("target_fs"),
                        tele_on=tele_on, stream_on=stream_on,
                        stage_error="image SHA-256 verification failed; retrying download",
                        observation=_not_active_observation(tele_on, time.time()))
                    return "bad-sha"
            # The observation phase stays 'steady' whatever the report does:
            # aria2 is seeding here, not downloading, and _build_observation
            # takes an aria snapshot only for 'downloading'/'seeding-only'.
            obs, _ = _build_observation(
                cfg, deps, state, img_id, stage, "steady", time.time(),
                tick_seconds=tick.tick_seconds)
            hb = tick.heartbeat(image, deps, "ready",
                                target_fs=state.get("stage_fs"),
                                tele_on=tele_on,
                                observation=obs,
                                stream_on=stream_on)
            tick.telemetry(cfg, deps, state, img_id, stage, phase,
                           hb, time.time())
            return "complete"
        deps.emit("RECHECK", "%s re-acquiring (content=%s staged=%s root=%s)"
                  % (image["filename"], content_ok, staged_ok, root_ok))
        # DROP A STALE REPLAN FLAG. replan_verify only ever means one thing:
        # "the staged bytes are already here, hash them ONCE under the new
        # plan". Reaching this line says they are not here in any form worth
        # hashing — the staged file is gone, or the catalog content moved under
        # it, or the root copy vanished — so the flag has nothing left to
        # verify. Left in the bag it would survive the whole re-acquisition
        # (adopt_plan raises it on 'done' AND 'copied', which a park+reassign
        # leaves set even after park deleted the staged file) and then fire one
        # tick AFTER the download path's own verify() had already hashed the
        # very same bytes under the very same transfer_id: a second
        # multi-minute pass over ~1.2 GB that can only agree with the first.
        # Nothing is lost by dropping it, because EVERY fall-through from here
        # ends in that download path, which hashes and arms the terminal report
        # under the adopted id on its own.
        telemetry_report.take_replan_verify(state, img_id)
        if not staged_ok:
            # Provenance (Directive 2, reviewer PROBE1/PROBE2 follow-up): the
            # placement this record's origin/download_started describe is
            # gone, or was not re-verified THIS cycle — on a stage-equals-root
            # platform (deps.copy_in_place, e.g. XR) staged_ok and root_ok are
            # literally the same fact, so this also covers a root copy that
            # vanished or was silently replaced OUTSIDE an unassign. Whatever
            # eventually lands at this name next is judged on its OWN
            # evidence (a fresh copy_to_root re-derives origin), never on a
            # provenance fact this record can no longer vouch for.
            done_st.pop("origin", None)
            done_st.pop("download_started", None)
        if staged_ok and not content_ok:
            # A republished image under the SAME id is the ORDINARY catalog
            # event, not a rare edge case: image ids are DERIVED from the
            # filename (server/publish.py's derive_id strips the known image
            # suffixes), so a rebuild published under an unchanged filename
            # routinely lands here with new content under the SAME id and
            # the SAME name. Refusing this delete would leave the device
            # stuck on stale content forever with no path back to the
            # catalog's current target, on every such republish — so
            # convergence wins even over an adopted file (the operator's
            # file is not assumed to match either the old or the new
            # content; the catalog changed, not necessarily anything about
            # what is actually sitting at this name). The one thing owed to
            # the operator is honesty: say so before overriding it.
            if deps.copy_in_place and done_st.get("origin") != "downloaded":
                deps.emit("ROOTCOPY-REPLACED",
                          "replacing operator-adopted %s: catalog content "
                          "changed under image id %s" % (image["filename"],
                                                          img_id))
            deps.remove_stage(stage)      # stale content on disk -> drop, re-download
            staged_ok = False
            # Same catalog id with new content is a genuine image change, so a
            # previous terminal placement failure must not poison the new bytes.
            _reset_copy_failures(done_st)
            # A fresh acquisition cycle starts here: whatever provenance the
            # OLD content had must not leak into the verdict for the NEW
            # content (e.g. a genuine download's leftover flag wrongly
            # marking a subsequent operator-adopted replacement as
            # 'downloaded'). aria_add re-sets it later THIS SAME tick if the
            # file really is gone and a fresh download starts.
            done_st.pop("origin", None)
            done_st.pop("download_started", None)
        # 'copied' is a fact about the FLASH-ROOT copy, and root_present()
        # above just checked THAT copy by presence AND exact catalog size.
        # Clearing it unconditionally threw that answer away and re-ran a
        # ~1.2 GB placement for a copy demonstrably still in place — which is
        # precisely where an un-parked image lands (park deletes the stage
        # copy and deliberately keeps the root copy, so the only thing missing
        # is the staged file). Content that CHANGED invalidates the root copy
        # too, so a stale sha still forces the re-placement, as does a root
        # copy that is missing or the wrong size.
        done_st["done"] = staged_ok       # keep 'done' only for a root-only loss
        done_st["copied"] = bool(root_ok and content_ok)
        # DROP THE VERIFY VERDICT WITH THE BYTES IT DESCRIBED (board #28).
        # content_sha256_state is "this transfer hashed THESE bytes and they
        # matched". Reaching this line means the record's own cheap self-check
        # just failed — the staged file is gone, the catalog content moved
        # under it, or the root copy vanished — so the verdict is no longer
        # backed by anything this tick can see, and the re-acquisition below
        # deliberately KEEPS the image id and its stored transfer_id (a
        # changed-content / local-loss boundary reuses it). Left in the bag it
        # is read verbatim into every report built while the replacement is
        # still downloading, attesting content that is not on the device.
        #
        # Nothing measured is lost and nothing extra is hashed: when the staged
        # file really is complete, the download path a few lines below hashes
        # it on THIS SAME TICK and records a real verdict again; when it is
        # not, there is nothing to hash and absence — read back as
        # 'not_checked' — is the honest answer.
        (done_st.get("tele") or {}).pop("content_sha256_state", None)

    # Legacy bookkeeping: the old agent's one-image world had a single
    # top-level "current image" pointer, and readers of the state file (plus
    # the top-level root_file mirror written on placement) still expect it.
    # The FIRST image of the set owns it; the per-image records under
    # state[<image id>] are the real thing.
    # Written HERE rather than in run_once to keep the single-image agent's
    # ORDER: the pointer only ever advanced AFTER the catalog answered for the
    # image and its filename passed the whitelist, so a device assigned an
    # image the catalog does not have — or one it names illegally — keeps
    # pointing at the image it actually staged.
    if legacy_pointer:
        state["image_id"] = img_id

    # Delete replaced flash-root images, VERIFYING each is actually gone
    # before claiming CLEANUP: AAA nodes silently no-op a raw exec `delete`
    # (the reclaim/copyroot EEM applets exist for exactly that), so the
    # delete runs through the same authorization-bypass applet as bundle
    # reclaim — a raw delete would no-op on every retry and strand the old
    # image on flash forever. Unverified entries stay on the list and are
    # retried every tick (the applet may still be running when we look; the
    # next tick's re-check settles it). The whitelist re-check guards the
    # destructive interpolation against a hand-edited state file.
    # NOTHING QUEUES HERE ANY MORE: an image dropped from the assignment set is
    # parked and its root copy deliberately kept (_reconcile_set). The drain
    # stays for state files written by the agent that did queue replaced root
    # copies — those deletes were promised to an operator and must still land.
    #
    # Provenance gate (Directive 2): pending_root_deletes names a FILE, not
    # the per-image record that placed it, so its origin is looked up by
    # root_file. An explicit 'adopted' is protected on EVERY platform now
    # that Guest Shell can attest a same-named root file. For legacy records
    # with a missing/unknown origin, preserve the prior split: a platform
    # that physically writes its root copy still drains the old queue, while
    # copy_in_place platforms fail safe. A name explicitly recorded as
    # 'downloaded' remains deletable everywhere. Protected entries are logged
    # once and resolved out of the queue rather than retried forever — there
    # is nothing a retry could ever change.
    pending = state.get("pending_root_deletes") or []
    if pending:
        fs = state.get("stage_fs", "flash:")
        doomed = [n for n in pending
                  if n != image["filename"] and _FILENAME_RE.match(n)]
        deletable = [n for n in doomed
                    if _root_file_origin(state, n) != "adopted"
                    and (not deps.copy_in_place
                         or _root_file_origin(state, n) == "downloaded")]
        for protected in doomed:
            if protected not in deletable:
                deps.emit("ROOTCOPY-KEPT",
                          "left in place: operator-adopted %s" % protected)
        # The BOOT target is never on the delete list either: a replaced root
        # copy the operator has since pointed BOOT at is the file the device
        # boots next. Resolved out of the queue like an adopted file (a retry
        # could never change what BOOT says); an unreadable BOOT variable
        # keeps the whole queue for the next tick and deletes nothing now.
        boot = _boot_target(deps)
        if boot is None:
            deps.emit("CLEANUP-PENDING",
                      "replaced-image cleanup deferred: BOOT variable "
                      "unreadable; will retry")
            deletable = []
            still = list(doomed)
        else:
            still = []
            for kept in [n for n in deletable if _is_boot_target(boot, n)]:
                deps.emit("ROOTCOPY-KEPT",
                          "left in place: %s is the BOOT target" % kept)
                deletable.remove(kept)
        if deletable:
            deps.reclaim_bundle(fs, deletable)
        for old_root in deletable:
            if deps.root_present(old_root, fs):
                still.append(old_root)
                deps.emit("CLEANUP-PENDING",
                          "replaced image %s still present after delete; "
                          "will retry" % old_root)
            else:
                deps.emit("CLEANUP", "removed replaced image %s (now %s)"
                          % (old_root, img_id))
        if still:
            state["pending_root_deletes"] = still
        else:
            state.pop("pending_root_deletes", None)

    # already downloaded AND aria2 finished? aria2 keeps a "<file>.aria2" control
    # file until the download is fully done; checking it avoids hashing a file that
    # has reached full size but whose last pieces aren't on disk yet (a race that
    # produced spurious sha mismatches on the 60s timer).
    downloading = deps.file_size(stage + ".aria2") is not None
    # Both the old HTTP announce and the HTTPS replacement have an identical
    # info dictionary, so torrent_id cannot distinguish them. For an
    # identity-equal on-disk torrent with an older/missing transport marker,
    # atomically refetch the small metainfo and re-add it. forceRemove does not
    # delete the payload or its .aria2 resume bitfield. This applies to Guest
    # Shell as well as the container platforms: the authentication style stays
    # platform-specific, but no device may keep announcing over HTTP. Run it
    # before the complete-file fast path so an already-staged seed migrates.
    def migrate_cached_transport(readd):
        try:
            deps.catalog.download_torrent(img_id, torrent)
            if readd:
                deps.aria_remove(image["filename"])
                deps.aria_add(torrent, stage_dir)
        except TrackerAuthConfigError:
            deps.emit("TRACKER-AUTH",
                      "tracker authorization unavailable; refusing addTorrent")
            tick.heartbeat(image, deps, "error",
                           target_fs=state.get("stage_fs"),
                           tele_on=tele_on, stream_on=stream_on,
                           stage_error="tracker authorization unavailable")
            return "tracker-auth"
        except Exception as e:
            deps.emit("TORRENT-UNAVAILABLE",
                      "%s tracker transport migration unavailable: %s"
                      % (image["filename"], e))
            tick.heartbeat(image, deps, "error",
                           target_fs=state.get("stage_fs"),
                           tele_on=tele_on, stream_on=stream_on,
                           stage_error="tracker transport migration unavailable")
            return "torrent-unavailable"
        # The just-fetched metainfo is for the catalog identity resolved above.
        # Recording both facts together avoids a second fetch later in this
        # same tick for pre-identity state, and prevents the HTTPS marker from
        # describing an unknown/older torrent.
        st["torrent_id"] = torrent_id
        st["torrent_auth_format"] = torrent_transport
        return None

    staged_size = deps.file_size(stage)
    completed_candidate = staged_size == size and not downloading
    # A too-large payload is about to be discarded with its torrent, so do not
    # fetch the replacement twice. A size-complete candidate is verified first
    # so bad bytes likewise cannot consume a throwaway metainfo download.
    if (migrate_transport and not completed_candidate
            and (staged_size is None or staged_size <= size)):
        # A resume sidecar proves aria2 has a real bitfield worth preserving
        # and re-adding now. With no payload, or a partial payload lacking its
        # sidecar, refresh only the metainfo here; the ordinary guarded start
        # path below will clear any phantom entry and add it exactly once.
        migration_error = migrate_cached_transport(readd=downloading)
        if migration_error:
            return migration_error

    if completed_candidate:
        if deps.verify(stage, image["sha256"]):
            if migrate_transport:
                migration_error = migrate_cached_transport(readd=True)
                if migration_error:
                    return migration_error
            # state is PER-IMAGE: a reassignment to a new image id must go through
            # the full DONE + copy-to-root cycle again, untouched by the old one.
            st = state.setdefault(img_id, {})
            # Record the CONTENT-HASH verify outcome INTO STATE at the decision
            # point (spec §3D): the report reads this verbatim and never infers
            # 'verified' from done/copied or absence. verify() returned True here.
            # Durability follows the report it feeds — the report-freeze
            # checkpoint (spec §2) flushes this fact BEFORE its POST, and the
            # outer final save persists it either way; a crash before that just
            # re-derives the same fact next tick (verify is idempotent).
            st.setdefault("tele", {})["content_sha256_state"] = "verified"
            if st.get("sha") not in (None, image["sha256"]):
                # A catalog republish under the same id is still genuinely new
                # content and is the only same-id event allowed to clear a
                # durable placement-failure terminal state.
                _reset_copy_failures(st)
            st["sha"] = image["sha256"]    # record verified content (change-detect)
            if not st.get("done"):
                st["done"] = True
                deps.emit("DONE", "%s complete sha256-ok id=%s"
                          % (image["filename"], img_id))
            # Place at flash root via NATIVE EEM. The agent templates the
            # IRIS-COPYROOT applet and fires it; the applet clears any stale
            # same-named leftover, then runs a plain `copy` — no in-band
            # signature check. The agent then polls for the file at flash
            # root and blesses the copy only on presence AND an exact
            # byte-size match against the catalog's declared size for this
            # image. copy_to_root returns False if the file never appears or
            # never reaches the expected size -> st['copied'] stays False so
            # the next tick retries.
            # Copy gate: placing the flash-root copy needs room for a SECOND
            # full-size image alongside the staged/seeding scratch — UNLESS
            # copy_to_root never duplicates bytes at all (deps.copy_in_place,
            # e.g. XR's attest_in_place: stage_dir IS the root, so "placing"
            # the copy is just a stat of the file already staged there). On a
            # tight device that fit one image but not two, degrade to
            # keep-seeding-only — the staged file keeps feeding the swarm,
            # the running image is untouched, and we surface the shortfall
            # instead of failing a copy.
            #
            # A pre-existing file at image["filename"] (the operator's
            # ordinary same-name republish flow, or any other file already
            # sitting at this name) needs NO extra charge here. The
            # crash-safety sequence (stage under a temp name, prove it, then
            # `rename` over the real name — see copy_to_root) never deletes
            # that old file first and never writes new bytes for it: it
            # stays exactly where it is until the final rename, a
            # directory-entry update that moves no data. deps.target_fs()'s
            # `free` already excludes whatever currently occupies
            # image["filename"], so charging for it again here would double
            # count the same bytes and refuse placements that physically fit
            # (scrubber #138). The only NEW bytes this attempt writes are the
            # temp copy, exactly `size` (doubled under io_transfer, same as
            # a fresh name).
            if not st.get("copied"):
                mode = deps.detect_mode()
                target_prefix, free = deps.target_fs()
                state["stage_fs"] = target_prefix
                now = time.time()

                # Guest Shell mounts only guest-share, not the IOS root.
                # IOS `rename` does not
                # overwrite a same-named destination on affected releases, so
                # first attest those existing bytes through native IOS SHA.
                # This runs BEFORE
                # the copy terminal/backoff and space gates: an upgraded agent
                # must be able to recover a hardware-stranded good destination
                # plus full-size .iris-tmp without needing room for a third
                # copy. Once a collision has been checked, throttle subsequent
                # multi-GB hashes with the ordinary copy backoff; the marker is
                # absent in old state, guaranteeing one immediate upgrade
                # probe even when copy_terminal/copy_next_ts are already set.
                adoption = "not-applicable"
                if (st.get("root_adopt_checked")
                        and now < st.get("copy_next_ts", 0)):
                    adoption = "blocked"
                else:
                    adoption, adoption_error = _try_adopt_guestshell_root(
                        cfg, deps, image, target_prefix)
                    if adoption == "adopted":
                        st["copied"] = True
                        st["root_file"] = image["filename"]
                        if state.get("image_id") == img_id:
                            state["root_file"] = image["filename"]
                        st["origin"] = "adopted"
                        _reset_copy_failures(st)
                    elif adoption == "blocked":
                        st["root_adopt_checked"] = True
                        st["copy_terminal"] = True
                        st["stage_error"] = adoption_error
                        # Hashing itself can outlast a backoff interval. Start
                        # the retry delay when it finishes, not before launch.
                        st["copy_next_ts"] = time.time() + _ROOT_COPY_BACKOFF_BASE
                    elif (adoption == "absent"
                          and st.get("root_adopt_checked")):
                        # The operator removed a previously conflicting root
                        # file. Start a fresh placement cycle immediately.
                        _reset_copy_failures(st)
                # Container placement first creates an IOS-visible scratch and
                # then the root copy, so it transiently consumes two full
                # images; a platform whose root copy IS the staged file (no
                # new bytes written) needs no additional headroom at all.
                copy_bytes = (0 if deps.copy_in_place
                              or adoption in ("adopted", "blocked") else
                              size * (2 if deps.io_transfer else 1))
                if (adoption not in ("adopted", "blocked")
                        and not flashcheck.has_room(free, copy_bytes)):
                    # Only burn the once-guard when reclaim ACTUALLY ran — a
                    # transient mode=None (or unconfirmable running image) does
                    # nothing, so leave the guard clear to retry next tick.
                    if not st.get("copy_reclaim_tried"):
                        if _reclaim_for_mode(deps, mode, target_prefix,
                                             image, state):
                            st["copy_reclaim_tried"] = True
                            target_prefix, free = deps.target_fs()
                    if not flashcheck.has_room(free, copy_bytes):
                        st["blocked_no_space"] = True
                        deps.emit("FLASH-FULL",
                                  "%s staged+seeding, no room for flash-root copy "
                                  "(free=%d need>=%d mode=%s)"
                                  % (image["filename"], free,
                                     copy_bytes + flashcheck.HEADROOM, mode))
                        obs, peers = _build_observation(
                            cfg, deps, state, img_id, stage, "seeding-only",
                            time.time(), tick_seconds=tick.tick_seconds)
                        hb = tick.heartbeat(image, deps,
                                            "flash_full_seeding_only",
                                            target_fs=state.get("stage_fs"),
                                            tele_on=tele_on,
                                            observation=obs,
                                            stream_on=stream_on)
                        tick.telemetry(cfg, deps, state, img_id, stage,
                                       "seeding-only", hb, time.time(),
                                       peers=peers)
                        return "seeding-only"
                st.pop("blocked_no_space", None)
                # Container-mode IOx devices must SCP the completed image into
                # IOS-visible storage before the final placement copy. That large
                # transfer blocks this agent process, so publish its state first
                # instead of leaving the Console on ambiguous "staging".
                # A state file written by the regressed implementation may have
                # deferred the first retry. Clear that timestamp too: one
                # immediate next-tick retry is intentional so transient
                # filesystem/SSH failures recover without a five-minute wait.
                if (st.get("copy_attempts") == 1
                        and not st.get("root_adopt_checked")):
                    st.pop("copy_next_ts", None)
                if st.get("copy_terminal"):
                    pass
                elif now < st.get("copy_next_ts", 0):
                    deps.emit("ROOTCOPY-BACKOFF",
                              "%s retry deferred until %d"
                              % (image["filename"], st["copy_next_ts"]))
                elif deps.io_transfer:
                    # POSTed on the spot, not deferred with the tick's set
                    # heartbeat: its whole point is to be visible BEFORE the
                    # long blocking transfer below, so the Console does not sit
                    # on an ambiguous "staging" for minutes.
                    _send_heartbeat(
                        deps, sid, _heartbeat(image, deps, "transferring_to_ios",
                                              target_fs=target_prefix,
                                              tele_on=tele_on,
                                              stream_on=stream_on),
                        instruction_attestation)
                if not st.get("copied") and not st.get("copy_terminal") \
                        and now >= st.get("copy_next_ts", 0):
                    result = deps.copy_to_root(image["filename"], target_prefix, size)
                    # ROOT_COPY_NOT_ATTEMPTED is a truthy object(), so it MUST be
                    # excluded before any plain truth test on `result`.
                    attempted = result is not ROOT_COPY_NOT_ATTEMPTED
                    if result is ROOT_COPY_RUNNING_IMAGE_UNKNOWN:
                        # Transient: the running-image scrape glitched, not a
                        # copy failure. Leave copy_attempts/copy_next_ts alone
                        # so this tick doesn't count toward the durable
                        # copy_failed terminal state — retry next tick exactly
                        # as before the bounded-retry schedule existed.
                        pass
                    elif attempted and result:
                        st["copied"] = True
                        # Per image, because a set can have several root copies
                        # placed at once — and parking one has to know which
                        # file it placed. The top-level key stays as the legacy
                        # mirror for the FIRST image of the set (state files are
                        # read by older code paths and by _protect_set).
                        st["root_file"] = image["filename"]
                        if state.get("image_id") == img_id:
                            state["root_file"] = image["filename"]
                        # Provenance (Directive 2): reaching THIS branch means
                        # copy_to_root physically wrote the IOS-XE root copy,
                        # or an in-place platform attested its stage path. The
                        # Guest Shell adoption path returns before this call
                        # and records "adopted" directly. An in-place verdict
                        # depends on whether THIS agent's aria2 session is what
                        # fetched the file
                        # (download_started, set at the aria_add call site) —
                        # absent means attest_in_place adopted bytes that
                        # were already at the mount. Every deletion path
                        # keyed on 'origin' treats anything but 'downloaded'
                        # as adopted, including a missing origin (legacy
                        # state), fail-safe by construction.
                        st["origin"] = ("downloaded" if not deps.copy_in_place
                                       or st.get("download_started")
                                       else "adopted")
                        _reset_copy_failures(st)
                    else:
                        if attempted:
                            # A genuine failure that got past the delete-first:
                            # IOS work ran, so a file at the image name now is
                            # OUR partial. This is the ONLY thing that arms the
                            # terminal reclaim (Layer 1). A pre-IOS refusal
                            # still counts as an attempt below — the operator
                            # must still reach the terminal state — but it
                            # deleted nothing, so it must never authorise a
                            # delete. Cleared with copy_attempts in
                            # _reset_copy_failures.
                            st["ios_copy_started"] = True
                        attempts = st.get("copy_attempts", 0) + 1
                        st["copy_attempts"] = attempts
                        st["stage_error"] = (
                            "final IOS placement failed; inspect IRIS ROOTCOPY-FAIL")
                        if attempts >= _ROOT_COPY_MAX_ATTEMPTS:
                            st["copy_terminal"] = True
                            st.pop("copy_next_ts", None)
                            deps.emit("ROOTCOPY-GIVEUP",
                                      "%s placement failed %d times; manual intervention required"
                                      % (image["filename"], attempts))
                            # Transition-only: copy_terminal short-circuits the
                            # whole copy block from the next tick on, so this
                            # runs exactly once. Nothing else owns the leftover.
                            # Layer 1: only a genuine post-delete-first failure
                            # proves the file at that name is ours to delete.
                            if st.get("ios_copy_started"):
                                _reclaim_failed_root_copy(deps, target_prefix,
                                                          image)
                            else:
                                deps.emit(
                                    "ROOTCOPY-RECLAIM-REFUSED",
                                    "%s left in place at %s: no attempt reached "
                                    "IOS (every failure was refused or failed "
                                    "before the delete-first), so anything at "
                                    "that name is not ours to delete"
                                    % (image["filename"], target_prefix))
                        else:
                            if attempts == 1:
                                # Retry on the next tick for fast recovery from
                                # transient filesystem or SSH failures. Backoff
                                # starts only after the second consecutive failure.
                                st.pop("copy_next_ts", None)
                            else:
                                st["copy_next_ts"] = now + _copy_backoff(attempts)
            # "ready" only when the flash-root copy is actually placed; a failed
            # copy_to_root (signature fail / never appeared) keeps "staging" so
            # the heartbeat never claims a verified root copy that isn't there.
            obs, _ = _build_observation(
                cfg, deps, state, img_id, stage, "seeding-only", time.time(),
                tick_seconds=tick.tick_seconds)
            hb = tick.heartbeat(image, deps,
                                "ready" if st.get("copied") else
                                ("copy_failed" if st.get("copy_terminal")
                                 else "staging"),
                                target_fs=state.get("stage_fs"),
                                tele_on=tele_on,
                                stage_error=st.get("stage_error"),
                                observation=obs,
                                stream_on=stream_on)
            tick.telemetry(cfg, deps, state, img_id, stage, "copied",
                           hb, time.time())
            return "complete"
        deps.emit("ERROR", "%s sha256 MISMATCH - discarding" % image["filename"])
        # Record the mismatch fact INTO STATE at the decision point (spec §3D):
        # 'mismatch' is a distinct explicit state, never 'false'/'not_checked'.
        # Durability follows the report; re-derived idempotently after a crash.
        state.setdefault(img_id, {}).setdefault("tele", {})[
            "content_sha256_state"] = "mismatch"
        # ...and lower 'done' with it (board #28). 'done' means "content
        # verified against the catalog", and this transfer just proved the
        # opposite about the only bytes it had — reaching this line at all
        # means a PREVIOUS cycle's True is still sitting there (the file is
        # deleted on the next line, so nothing on disk backs it). Left set, the
        # record reads done=True beside content_sha256_state='mismatch', two
        # statements about the same content that cannot both be true.
        state[img_id]["done"] = False
        deps.remove_stage(stage)          # drop the bad file so the next tick re-downloads
        # ...and the torrent it came from. Bytes that hash wrong are exactly
        # what a stale torrent delivers (a same-id republish regenerates it),
        # so the next tick re-fetches the catalog's current torrent — a few
        # hundred KB — instead of re-adding this one and looping.
        deps.remove_stage(os.path.join(stage_dir, img_id + ".torrent"))
        state[img_id].pop("torrent_id", None)
        state[img_id].pop("torrent_auth_format", None)
        # Verification failed on this tick, so publish that decision now.
        # Omitting the heartbeat retained the previous device status and made
        # set aggregation silently drop this image's failure.
        tick.heartbeat(
            image, deps, "error",
            target_fs=state.get("stage_fs") or cfg.get("target_fs"),
            tele_on=tele_on, stream_on=stream_on,
            stage_error="image SHA-256 verification failed; retrying download",
            observation=_not_active_observation(tele_on, time.time()))
        return "bad-sha"

    # need to download — media-aware flash pre-check + mode-gated reclaim.
    # Resolve the device's install-vs-bundle mode and target filesystem first:
    # on a bundle device `install remove inactive` does not apply, so reclaim
    # deletes vetted unused image artifacts instead; an unknown mode skips all
    # destructive reclaim. Attempt reclaim AT MOST ONCE per image (the once-guard
    # keeps a still-too-full device from stacking attempts), then re-read free.
    mode = deps.detect_mode()
    target_prefix, free = deps.target_fs()
    state["stage_fs"] = target_prefix
    stage_bytes = size * (2 if deps.io_transfer else 1)
    if not flashcheck.has_room(free, stage_bytes):
        st = state.setdefault(img_id, {})
        # Burn the once-guard only when reclaim actually ran (a no-op on a
        # transient mode=None must not permanently disable reclaim).
        if not st.get("reclaim_tried"):
            if _reclaim_for_mode(deps, mode, target_prefix, image, state):
                st["reclaim_tried"] = True
                target_prefix, free = deps.target_fs()
        if not flashcheck.has_room(free, stage_bytes):
            # Nothing is staged yet on this path, so the device is NOT seeding —
            # report plain flash_full (reserve flash_full_seeding_only for the
            # copy gate, where the scratch is downloaded and feeding the swarm).
            deps.emit("FLASH-FULL",
                      "%s no room to stage (free=%d need>=%d mode=%s)"
                       % (image["filename"], free,
                          stage_bytes + flashcheck.HEADROOM,
                         mode))
            hb = tick.heartbeat(image, deps, "flash_full",
                                target_fs=state.get("stage_fs"),
                                tele_on=tele_on,
                                stream_on=stream_on)
            tick.telemetry(cfg, deps, state, img_id, stage, "no-space",
                           hb, time.time())
            return "no-space"

    # stage the torrent, then kick aria2c — but ONLY if aria2 does not already
    # know about a download for this file. It used to be gated on the file's
    # mere PRESENCE (a present partial file means a download is already in
    # progress; the 60 s EEM timer must NOT re-addTorrent it, which would
    # duplicate/corrupt the download) — but on a container platform (IOx CAF,
    # XR appmgr) the container, and aria2c's in-memory session with it, can be
    # recreated (crash restart, redeploy, upgrade) while the mount keeps the
    # partial file AND its `.aria2` control file untouched. A present file no
    # longer proves anything is in progress in that case: nothing ever
    # re-added the torrent, so the device logged the same PROGRESS percentage
    # forever (board #70, hardware-reproduced on IOx and on a Cisco 8010's XR
    # appmgr). The guard below is keyed on ARIA2'S OWN KNOWLEDGE of the file
    # (deps.aria_stats), never on file presence alone.
    have = deps.file_size(stage)
    # A SAME-ID REPUBLISH regenerates the torrent (server/publish.py writes a
    # new info hash under the unchanged id), and nothing on the device ever
    # removed `<id>.torrent` — not remove_stage, not park, not purge_others —
    # so the OLD torrent was re-added on every tick and the device fetched
    # the old content forever (or sat at 0 % once the old swarm was gone).
    # The identity the torrent was fetched FOR is recorded per image; when the
    # catalog's identity has moved, the on-disk torrent, its control file and
    # whatever it delivered are stale together. An older state file that never
    # recorded one only re-fetches the torrent (below), touching no download.
    torrent_stale = (deps.file_size(torrent) is not None
                     and st.get("torrent_id") not in (None, torrent_id))
    # More bytes than the catalog declares can only be an earlier content's
    # download, never progress.
    if torrent_stale or (have is not None and have > size):
        deps.emit("RECHECK",
                  "%s catalog torrent changed under image id %s; discarding "
                  "the stale torrent and download" % (image["filename"], img_id))
        deps.remove_stage(stage)
        deps.remove_stage(stage + ".aria2")
        deps.remove_stage(torrent)
        have = None
    # The state marker records both the platform's authentication form and the
    # tracker transport generation. The migration above handles an unchanged
    # identity; a genuinely new torrent records the current marker here.
    if (deps.file_size(torrent) is None
            or st.get("torrent_id") != torrent_id):
        try:
            deps.catalog.download_torrent(img_id, torrent)
        except Exception as e:
            # One image's torrent GET failing — 404 when the file is missing,
            # 503 while the deployment gate is closed, 500 without an announce
            # credential — used to unwind the WHOLE tick: no set heartbeat, no
            # telemetry replay, and main() never saved the done/copied work of
            # the siblings processed before it. Report it as THIS image's
            # error and let the set carry on; the next tick retries.
            deps.emit("TORRENT-UNAVAILABLE",
                      "%s torrent not available from the catalog: %s"
                      % (image["filename"], e))
            tick.heartbeat(image, deps, "error",
                           target_fs=state.get("stage_fs"),
                           tele_on=tele_on, stream_on=stream_on,
                           stage_error="catalog torrent unavailable: %s" % e)
            return "torrent-unavailable"
        st["torrent_id"] = torrent_id
        st["torrent_auth_format"] = torrent_transport
    # ARIA2 MAY HAVE FORGOTTEN A PRESENT FILE (board #70). A present partial
    # (or a size-matching file still marked 'downloading' below) no longer
    # proves aria2 is actively fetching it — ask aria2 directly.
    resume_untracked = False
    if have is not None and deps.aria_stats(stage) is None:
        if deps.file_size(stage + ".aria2") is None:
            # No control file to resume FROM. A re-added download with no
            # control file loads no real bitfield, and aria2's own
            # bt-seed-unverified option — needed so a genuinely finished
            # download can be re-seeded without a full re-hash — marks it
            # complete WITHOUT EVER HASHING IT in exactly that situation
            # (RequestGroup.cc's BitTorrent branch: no control file + file
            # present -> markAllPiecesDone() -> onDownloadFinished(), before
            # any integrity check runs). Re-adding here would announce a
            # TRUNCATED file to the swarm as a finished seed. There is
            # nothing left to trust about what actually landed without that
            # bitfield, so discard it and restart the download clean instead
            # — exactly like the RECHECK case above, just discovered later.
            deps.emit("RECHECK",
                      "%s partial staged file has no aria2 control file; "
                      "discarding and restarting the download"
                      % image["filename"])
            deps.remove_stage(stage)
            have = None
        else:
            # The control file survived, so re-adding loads the REAL bitfield
            # and re-verifies it (the launcher's --check-integrity default) —
            # the ordinary #66 resume case, just re-entered after aria2 itself
            # lost track of the download (container/daemon restart). Also
            # covers a COMPLETED file behind a stale .aria2 sidecar that
            # survived a SIGKILL before aria2's next auto-save could clear it:
            # the re-add loads that stale bitfield, the file is already all
            # there, and the very next auto-save removes the control file.
            resume_untracked = True
    if have is None or resume_untracked:
        # clear any stale/phantom aria2 entry (e.g. a completed seed whose staged
        # file was deleted) so addTorrent actually re-downloads instead of being a
        # silent no-op on the duplicate info_hash.
        # A down RPC (aria2c launch failed / daemon died) must NOT crash the
        # tick: these are the only RPC calls before the staging heartbeat, and
        # letting the connection error escape is the 2026-08-20 failure class —
        # the device never heartbeats and is invisible exactly while broken.
        # OSError covers the whole family (URLError subclasses it). Degrade to
        # an error heartbeat; the next tick retries after bootstrap relaunches.
        # A fresh download of this image starts here: drop any peer-transfer
        # snapshot left by a PREVIOUS transfer of the same file, which is the
        # only thing that shares its sidecar name.
        _discard_peer_transfer_records(stage)
        try:
            deps.aria_remove(image["filename"])
            deps.aria_add(torrent, stage_dir)
            # Provenance (Directive 2): proof, for the eventual origin
            # verdict, that THIS agent's own aria2 session is what is
            # fetching this image — recorded only once the call actually
            # went through (an RPC failure below re-tries the whole thing,
            # including this, next tick).
            state.setdefault(img_id, {})["download_started"] = True
        except TrackerAuthConfigError:
            # The torrent URL deliberately carries no credential. Never start
            # it without the separately scoped per-device announce bearer, and
            # never print that bearer in the diagnostic.
            deps.emit("TRACKER-AUTH",
                      "tracker authorization unavailable; refusing addTorrent")
            tick.heartbeat(image, deps, "error",
                           target_fs=state.get("stage_fs"),
                           tele_on=tele_on, stream_on=stream_on,
                           stage_error="tracker authorization unavailable")
            return "tracker-auth"
        except OSError as e:
            # An HTTP 400/401 from the RPC endpoint is NOT a dead daemon: it is
            # aria2c rejecting our token, which is the ordinary state of a
            # freshly-onboarded device. The installer bakes rpc-secret EMPTY on
            # purpose, guestshell-start.sh seeds aria2c from that file, and the
            # real secret only arrives on this agent's first token refresh --
            # so until bootstrap.sh's step 2 syncs the file and bounces the
            # daemon, every RPC we make is unauthorized. aria2-next answers
            # that with HTTP 400 (upstream aria2 returns a JSON-RPC error
            # object instead, which is why this never showed up before the
            # fork), and urllib's HTTPError is an OSError subclass -- so this
            # arm reported a healthy device mid-bringup as a staging FAILURE,
            # "aria2c RPC unreachable: HTTP Error 400: Bad Request", which
            # cleared itself a tick or two later once bootstrap ran again.
            #
            # Reported as 'staging' with NO stage_error: the device really is
            # in the staging lifecycle and nothing has failed. 'staging' is
            # also an already-valid wire value (catalog.py _V2_STAGE_STATES),
            # so this cannot make a heartbeat get rejected. The return string
            # stays "aria2-down" because bootstrap logs and tests key off that
            # vocabulary -- what changes is what the OPERATOR is told, not the
            # control flow.
            if getattr(e, "code", None) in (400, 401):
                deps.emit("ARIA2-AUTH",
                          "aria2c has not adopted the rotated RPC secret yet; "
                          "bootstrap will resync and bounce it (%s)" % e)
                tick.heartbeat(image, deps, "staging",
                               target_fs=state.get("stage_fs"),
                               tele_on=tele_on, stream_on=stream_on)
                return "aria2-down"
            deps.emit("ARIA2-DOWN",
                      "aria2c RPC unreachable; cannot stage %s: %s"
                      % (image["filename"], e))
            rpc_obs = None
            try:
                rpc_obs = telemetry_report.build_observation(
                    obs_state="rpc_unavailable", observed_at=time.time(),
                    transfer_id=telemetry_report.ensure_transfer_id(
                        state, img_id),
                    image_id=img_id)
            except Exception:
                pass
            tick.heartbeat(image, deps, "error",
                           target_fs=state.get("stage_fs"),
                           tele_on=tele_on, stream_on=stream_on,
                           observation=rpc_obs,
                           stage_error="aria2c RPC unreachable: %s" % e)
            return "aria2-down"
        except RuntimeError as e:
            # addTorrent can answer HTTP 200 with a JSON-RPC error or no GID.
            # _aria_add_result rejects that response: report this image's
            # failure without losing the tick or completed sibling work.
            # Arbitrary RPC diagnostics may contain credentials.
            deps.emit("ARIA2-DOWN", "%s download could not start (%s)"
                      % (image["filename"], type(e).__name__))
            tick.heartbeat(
                image, deps, "error", target_fs=state.get("stage_fs"),
                tele_on=tele_on, stream_on=stream_on,
                stage_error="aria2c could not start the download; retrying",
                observation=_not_active_observation(tele_on, time.time()))
            return "aria2-down"
        if resume_untracked:
            deps.emit("STAGING",
                      "%s aria2 lost track of an in-progress download "
                      "(container/daemon restart); re-added to resume"
                      % image["filename"])
        else:
            deps.emit("STAGING", "downloading %s via private swarm" % image["filename"])
    else:
        # one progress line per agent run (60s) — NOT a separate fast timer (the
        # old 10s IRIS-MONITOR raced and spammed). Computed from the on-disk size.
        deps.emit("PROGRESS", "%s %d%% (%dMB/%dMB)"
                  % (image["filename"], have * 100 // size, have >> 20, size >> 20))
    obs, peers = _build_observation(
        cfg, deps, state, img_id, stage, "downloading", time.time(),
        tick_seconds=tick.tick_seconds)
    hb = tick.heartbeat(image, deps,
                        target_fs=state.get("stage_fs"),
                        tele_on=tele_on,
                        observation=obs,
                        stream_on=stream_on)
    tick.telemetry(cfg, deps, state, img_id, stage, "downloading",
                   hb, time.time(), peers=peers)
    return "downloading"


def _torrent_identity(image):
    """What `<id>.torrent` on disk was fetched FOR: the catalog's info hash
    when the image record carries one (server/publish.py writes
    info_hash_hex), else the content sha256. Either moves whenever the
    catalog regenerates the torrent under an unchanged id, which is the
    ordinary republish event (ids derive from filenames)."""
    ih = image.get("info_hash_hex")
    if isinstance(ih, str) and ih.strip():
        return "ih:" + ih.strip().lower()
    return "sha:" + str(image.get("sha256") or "")


class InstructionApplyError(ValueError):
    """A bounded instruction could not be applied to the local aria2."""


def _decimal_i63(value):
    if isinstance(value, bool):
        raise InstructionApplyError("invalid option")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        number = int(value)
    else:
        raise InstructionApplyError("invalid option")
    if number < 0 or number > _MAX_I63:
        raise InstructionApplyError("invalid option")
    return number


def _owned_aria_options(value, names):
    if not isinstance(value, dict):
        raise InstructionApplyError("invalid option result")
    try:
        return {name: _decimal_i63(value[name]) for name in names}
    except (KeyError, TypeError, ValueError, OverflowError):
        raise InstructionApplyError("invalid option result") from None


def _instruction_rpc(rpc, method, params):
    try:
        return rpc(method, params)
    except InstructionApplyError:
        raise
    except Exception:
        raise InstructionApplyError("RPC unavailable") from None


def _instruction_values(result):
    qos = dict(_FIXED_QOS)
    control = dict(_FIXED_CONTROL)
    instruction = result.get("instruction") if isinstance(result, dict) else None
    if not isinstance(instruction, dict):
        return qos, control
    role = instruction.get("role")
    device = instruction.get("device")
    if not isinstance(role, dict) or not isinstance(device, dict):
        return qos, control
    role_qos = role.get("qos")
    role_control = role.get("control")
    device_qos = device.get("qos_override")
    device_control = device.get("control_override")
    if isinstance(role_qos, dict):
        qos.update({name: role_qos[name] for name in _FIXED_QOS
                    if name in role_qos})
    if isinstance(device_qos, dict):
        qos.update({name: device_qos[name] for name in _FIXED_QOS
                    if name in device_qos})
    if isinstance(role_control, dict):
        control.update({name: role_control[name] for name in _FIXED_CONTROL
                        if name in role_control})
    if isinstance(device_control, dict):
        control.update({name: device_control[name] for name in _FIXED_CONTROL
                        if name in device_control})
    return qos, control


def _canonical_ipv4(value):
    if not isinstance(value, str):
        raise InstructionApplyError("invalid peer rule")
    try:
        parsed = (ipaddress.IPv4Network(value, strict=True)
                  if "/" in value else ipaddress.IPv4Address(value))
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError,
            ValueError):
        raise InstructionApplyError("invalid peer rule") from None
    if str(parsed) != value:
        raise InstructionApplyError("invalid peer rule")
    return parsed


def _allow_complement(allowed):
    canonical = sorted(str(_canonical_ipv4(value)) for value in allowed)
    digest = hashlib.sha256(
        json.dumps(canonical, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    if (_ALLOW_COMPLEMENT_CACHE["digest"] == digest
            and isinstance(_ALLOW_COMPLEMENT_CACHE["rules"], list)):
        return list(_ALLOW_COMPLEMENT_CACHE["rules"])
    intervals = []
    for text in canonical:
        item = _canonical_ipv4(text)
        if isinstance(item, ipaddress.IPv4Address):
            start = end = int(item)
        else:
            start, end = int(item.network_address), int(item.broadcast_address)
        intervals.append((start, end))
    intervals.sort(key=lambda interval: interval[0])
    merged = []
    for start, end in intervals:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    intervals = merged
    rules = []
    cursor = 0
    maximum = (1 << 32) - 1
    for start, end in intervals:
        if cursor < start:
            rules.extend(str(network) for network in
                         ipaddress.summarize_address_range(
                             ipaddress.IPv4Address(cursor),
                             ipaddress.IPv4Address(start - 1)))
        cursor = max(cursor, end + 1)
    if cursor <= maximum:
        rules.extend(str(network) for network in
                     ipaddress.summarize_address_range(
                         ipaddress.IPv4Address(cursor),
                         ipaddress.IPv4Address(maximum)))
    rules.append("::/0")
    _ALLOW_COMPLEMENT_CACHE.update(digest=digest, rules=list(rules))
    return list(rules)


def _peer_blocklist(result, cfg):
    peers = result.get("effective_peers") if isinstance(result, dict) else None
    if not isinstance(peers, dict):
        return [], False
    mode = peers.get("mode")
    if mode == "tracker-only":
        return [], False
    if mode == "deny":
        if set(peers) != {"mode", "rules", "include_origin",
                          "allowed_expires_at"}:
            raise InstructionApplyError("invalid peer posture")
        if (not isinstance(peers["rules"], list)
                or not isinstance(peers["include_origin"], bool)):
            raise InstructionApplyError("invalid peer posture")
        _public_i63(peers["allowed_expires_at"])
        rules = list(peers["rules"]) + ["::/0"]
    elif mode == "allow":
        if set(peers) != {"mode", "allowed", "include_origin",
                          "allowed_expires_at"}:
            raise InstructionApplyError("invalid peer posture")
        if (not isinstance(peers["allowed"], list)
                or not isinstance(peers["include_origin"], bool)):
            raise InstructionApplyError("invalid peer posture")
        _public_i63(peers["allowed_expires_at"])
        allowed = list(peers["allowed"])
        if peers["include_origin"]:
            try:
                hostname = urllib.parse.urlsplit(cfg.get("catalog_url", "")).hostname
                address = ipaddress.IPv4Address(hostname)
                if str(address) != hostname:
                    raise ValueError
            except (AttributeError, TypeError, ValueError,
                    ipaddress.AddressValueError):
                return [], True
            allowed.append(str(address))
        rules = _allow_complement(allowed)
    else:
        raise InstructionApplyError("invalid peer posture")
    for rule in rules:
        try:
            if ":" in rule:
                parsed = ipaddress.IPv6Network(rule, strict=True)
                canonical = str(parsed)
            else:
                canonical = str(_canonical_ipv4(rule))
        except (ValueError, TypeError):
            raise InstructionApplyError("invalid peer rule") from None
        if canonical != rule:
            raise InstructionApplyError("invalid peer rule")
    return rules, False


def _valid_apply_baseline(value):
    if (not isinstance(value, dict)
            or set(value) != {"session_id", "rules_digest",
                              "blocklist_revision", "blocklist_rules",
                              "applied"}):
        return None
    session = value.get("session_id")
    digest = value.get("rules_digest")
    try:
        applied = _public_integer_unit(value.get("applied"), _APPLIED_FIELDS)
        revision = _public_i63(value.get("blocklist_revision"))
        count = _public_i63(value.get("blocklist_rules"))
    except (TypeError, ValueError):
        return None
    if (not isinstance(session, str) or not 1 <= len(session) <= 128
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
        return None
    return dict(value, applied=applied, blocklist_revision=revision,
                blocklist_rules=count)


def _apply_instruction(result, cfg, state, rpc, torrent_defaults):
    """Read, reassert and attest the closed Task 16 aria2 transaction."""
    if not callable(rpc) or not isinstance(torrent_defaults, dict):
        raise InstructionApplyError("instruction application unavailable")
    qos, _control = _instruction_values(result)
    global_write = {
        "bt-max-peers": str(qos["max_peers"]),
        "max-upload-limit": str(qos["leech_up_bps"]),
        "max-download-limit": str(qos["leech_down_bps"]),
        "max-overall-upload-limit": str(qos["overall_up_bps"]),
        "max-overall-download-limit": str(qos["overall_down_bps"]),
        "bt-request-peer-speed-limit": str(
            qos["request_peer_speed_limit_bps"]),
        "max-concurrent-downloads": str(qos["max_concurrent"]),
    }
    applied = {public: _decimal_i63(global_write[option])
               for option, public in _ARIA_GLOBAL_OPTIONS}
    rules, peer_degraded = _peer_blocklist(result, cfg)
    rules_digest = hashlib.sha256(
        json.dumps(rules, separators=(",", ":")).encode("ascii")
    ).hexdigest()

    session_result = _instruction_rpc(rpc, "aria2.getSessionInfo", [])
    if (not isinstance(session_result, dict)
            or set(session_result) != {"sessionId"}
            or not isinstance(session_result["sessionId"], str)
            or not 1 <= len(session_result["sessionId"]) <= 128):
        raise InstructionApplyError("invalid session")
    session = session_result["sessionId"]
    global_read = _owned_aria_options(
        _instruction_rpc(rpc, "aria2.getGlobalOption", []),
        tuple(option for option, _public in _ARIA_GLOBAL_OPTIONS))
    active_raw = _instruction_rpc(
        rpc, "aria2.tellActive", [["gid", "files", "seeder"]])
    active = []
    row = None
    try:
        if not isinstance(active_raw, list) or len(active_raw) > 10:
            raise InstructionApplyError("invalid active downloads")
        for row in active_raw:
            if (not isinstance(row, dict)
                    or set(row) != {"gid", "files", "seeder"}
                    or not isinstance(row["gid"], str)
                    or _ARIA_GID_RE.fullmatch(row["gid"]) is None
                    or not isinstance(row["files"], list)
                    or row["seeder"] not in ("true", "false")):
                raise InstructionApplyError("invalid active download")
            active.append((row["gid"], row["seeder"] == "true"))
    finally:
        row = None
        active_raw = None
    live_reads = []
    live_names = tuple(option for option, _public in _ARIA_LIVE_OPTIONS)
    for gid, seeder in active:
        current = _owned_aria_options(
            _instruction_rpc(rpc, "aria2.getOption", [gid]), live_names)
        live_reads.append((gid, seeder, current))

    if _instruction_rpc(
            rpc, "aria2.changeGlobalOption", [dict(global_write)]) != "OK":
        raise InstructionApplyError("global write failed")
    for gid, seeder, _current in live_reads:
        live_write = {
            "bt-max-peers": str(qos["max_peers"]),
            "max-upload-limit": str(
                qos["seed_up_bps"] if seeder else qos["leech_up_bps"]),
            "max-download-limit": str(
                qos["seed_down_bps"] if seeder else qos["leech_down_bps"]),
            "bt-request-peer-speed-limit": str(
                qos["request_peer_speed_limit_bps"]),
        }
        if _instruction_rpc(
                rpc, "aria2.changeOption", [gid, live_write]) != "OK":
            raise InstructionApplyError("download write failed")
    block = _instruction_rpc(
        rpc, "aria2.setBtPeerBlocklist", [list(rules)])
    block = _public_integer_unit(
        block, ("ruleCount", "revision", "disconnectedPeers",
                "removedPeers"))

    bag = state.get("instructions")
    if not isinstance(bag, dict):
        bag = {}
        state["instructions"] = bag
    previous = _valid_apply_baseline(bag.get("aria_apply"))
    same_session = previous is not None and previous["session_id"] == session
    drift_rows = []
    if same_session:
        for option, public in _ARIA_GLOBAL_OPTIONS:
            observed = global_read[option]
            expected = applied[public]
            if observed != expected:
                drift_rows.append({"option": public, "expected": expected,
                                   "observed": observed})
        for _gid, seeder, current in sorted(live_reads, key=lambda row: row[0]):
            expected_live = {
                "bt_max_peers": qos["max_peers"],
                "max_upload_limit": (qos["seed_up_bps"] if seeder
                                     else qos["leech_up_bps"]),
                "max_download_limit": (qos["seed_down_bps"] if seeder
                                       else qos["leech_down_bps"]),
                "request_peer_speed_limit":
                    qos["request_peer_speed_limit_bps"],
            }
            for option, public in _ARIA_LIVE_OPTIONS:
                if current[option] != expected_live[public]:
                    drift_rows.append({
                        "option": public, "expected": expected_live[public],
                        "observed": current[option]})
    fact = _heartbeat_with_instruction(
        {}, result.get("attestation") if isinstance(result, dict) else None)
    source_state = fact.get("instr_state")
    if peer_degraded:
        fact["instr_state"] = "tracker-only"
        fact.pop("instr_reason", None)
    elif (previous is not None
          and source_state in ("none", "applied", "lkg")):
        fact["instr_state"] = "reasserted"
    fact.update(applied=applied, blocklist_rules=block["ruleCount"],
                blocklist_revision=block["revision"])
    drift = {"options": drift_rows}
    if same_session and previous["rules_digest"] == rules_digest:
        if previous["blocklist_revision"] != block["revision"]:
            drift["blocklist_revision"] = {
                "expected": previous["blocklist_revision"],
                "observed": block["revision"]}
        if previous["blocklist_rules"] != block["ruleCount"]:
            drift["blocklist_rules"] = {
                "expected": previous["blocklist_rules"],
                "observed": block["ruleCount"]}
    if drift_rows or len(drift) > 1:
        fact["qos_drift"] = drift
    bag["aria_apply"] = {
        "session_id": session, "rules_digest": rules_digest,
        "blocklist_revision": block["revision"],
        "blocklist_rules": block["ruleCount"], "applied": dict(applied),
    }
    future = {option: global_write[option]
              for option, _public in _ARIA_LIVE_OPTIONS}
    torrent_defaults.clear()
    torrent_defaults.update(future)
    return fact


def _task16_runtime(deps):
    return (callable(getattr(deps, "instruction_step", None))
            and callable(getattr(deps, "aria_rpc", None))
            and isinstance(getattr(deps, "torrent_defaults", None), dict))


def _policy_assignment_ids(policy):
    if not isinstance(policy, dict):
        raise ValueError("invalid policy")
    single = policy.get("approved_image_id")
    if ("approved_image_id" in policy and single is not None
            and (not isinstance(single, str)
                 or not 1 <= len(single) <= 128)):
        raise ValueError("invalid policy")
    if "approved_image_ids" in policy:
        values = policy["approved_image_ids"]
        if not isinstance(values, (list, tuple)):
            raise ValueError("invalid policy")
        ids = list(values)
        if not ids and single is not None:
            ids = [single]
    else:
        ids = [] if single is None else [single]
    if (len(ids) > 10
            or any(not isinstance(value, str) or not 1 <= len(value) <= 128
                   for value in ids)):
        raise ValueError("invalid policy")
    return list(dict.fromkeys(ids))


def _bounded_finite_number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value) and 0 <= value <= _MAX_I63
    except (OverflowError, TypeError, ValueError):
        return False


def _valid_poll_marker(value):
    if (not isinstance(value, dict)
            or set(value) != {"boot_id", "monotonic", "assignment_ids"}):
        return None
    boot = value.get("boot_id")
    stamp = value.get("monotonic")
    ids = value.get("assignment_ids")
    if (not isinstance(boot, str) or not 1 <= len(boot) <= 128
            or not _bounded_finite_number(stamp)
            or not isinstance(ids, list) or len(ids) > 10
            or any(not isinstance(item, str) or not 1 <= len(item) <= 128
                   for item in ids)):
        return None
    return {"boot_id": boot, "monotonic": stamp,
            "assignment_ids": list(ids)}


def _valid_heartbeat_hint(value):
    if not isinstance(value, dict) or not set(value).issubset({
            "instr_rev", "keylist_seq"}):
        return None
    clean = {}
    revision = value.get("instr_rev")
    if revision is not None:
        if (not isinstance(revision, dict)
                or set(revision) != {"epoch", "instr_serial"}
                or any(isinstance(revision.get(name), bool)
                       or not isinstance(revision.get(name), int)
                       or not 0 <= revision[name] <= _MAX_I63
                       for name in ("epoch", "instr_serial"))):
            return None
        clean["instr_rev"] = dict(revision)
    if "keylist_seq" in value:
        sequence = value["keylist_seq"]
        if (isinstance(sequence, bool) or not isinstance(sequence, int)
                or not 1 <= sequence <= _MAX_I63):
            return None
        clean["keylist_seq"] = sequence
    return clean or None


def _record_heartbeat_hint(state, response, authenticated_date):
    if not _bounded_finite_number(authenticated_date):
        return
    bag = state.get("instructions")
    if not isinstance(bag, dict):
        bag = {}
        state["instructions"] = bag
    candidate = {}
    if isinstance(response, dict):
        for name in ("instr_rev", "keylist_seq"):
            if name in response:
                candidate[name] = response[name]
    clean = _valid_heartbeat_hint(candidate)
    if clean is None:
        bag.pop("heartbeat_hint", None)
    else:
        bag["heartbeat_hint"] = clean


def _cadence_due(state, interval, boot, monotonic_now):
    if interval == 60:
        return True
    bag = state.get("instructions")
    if not isinstance(bag, dict):
        return True
    marker = _valid_poll_marker(bag.get("poll"))
    if marker is None or marker["boot_id"] != boot:
        return True
    if monotonic_now < marker["monotonic"]:
        return True
    if monotonic_now - marker["monotonic"] >= interval:
        return True
    hint = _valid_heartbeat_hint(bag.get("heartbeat_hint"))
    if hint is not None:
        revision = hint.get("instr_rev")
        if revision is not None:
            local = (bag.get("accepted_epoch"), bag.get("accepted_serial"))
            if local != (revision["epoch"], revision["instr_serial"]):
                return True
        if ("keylist_seq" in hint
                and bag.get("keylist_seq") != hint["keylist_seq"]):
            return True
    return False


def _cadence_heartbeat(cfg, deps, state, ids, tele_on, stream_on,
                       attestation):
    now = time.time()
    if not ids:
        payload = _heartbeat(
            None, deps, "unassigned", target_fs=cfg.get("target_fs"),
            tele_on=tele_on, stream_on=stream_on,
            observation=_not_active_observation(tele_on, now))
    else:
        first = ids[0]
        staged = _staged_image_ids(state, ids)
        ready = len(staged) == len(ids)
        payload = _heartbeat(
            {"id": first}, deps, "ready" if ready else "staging",
            target_fs=cfg.get("target_fs"), tele_on=tele_on,
            stream_on=stream_on,
            observation=_not_active_observation(tele_on, now),
            staged_image_ids=staged if len(ids) > 1 else None)
    response = _send_heartbeat(
        deps, cfg["device_id"], payload, attestation)
    # A cadence-only tick deliberately takes no sample, but its heartbeat is
    # still authoritative for renewing or clearing stream directives.
    telemetry_report.store_directives(state, response, now)
    response_date = getattr(deps.catalog, "response_authenticated_date", None)
    _record_heartbeat_hint(state, response, response_date)
    return response


def _contained_cadence_heartbeat(cfg, deps, state, ids, tele_on, stream_on,
                                 attestation):
    try:
        return _cadence_heartbeat(
            cfg, deps, state, ids, tele_on, stream_on, attestation)
    except Exception as exc:
        try:
            deps.emit("HEARTBEAT-FAIL",
                      "%s heartbeat construction failed (ignored): %s"
                      % (cfg["device_id"], type(exc).__name__))
        except Exception:
            pass
        return None


# Longest stage_error a contained staging failure reports (#235). Well
# inside the server's 1024-byte heartbeat cap (catalog.py _HEARTBEAT_STR_CAPS)
# and short enough for the Console's device row.
_STAGE_ERROR_MAX = 240
_STAGE_ERROR_URL_RE = re.compile(r"[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)
# Credential-looking keys: the agent's own config names (catalog_token,
# announce_token, device_ssh_pass, announce_key), HTTP auth words, and any
# *key / *pass* spelling. Only a key=value / key:value pair is redacted, so an
# exception TYPE such as KeyError (added after redaction anyway) is untouched.
_STAGE_ERROR_SECRET_RE = re.compile(
    r"(\w*token|\w*secret|\w*pass(?:w(?:or)?d)?|bearer|authorization|\w*key)"
    r"\s*[=:]\s*\S+", re.IGNORECASE)


def _public_stage_error(exc, limit=_STAGE_ERROR_MAX):
    """The exception text a contained staging failure may put on the wire.

    Exception messages are not written with the heartbeat in mind: a catalog
    or tracker error can quote an authenticated URL, an aria2 RPC fault can
    echo the `token:<secret>` parameter it rejected. Any URL and any
    key=value/key:value pair whose key names a credential is redacted before
    the text leaves the device, whitespace is collapsed, and the result is
    bounded to `limit` characters. The exception type always leads so an
    empty message (KeyError()) still says something."""
    text = " ".join(str(exc).split())
    text = _STAGE_ERROR_URL_RE.sub("<url>", text)
    text = _STAGE_ERROR_SECRET_RE.sub(r"\1=<redacted>", text)
    name = type(exc).__name__
    text = "%s: %s" % (name, text) if text else name
    if len(text) > limit:
        text = text[:max(limit - 3, 0)] + "..."
    return text


def _contained_stage_failure(cfg, deps, state, img_id, tick, tele_on,
                             stream_on, exc):
    """Record ONE image's uncontained staging exception as that image's
    verdict instead of letting it escape run_once (#235).

    Before this, any exception inside _stage_image -- deps.target_fs()
    refusing to name a writable IOS filesystem ("no proved writable IOS
    staging filesystem"), an SSH transport error, a state-shape surprise --
    unwound past the set heartbeat POST below, so the server never heard
    from the device at all: last_seen stayed "never" and the only trace was a
    syslog line on the device. A device that cannot stage must still
    register, exactly like the unassigned path does; the failure rides the
    heartbeat as stage_state "error" with the bounded, redacted exception
    text as stage_error, and the tick returns "stage-error" for it. Nothing
    is written to state: the next tick re-runs the image and re-reports or
    clears the error on its own, and a bare stage_error entry would read as
    an image record to the park pass.

    The tick's earlier records are replaced: whatever heartbeat or telemetry
    the image staged before raising described a tick that did not finish."""
    text = _public_stage_error(exc)
    try:
        deps.emit("STAGE-FAIL", "%s staging failed: %s" % (img_id, text))
    except Exception:
        pass
    tick.tele = None
    tick.heartbeat({"id": img_id}, deps, "error",
                   target_fs=state.get("stage_fs") or cfg.get("target_fs"),
                   tele_on=tele_on, stream_on=stream_on,
                   stage_error=text,
                   observation=_not_active_observation(
                       tele_on, time.time()))
    return "stage-error"


def run_once(cfg, deps, state, tick_seconds=60):
    tick_seconds = _normalize_tick_seconds(tick_seconds)
    # Self-refresh the catalog token BEFORE any catalog work, once it's past
    # half-life (or its expiry is unknown). Best-effort: deps.refresh() does the
    # POST + client rebind + atomic conf rewrite and returns the updated cfg,
    # or None on failure — on failure we log and proceed on the current
    # in-memory cfg (a 7d TTL + half-life refresh leaves a ~3.5d retry buffer,
    # so a few failed ticks never strand the device; the live client's bearer
    # is _refresh_impl's concern, see its docstring for the failure split).
    _container_platform = cfg.get("device_platform") in agent_config.DEVICE_PLATFORMS
    expires_at = int(float(cfg.get("token_expires_at", 0) or 0))
    catalog_now = None
    instruction_runtime = None
    monotonic_now = None
    current_boot_id = None
    # main() validates these fields before run_once. A few old unit fixtures
    # deliberately call this function with only device_id/stage_dir; preserve
    # that non-runtime seam without consulting the untrusted device wall clock.
    # Every production config has catalog_url and therefore refreshes
    # conservatively until an authenticated catalog Date anchors this boot.
    if cfg.get("catalog_url") or isinstance(state.get("instructions"), dict):
        import instr
        instruction_runtime = instr
        monotonic_now = time.monotonic()
        current_boot_id = instr.boot_id()
        catalog_now = instr.project_clock(
            state, "catalog", monotonic_now, current_boot_id)
    refresh_due = catalog_now is None
    if catalog_now is not None:
        refresh_due = needs_refresh(catalog_now, expires_at,
                                    _TOKEN_TTL, _TOKEN_REFRESH_AT)
    if ((_container_platform and not cfg.get("announce_token")) or refresh_due):
        new_cfg = deps.refresh()
        if new_cfg is None:
            # main() never reaches this point without catalog_url. Preserve
            # the old direct-unit-call seam's quiet behavior while still
            # exercising its conservative refresh callback.
            if cfg.get("catalog_url") or expires_at == 0:
                deps.emit(
                    "TOKEN-REFRESH-FAIL",
                    "catalog token refresh failed; proceeding on current token")
        else:
            cfg = new_cfg
    sid = cfg["device_id"]
    stage_dir = cfg["stage_dir"]
    tele_on = telemetry_report.enabled(cfg)
    stream_on = telemetry_report.stream_enabled(cfg)

    # Upgrade from an older agent: clear "copied" so the next copy_to_root
    # re-verifies the flash-root copy instead of trusting the old flag.
    # Keep root_file — the park pass below needs it to know which file each
    # image placed. Only emit UPGRADE if we actually cleared something.
    # Runs ONCE per tick, before the set is reconciled or any image is staged.
    if state.get("schema_version", 1) < _STATE_SCHEMA:
        cleared = False
        for v in state.values():
            if isinstance(v, dict) and v.get("copied"):
                v["copied"] = False
                cleared = True
        state["schema_version"] = _STATE_SCHEMA
        if cleared:
            deps.emit("UPGRADE", "re-verifying flash-root copy after upgrade")

    if "max_peers" in cfg:
        instruction_bag = state.get("instructions")
        if not isinstance(instruction_bag, dict):
            instruction_bag = {}
            state["instructions"] = instruction_bag
        if instruction_bag.get("max_peers_ignored") is not True:
            # Mark before the best-effort notice so a failed syslog write does
            # not repeat forever or suppress the tick's heartbeat/staging work.
            instruction_bag["max_peers_ignored"] = True
            try:
                deps.emit(
                    "MAX-PEERS-IGNORED",
                    "legacy max_peers configuration is ignored; signed "
                    "instructions control peer limits")
            except Exception:
                pass

    task16 = _task16_runtime(deps)
    instruction_attestation = None
    if task16:
        # Refresh is deliberately complete before this fresh launcher-local
        # verifier budget and cache-only LKG preview are created.
        monotonic_now = time.monotonic()
        if instruction_runtime is None:
            import instr
            instruction_runtime = instr
        current_boot_id = instruction_runtime.boot_id()
        verification_attempts = {}
        try:
            preview = deps.instruction_step(
                cfg=cfg, state=state, hints={}, catalog_date=None,
                cache_only=True,
                verification_attempts=verification_attempts)
            if not isinstance(preview, dict):
                raise ValueError("invalid preview")
        except Exception as e:
            deps.emit("INSTRUCTION-FAIL",
                      "instruction preview failed (ignored): %s"
                      % type(e).__name__)
            preview = {
                "instruction": None, "effective": None,
                "effective_peers": {"mode": "tracker-only",
                                    "include_origin": False},
                "attestation": _instruction_unavailable_fact(state),
            }
        _qos, preview_control = _instruction_values(preview)
        interval = preview_control.get("catalog_tick_s", 60)
        if (isinstance(interval, bool) or not isinstance(interval, int)
                or not 60 <= interval <= 900 or interval % 60):
            interval = 60
        due = _cadence_due(
            state, interval, current_boot_id, monotonic_now)
        marker = _valid_poll_marker(
            state.get("instructions", {}).get("poll")
            if isinstance(state.get("instructions"), dict) else None)
        if not due:
            ids = marker["assignment_ids"]
            try:
                instruction_attestation = _apply_instruction(
                    preview, cfg, state, deps.aria_rpc,
                    deps.torrent_defaults)
            except Exception as e:
                deps.emit("INSTRUCTION-APPLY-FAIL",
                          "instruction apply failed: %s"
                          % type(e).__name__)
                instruction_attestation = _instruction_unavailable_fact(state)
                _contained_cadence_heartbeat(
                    cfg, deps, state, ids, tele_on, stream_on,
                    instruction_attestation)
                return "instruction-apply-unavailable"
            _contained_cadence_heartbeat(
                cfg, deps, state, ids, tele_on, stream_on,
                instruction_attestation)
            return "catalog-not-due"

        try:
            policy = deps.catalog.get_policy(sid)
            # Bind all hint/clock decisions to this response's own Date before
            # any heartbeat or other request can replace the client property.
            authenticated_date = getattr(
                deps.catalog, "response_authenticated_date", None)
            policy_received_monotonic = time.monotonic()
            ids = _policy_assignment_ids(policy)
        except Exception as e:
            try:
                instruction_runtime.note_hint(
                    state, None, authenticated=False)
            except Exception:
                pass
            deps.emit("CATALOG-UNAVAILABLE",
                      "catalog policy unavailable: %s" % type(e).__name__)
            ids = [] if marker is None else marker["assignment_ids"]
            try:
                instruction_attestation = _apply_instruction(
                    preview, cfg, state, deps.aria_rpc,
                    deps.torrent_defaults)
            except Exception as apply_error:
                deps.emit("INSTRUCTION-APPLY-FAIL",
                          "instruction apply failed: %s"
                          % type(apply_error).__name__)
                instruction_attestation = _instruction_unavailable_fact(state)
                _contained_cadence_heartbeat(
                    cfg, deps, state, ids, tele_on, stream_on,
                    instruction_attestation)
                return "instruction-apply-unavailable"
            _contained_cadence_heartbeat(
                cfg, deps, state, ids, tele_on, stream_on,
                instruction_attestation)
            return "catalog-unavailable"

        if authenticated_date is not None:
            try:
                instruction_runtime.observe_clock(
                    state, "catalog", authenticated_date,
                    policy_received_monotonic, current_boot_id)
            except instruction_runtime.InstructionError:
                pass
        try:
            instruction_result = deps.instruction_step(
                cfg=cfg, state=state, hints=policy,
                catalog_date=authenticated_date, cache_only=False,
                verification_attempts=verification_attempts)
            if not isinstance(instruction_result, dict):
                raise ValueError("invalid instruction result")
        except Exception as e:
            deps.emit("INSTRUCTION-FAIL",
                      "instruction step failed (ignored): %s"
                      % type(e).__name__)
            instruction_result = {
                "instruction": None, "effective": None,
                "effective_peers": {"mode": "tracker-only",
                                    "include_origin": False},
                "attestation": _instruction_unavailable_fact(state),
            }
        bag = state.get("instructions")
        if not isinstance(bag, dict):
            bag = {}
            state["instructions"] = bag
        bag["poll"] = {
            "boot_id": current_boot_id,
            "monotonic": policy_received_monotonic,
            "assignment_ids": list(ids),
        }
        try:
            instruction_attestation = _apply_instruction(
                instruction_result, cfg, state, deps.aria_rpc,
                deps.torrent_defaults)
        except Exception as e:
            deps.emit("INSTRUCTION-APPLY-FAIL",
                      "instruction apply failed: %s" % type(e).__name__)
            instruction_attestation = _instruction_unavailable_fact(state)
            _contained_cadence_heartbeat(
                cfg, deps, state, ids, tele_on, stream_on,
                instruction_attestation)
            return "instruction-apply-unavailable"
    else:
        # Task 15 compatibility path for downstream callers that have not
        # supplied Task 16's RPC/default metadata.
        policy = deps.catalog.get_policy(sid)
        cumulative_catalog_date = getattr(
            deps.catalog, "last_authenticated_date", None)
        _missing_response_date = object()
        authenticated_date = getattr(
            deps.catalog, "response_authenticated_date", _missing_response_date)
        if authenticated_date is _missing_response_date:
            authenticated_date = cumulative_catalog_date
        catalog_clock_date = (cumulative_catalog_date
                              if cumulative_catalog_date is not None
                              else authenticated_date)
        if catalog_clock_date is not None:
            monotonic_now = time.monotonic()
            if instruction_runtime is None:
                import instr
                instruction_runtime = instr
                current_boot_id = instr.boot_id()
            try:
                instruction_runtime.observe_clock(
                    state, "catalog", catalog_clock_date,
                    monotonic_now, current_boot_id)
            except instruction_runtime.InstructionError:
                pass
        if callable(deps.instruction_step):
            try:
                instruction_result = deps.instruction_step(
                    cfg=cfg, state=state, hints=policy,
                    catalog_date=authenticated_date)
                if isinstance(instruction_result, dict):
                    instruction_attestation = instruction_result.get(
                        "attestation")
            except Exception as e:
                deps.emit("INSTRUCTION-FAIL",
                          "instruction step failed (ignored): %s"
                          % type(e).__name__)
                instruction_attestation = _instruction_unavailable_fact(state)
    if not task16:
        # Older servers and policy rows carry only the singular assignment.
        # Keep this permissive parsing only on the compatibility path; Task 16
        # already validated its bounded ordered set above.
        ids = policy.get("approved_image_ids")
        if not isinstance(ids, (list, tuple)) or not ids:
            single = policy.get("approved_image_id")
            ids = [single] if single else []
        ids = list(dict.fromkeys(i for i in ids if i))
    # The server's per-image transfer identities, to be adopted per image by
    # _stage_image. Only the SHAPE is settled here: a `plans` value that is not
    # a map at all (older server, legacy-bootstrap policy row, captive-portal
    # garbage) collapses to an empty map, every image is handed None, and the
    # agent mints its own ids exactly as it does today.
    #
    # The adoption itself deliberately does NOT happen in a loop right here,
    # which is where it first lived. Adopting for an id straight off the policy
    # writes state[img_id]['tele'] for an image the device may have no record
    # of and may never be able to stage; 'tele' is one of _IMAGE_ENTRY_FIELDS,
    # so that bare entry reads as a real image record to the park pass below
    # and — having no root_file, for an id the catalog cannot name — becomes a
    # PARK-DEFERRED emit on every tick, forever, the moment the id leaves the
    # set. _stage_image adopts instead, behind that image's catalog lookup and
    # filename whitelist and still ahead of every deps.aria_add().
    plans = policy.get("plans")
    plan_rows = plans if isinstance(plans, dict) else {}
    # Reconcile even an empty set: clearing the final assignment must stop
    # and park its torrents under the same ownership rules as any other
    # unassign, before reporting that the device is idle.
    _reconcile_set(deps, state, ids, stage_dir)
    if not ids:
        # Still heartbeat: an unassigned device must register (devices.json,
        # swarm map, telemetry posture) or console onboarding can never see
        # it come up — assignment only gates staging, not presence.
        hb_resp = _send_heartbeat(
            deps, sid,
            _heartbeat(None, deps, "unassigned",
                       target_fs=cfg.get("target_fs"),
                       tele_on=tele_on, stream_on=stream_on,
                       observation=_not_active_observation(
                           tele_on, time.time())),
            instruction_attestation)
        if task16:
            heartbeat_date = getattr(
                deps.catalog, "response_authenticated_date", None)
            _record_heartbeat_hint(state, hb_resp, heartbeat_date)
        return "no-assignment"

    ticks = []
    statuses = []
    for idx, img_id in enumerate(ids):
        tick = _ImageTick(tick_seconds)
        ticks.append(tick)
        # The FIRST image of the set carries the legacy top-level "image_id"
        # pointer; _stage_image writes it where the single-image agent did,
        # after that image's own catalog and filename checks pass.
        #
        # One image's failure is that image's verdict, never the tick's: the
        # set heartbeat below must still go out so the device registers and
        # the Console shows the error (#235, _contained_stage_failure).
        try:
            status = _stage_image(cfg, deps, state, img_id, tele_on,
                                  stream_on, tick,
                                  legacy_pointer=(idx == 0),
                                  plan_row=plan_rows.get(img_id),
                                  instruction_attestation=
                                  instruction_attestation)
        except Exception as exc:
            status = _contained_stage_failure(
                cfg, deps, state, img_id, tick, tele_on, stream_on, exc)
        statuses.append(status)

    # ONE heartbeat for the whole set (the device is one row on the server),
    # then each image's telemetry replayed against the answer it carried.
    hb_resp = _send_set_heartbeat(
        deps, sid, state, ids, ticks, instruction_attestation)
    if task16:
        heartbeat_date = getattr(
            deps.catalog, "response_authenticated_date", None)
        _record_heartbeat_hint(state, hb_resp, heartbeat_date)
    for tick in ticks:
        tick.replay(hb_resp)

    # A one-image set returns EXACTLY the string the single-image agent did —
    # bootstrap logs and tests key off that vocabulary. A real set reports
    # every image's status, in the order the server assigned them.
    if len(ids) == 1:
        return statuses[0]
    return "multi:" + ",".join(statuses)


# ---- catalog TLS context selection (#12: FAIL CLOSED on an unpinned CA) ----
# Pure + unit-tested (test_catalog_tls.py) so the verify/refuse branch is
# covered off-box even though build_deps itself is `# pragma: no cover`.

class CatalogTLSConfigError(Exception):
    """Raised by make_catalog_context() when catalog_ca is unset or its file
    is missing. Never caught to fall back to an unverified connection: the
    previous "verify-if-present" behavior silently downgraded to
    ssl._create_unverified_context() (no chain or hostname validation at all)
    whenever a dropped conf happened to omit catalog_ca -- a real
    MITM-exploitable TLS downgrade on the device's control-plane channel,
    logged only by a single warn() call nobody was watching for. Every
    platform entrypoint bakes/synthesizes a real catalog_ca on first boot, so
    a device that raises this has a genuine misconfiguration, not a
    legitimate legacy state."""


def make_catalog_context(cfg, error):
    """Return the ssl.SSLContext for the catalog connection.

    FAIL CLOSED (security fix; replaces the old "verify-if-present", spec
    §4.6 back-compat fallback):
      * catalog_ca set AND the file exists -> a VERIFYING context
        (ssl.create_default_context(cafile=...) does full chain + hostname/IP-SAN
        validation; catalog_url uses the SAN IP so the match succeeds);
      * otherwise -> call error(msg) once, then raise CatalogTLSConfigError.
        The connection attempt fails outright -- an operator sees a device
        that cannot reach the catalog, never one silently exposed over an
        unverified TLS connection. This function must NEVER return
        ssl._create_unverified_context().
    `error` is the agent's syslog emit (injected so this is testable off-box)."""
    import os
    import ssl
    ca = cfg.get("catalog_ca")
    if ca and os.path.exists(ca):
        return ssl.create_default_context(cafile=ca)
    msg = ("catalog_ca is not set; refusing an unverified TLS connection - "
           "set catalog_ca in the agent conf")
    error(msg)
    raise CatalogTLSConfigError(msg)


class TrackerAuthConfigError(OSError):
    """The per-device tracker bearer is unavailable or unsafe."""


def _tracker_headers(cfg, conf_path=None):
    """Return aria2's per-download Bearer header without exposing the token.

    The first-boot refresh writes announce_token before image work. Since the
    dependency closures were built from the pre-refresh dict, re-read that
    atomic config here. JSON-RPC carries the value over loopback; it never
    appears in aria2's process arguments.
    """
    current = cfg
    if conf_path:
        try:
            current = agent_config.load(conf_path)
        except (OSError, KeyError, ValueError):
            current = cfg
    token = current.get("announce_token")
    try:
        token = agent_config.validate_bearer_token(
            "announce_token", token, allow_empty=False)
    except ValueError as exc:
        raise TrackerAuthConfigError("invalid tracker authorization") from exc
    if not token:
        raise TrackerAuthConfigError("tracker authorization is unavailable")
    # aria2's JSON-RPC schema represents repeatable --header options as an
    # array. Do not log or interpolate this value anywhere else.
    return ["Authorization: Bearer " + token]


def _aria_torrent_options(cfg, dest_dir, conf_path=None,
                          require_tracker_bearer=False):
    """Build addTorrent options from the current verified private context."""
    import instr
    defaults = getattr(instr.torrent_option_context(), "defaults", None)
    names = tuple(option for option, _public in _ARIA_LIVE_OPTIONS)
    if (not isinstance(defaults, dict) or set(defaults) != set(names)
            or any(not isinstance(defaults.get(name), str)
                   for name in names)):
        defaults = {
            "bt-max-peers": str(_FIXED_QOS["max_peers"]),
            "max-upload-limit": str(_FIXED_QOS["leech_up_bps"]),
            "max-download-limit": str(_FIXED_QOS["leech_down_bps"]),
            "bt-request-peer-speed-limit": str(
                _FIXED_QOS["request_peer_speed_limit_bps"]),
        }
    options = {"dir": dest_dir, "bt-seed-unverified": "true"}
    options.update({name: defaults[name] for name in names})
    if require_tracker_bearer:
        options["header"] = _tracker_headers(cfg, conf_path)
    return options


# ---- Phase 2: catalog token self-refresh (half-life, stdlib only) ----
# Pure + unit-tested so the before/at/after-half-life branches are covered
# off-box; the run_once refresh step below wires it to the real CatalogClient.

# Agent-side mirror of the server knobs (IRIS_TOKEN_TTL / IRIS_TOKEN_REFRESH_AT)
# used only to decide WHEN to refresh; the server's returned expires_at is always
# authoritative for the actual expiry written to the conf.
# These env vars mirror the server's knobs so refresh timing stays aligned across
# deployments. In Guest Shell (env unset) they default to the production
# 7-day / half-life config.
_TOKEN_TTL = int(os.environ.get("IRIS_TOKEN_TTL", "604800"))
_TOKEN_REFRESH_AT = float(os.environ.get("IRIS_TOKEN_REFRESH_AT", "0.5"))


def needs_refresh(now, expires_at, ttl, refresh_at):
    """True once the catalog token has passed its half-life (or expiry is
    unknown). PURE — no clock/global reads.

      expires_at == 0  -> True  (enrolled-but-never-refreshed: refresh next tick)
      else             -> now >= expires_at - ttl*(1-refresh_at)

    With ttl=604800 (7d) + refresh_at=0.5 the window opens at expires_at-302400,
    leaving a ~3.5-day retry buffer before the token actually expires (so a few
    failed best-effort refreshes never strand the device)."""
    if expires_at == 0:
        return True
    return now >= expires_at - ttl * (1 - refresh_at)


def _refresh_impl(cfg, conf_path, catalog, emit_fn):
    """Refresh the catalog token, re-point the live client, persist the bag.

    1. POST token-refresh (catalog.refresh_token) -> {catalog_token,
       expires_at, announce_token, rpc_secret}.
    2. Re-point catalog.token at the new bearer IMMEDIATELY: the server
       rotates on the POST, and heartbeat/telemetry reject the rolled token
       even inside the overlap window. token-refresh alone can reissue the
       current bag to recover a lost response or failed conf write, but the
       rest of THIS tick — the heartbeat is its last step — must authenticate
       with the new token; leaving the client on the old one ends every refresh
       tick in a spurious HTTP 401 heartbeat.
    3. Merge into a copy of cfg, atomically rewrite conf_path, return the
       reloaded cfg.

    Best-effort: ANY failure (network, write) logs TOKEN-REFRESH-FAIL and
    returns None so the caller proceeds on the current in-memory cfg. On the
    POST-failure path the on-disk conf is never touched (no partial write)
    and the client keeps its current bearer. On a conf-WRITE failure the
    client still keeps the NEW bearer — the server has already rotated, so
    the new token is the only one the device-bound routes will accept for
    the rest of this process; the stale on-disk conf is the next process's
    problem for the next tick, which can now recover the current bag using the
    previous token until that token's original expiry.
    Module-level + injected client/emit so it's unit-testable; build_deps
    passes the real CatalogClient + emit."""
    sid = cfg["device_id"]
    refresh_token_fn = catalog.refresh_token  # attr lookup outside the try:
    # a mis-wired catalog (e.g. a bare callable) must fail loud, not be
    # swallowed into a best-effort TOKEN-REFRESH-FAIL every tick.
    try:
        bag = refresh_token_fn(sid)
        # A 200 whose body lacks the bag is a server-shape skew, not a
        # rotation: it belongs in the same best-effort branch as a failed
        # POST. Read outside the try it escaped run_once as a KeyError before
        # any catalog work, silencing the device on every tick. Nothing
        # secret reaches the emit: the token is never formatted, only tested.
        if not isinstance(bag, dict):
            raise ValueError("token-refresh body is not an object")
        token = bag["catalog_token"]
        expires_at = bag["expires_at"]
        if not isinstance(token, str) or not token:
            raise ValueError("token-refresh body has no usable catalog_token")
        int(float(expires_at))
    except Exception as e:
        emit_fn("TOKEN-REFRESH-FAIL", "%s refresh POST failed: %s" % (sid, e))
        return None
    catalog.token = token
    new_cfg = dict(cfg)
    new_cfg["catalog_token"] = token
    new_cfg["token_expires_at"] = str(expires_at)
    # announce_token + rpc_secret are returned as-is (not rotated here); persist
    # them so aria2's NEXT launch picks them up.
    if bag.get("announce_token") is not None:
        new_cfg["announce_token"] = bag["announce_token"]
    if bag.get("rpc_secret") is not None:
        new_cfg["rpc_secret"] = bag["rpc_secret"]
    try:
        # Instruction-key validation is an independent subtransaction. The
        # config helper returns a fresh mapping, retains the complete old pair
        # on malformed input, and deliberately never consumes a server lkg_key.
        new_cfg = agent_config.merge_instruction_key_refresh(new_cfg, bag)
        agent_config.write_conf(conf_path, new_cfg)
    except Exception as e:
        emit_fn("TOKEN-REFRESH-FAIL", "%s conf rewrite failed: %s" % (sid, e))
        return None
    emit_fn("TOKEN-REFRESH",
            "catalog token refreshed (expires_at=%s)" % bag["expires_at"])
    return new_cfg


def _emit_impl(cli_execute_fn, mnemonic, msg):
    """Emit an IOS syslog line, best-effort. ASCII-only: the Guest Shell cli
    module logs every command to an ascii-encoded file and crashes on non-ascii
    (e.g. an em-dash); double-quotes are downgraded to single. NEVER raises — a
    failed log emit (e.g. the container's SSH-to-self transport momentarily
    down) must not abort the tick or mask the error it was reporting."""
    msg = msg.replace('"', "'").encode("ascii", "replace").decode()
    try:
        cli_execute_fn('send log facility IRIS severity 6 mnemonic %s "%s"'
                       % (mnemonic, msg))
    except Exception:
        pass


# ---- telemetry sampling (#13): aria2 stats/peers snapshots. Module-level with
# an injected `rpc` callable (the _refresh_impl pattern) so the gid matching
# and the never-raise contract are unit-testable off-box; build_deps wires the
# real _rpc closure. BEST-EFFORT by design: telemetry is decoration, so an
# aria2 hiccup (daemon bouncing on rpc_secret rotation, stopped download,
# malformed row) returns None/[] — a raise out of the sampling tick would
# discard persisted state and force a ~1.2 GB re-copy. ----


def _aria_add_result(body):
    """Require addTorrent's GID before recording a live transfer or migration.

    JSON-RPC failures use HTTP 200 too. Never include their arbitrary message
    in an exception: aria2 may echo a credential-bearing option or URL.
    """
    try:
        response = json.loads(body)
        if not isinstance(response, dict) or "error" in response:
            raise ValueError
        gid = response.get("result")
        if not isinstance(gid, str) or not gid:
            raise ValueError
    except (ValueError, TypeError, UnicodeError):
        raise RuntimeError("aria2 addTorrent did not return a download GID") from None
    return gid


def _aria_downloads(rpc):
    """Yield (gid, file-basenames) for every download aria2 knows about —
    active first (live download / seed), then queued, then finished. The ONE
    iteration idiom shared by gid lookup, purge_others, and aria_remove (they
    had drifted into three near-identical copies, one of which skipped the
    queued view its own docstring claimed to check). Per-call failures are
    swallowed so one unavailable view doesn't hide the others."""
    for call, extra in (("aria2.tellActive", []),
                        ("aria2.tellWaiting", [0, 100]),
                        ("aria2.tellStopped", [0, 100])):
        try:
            downloads = rpc(call, extra + [["gid", "files"]])
        except Exception:
            continue
        for d in downloads:
            yield d.get("gid"), [os.path.basename(f.get("path", ""))
                                 for f in d.get("files", [])]


def _aria_drop(rpc, gid):
    """Remove a download AND its stopped-result entry, both best-effort —
    aria2 refuses a duplicate info_hash while either survives."""
    for method in ("aria2.forceRemove", "aria2.removeDownloadResult"):
        try:
            rpc(method, [gid])
        except Exception:
            pass


def _find_aria_gid(rpc, stage_path):
    """Locate the aria2 gid whose download owns the staged file at stage_path.
    Basename match against each download's files paths. Returns the gid
    string or None when no download matches (including on rpc failure)."""
    fname = os.path.basename(stage_path)
    for gid, names in _aria_downloads(rpc):
        if fname in names:
            return gid
    return None


def _take_peer_transfer_sidecar(path):
    """Read AND remove the hook's peer-transfer snapshot at `path`; returns the
    raw bytes, or None when there is nothing usable there. NEVER raises.

    Removal is unconditional, including when the document turns out to be
    garbage: this agent is one-shot, so a snapshot that cannot be used now
    never becomes usable later, and a leftover file keyed by staged FILENAME
    would be a candidate for folding into the next transfer of the same image.
    Bounded by PEER_TRANSFER_MAX_BYTES — the hook writes a few hundred bytes per
    peer, so anything larger is not a snapshot and is not worth reading into a
    CPU-capped Guest Shell."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return None                 # absent is the ordinary case: no hook ran
    raw = None
    try:
        if size <= telemetry_report.PEER_TRANSFER_MAX_BYTES:
            with open(path, "rb") as f:
                raw = f.read(telemetry_report.PEER_TRANSFER_MAX_BYTES)
    except OSError:
        raw = None
    try:
        os.remove(path)
    except OSError:
        pass
    return raw


def _discard_peer_transfer_records(stage_path):
    """Drop any snapshot left next to `stage_path` before a NEW download of the
    same image starts. The sidecar is keyed by staged filename, so this is what
    keeps a previous transfer's transfer records from ever being in a position to be
    attributed to this one (telemetry_report.fold_peer_transfer_records' started_ts
    check is the second, independent line of defence). Never raises."""
    try:
        os.remove(telemetry_report.peer_transfer_sidecar_path(stage_path))
    except OSError:
        pass


def _ingest_peer_transfer_records(deps, tele, stage_path, now):
    """Fold the hook's exact per-peer byte snapshot into `tele`, then delete it.

    Called once per transfer, at the completion tick, BEFORE done_ts freezes
    the terminal report — the hook fired minutes earlier (aria2 invoked it, not
    EEM), which is the whole point: nothing of ours lives between one-shot
    ticks, so the measurement had to be taken by the process that was there.
    Best-effort in every direction: an absent snapshot is the ordinary outcome
    for a device with no hook wired, and a broken hook is SILENT by design
    (daemon-mode stderr is /dev/null), so this must never be able to fail a
    tick. Returns True only when a snapshot was accepted."""
    try:
        raw = _take_peer_transfer_sidecar(
            telemetry_report.peer_transfer_sidecar_path(stage_path))
        if raw is None:
            return False
        block = telemetry_report.parse_peer_transfer_snapshot(raw)
        if not telemetry_report.fold_peer_transfer_records(tele, block, now):
            return False
        deps.emit("TELEMETRY",
                  "peer transfer records: %d peers, %d bytes from peers (measured)"
                  % (block.get("rows_total", 0),
                     block.get("bytes_from_all_senders_total", 0)))
        return True
    except Exception:
        return False


def _aria_session_impl(rpc):
    """aria2 session id (`aria2.getSessionInfo`) — the counter-epoch marker so a
    session change re-baselines rather than bridges a counter decrease (spec §2).
    Returns the sessionId string, or None on any error / missing field. NEVER
    raises."""
    try:
        info = rpc("aria2.getSessionInfo", [])
        if isinstance(info, dict):
            sid = info.get("sessionId")
            if sid:
                return str(sid)
    except Exception:
        pass
    return None


def _aria_stats_impl(rpc, stage_path):
    """Snapshot aria2 transfer stats for the staged file: the tellStatus subset
    the telemetry report needs (gid, completedLength, totalLength,
    downloadSpeed, uploadSpeed, connections — all values aria2 strings).
    Returns the dict, or None on no matching download / ANY error. NEVER
    raises."""
    try:
        gid = _find_aria_gid(rpc, stage_path)
        if gid is None:
            return None
        status = rpc("aria2.tellStatus",
                      [gid, ["gid", "completedLength", "totalLength",
                             "downloadSpeed", "uploadSpeed", "connections",
                             "status"]])
        # _rpc defaults a missing "result" to [] — never leak a non-dict out.
        return status if isinstance(status, dict) else None
    except Exception:
        return None


def _aria_peers_impl(rpc, stage_path):
    """Measured peer rows for the staged download, or [] on any RPC error.

    Rates are instantaneous aria2 measurements, so absent/malformed values are
    omitted rather than represented as a measured zero. Terminal participation
    remains independently IP/timestamp/count-only in observe_peers()."""
    try:
        gid = _find_aria_gid(rpc, stage_path)
        if gid is None:
            return []
        raw_rows = rpc("aria2.getPeers", [
            gid, ["ip", "port", "downloadSpeed", "uploadSpeed", "peerClientName",
                  "progress"]])
        if not isinstance(raw_rows, list):
            return []
        rows = []
        for peer in raw_rows:
            if not isinstance(peer, dict):
                continue
            ip = peer.get("ip")
            if not isinstance(ip, str) or not ip or len(ip) > 64:
                continue
            row = {"ip": ip}
            port = _optional_bounded_int(peer.get("port"), 65535)
            if port is not None and port > 0:
                row["port"] = port
            receive = _optional_bounded_int(peer.get("downloadSpeed"), 10 ** 12)
            send = _optional_bounded_int(peer.get("uploadSpeed"), 10 ** 12)
            if receive is not None:
                row["receive_bps"] = receive
            if send is not None:
                row["send_bps"] = send
            name = peer.get("peerClientName")
            if isinstance(name, str) and name:
                row["peer_client_name"] = name[:64]
            progress = _optional_progress(peer.get("progress"))
            if progress is not None:
                row["progress"] = progress
            rows.append(row)
        return rows
    except Exception:
        return []


def _optional_bounded_int(value, cap):
    """Coerce aria2's decimal-string counters, rejecting unknown values."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        out = int(value)
    except (TypeError, ValueError):
        return None
    if not 0 <= out <= cap:
        return None
    return out


def _optional_progress(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) and 0 <= out <= 100 else None


# ---- agent-side root-copy re-verification (module-level so it's unit-testable
# with injected cli_execute / sha256 callables; build_deps below wires it up
# with the real on-box implementations) ----

_DIR_ROW_RE_TMPL = r"(?m)^\s*\d+\s+[^d\s]\S*\s+(\d+)\s+.*\s%s\s*$"


def _dir_size_of(dir_out, fname):
    """Byte size of *fname* from IOS `dir` output, or None when the row is
    absent, unparseable, or a directory row. Anchored to the row END so
    cat9k.bin never reads cat9k.bin.backup's size. The permissions column is
    matched as any non-directory token ([^d\\s]\\S*) rather than a bare \\S+,
    so a same-named directory (row starts with `d...`) is never mistaken for
    a file — IOS file rows carry `-rw-`-style tokens, sometimes with a
    trailing `.` (e.g. `-rw-rw-r--.`)."""
    if not dir_out:
        return None
    m = re.search(_DIR_ROW_RE_TMPL % re.escape(fname), dir_out)
    return int(m.group(1)) if m else None


def _ios_root_file_size(fname, prefix, cli_execute_fn):
    """Strict native size: only explicit IOS ENOENT proves absence."""
    if (prefix not in _IOS_ROOT_PREFIXES
            or not isinstance(fname, str) or not _FILENAME_RE.fullmatch(fname)):
        raise ValueError("invalid IOS root path")
    path = prefix + fname
    output = cli_execute_fn("dir " + path)
    if not isinstance(output, str):
        raise ValueError("IOS root directory response unavailable")
    # IOS may spell the same root path with a slash after the colon.
    missing = r"%%Error opening %s/?%s \(No such file or directory\)" % (
        re.escape(prefix), re.escape(fname))
    if re.search(r"(?m)^" + missing + r"\s*$", output) and _dir_size_of(output, fname) is None:
        return None
    if "%Error" in output or "% Invalid" in output:
        raise ValueError("IOS root directory read failed")
    size = _dir_size_of(output, fname)
    if size is None:
        raise ValueError("IOS root directory response is ambiguous")
    return size


def _parse_ios_sha512(output, root_path):
    """Accept one native hash bound to the exact requested IOS filename."""
    pattern = r"(?m)^verify /sha512 \(%s\) = ([0-9a-fA-F]{128})\s*$" % re.escape(root_path)
    hashes = re.findall(pattern, output)
    if (len(hashes) != 1 or output.count("verify /sha512") != 1
            or "%Error" in output or "% Invalid" in output):
        raise ValueError("IOS SHA-512 response is missing or ambiguous")
    return hashes[0].lower()


def _verify_iox_root(fname, prefix, digest, cli_execute_fn):
    """Read-only native IOS SHA-512 of `<prefix><fname>`, run DIRECTLY on the
    IOx agent's SSH-to-self vty.

    The Guest Shell needs the asynchronous IRIS-ROOT-HASH EEM policy
    (_verify_guestshell_root) only because its synchronous `cli` module hangs
    on long-running commands. The IOx transport is a real vty session with a
    900 s execution budget (cli_ssh.SSHCli), which runs `verify /sha512` to
    completion like any other command — measured at 26 s for a 459 MB image
    on an IE-3400-8T2S. `verify` reads the file and prints one digest line;
    no image is copied, deleted or modified. Returns True only when the ONE
    digest IOS bound to exactly this path equals the catalog's; raises on
    any other response (_parse_ios_sha512), which the adoption caller turns
    into a "blocked" verdict rather than a guess."""
    root_path = _iox_root_ios_path(prefix, fname)
    if root_path is None or not isinstance(digest, str) or not re.fullmatch(
            r"[0-9a-fA-F]{128}", digest):
        raise ValueError("invalid native root hash request")
    output = cli_execute_fn("verify /sha512 %s" % root_path)
    if not isinstance(output, str):
        raise ValueError("IOS SHA-512 response unavailable")
    return _parse_ios_sha512(output, root_path) == digest.lower()


def _verify_guestshell_root(fname, prefix, digest, stage_dir,
                           cli_configure_fn, sleep_fn=None,
                           poll_attempts=125, poll_interval_s=5):
    """Read-only IOS SHA in a bounded asynchronous EEM policy.

    Native verify must never run in Guest Shell's synchronous CLI session:
    long native commands can hang that transport. A one-shot countdown runs
    on EEM with a 600-second maxrun. The agent polls only its fresh private
    share directory, and requires a completion receipt written AFTER IOS
    finishes and closes the hash output. No image is copied or modified.
    """
    root_path = _guestshell_root_ios_path(stage_dir, prefix, fname)
    if root_path is None or not isinstance(digest, str) or not re.fullmatch(
            r"[0-9a-fA-F]{128}", digest):
        raise ValueError("invalid native root hash request")
    import fcntl
    # main() already serializes ticks. Keep a dedicated lock and durable lease
    # too: after a killed agent, the native EEM job may still be hashing. A
    # launch whose CLI result was lost has no safe inferred completion time.
    lock_path = os.path.join(stage_dir, ".iris-root-hash.lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another IOS root hash is running") from None
        lease_path = os.path.join(stage_dir, ".iris-root-hash.json")
        try:
            with open(lease_path) as stream:
                lease = json.load(stream)
        except FileNotFoundError:
            lease = {}
        if not isinstance(lease, dict):
            raise ValueError("IOS root hash lease is unreadable")
        if lease:
            expiry = lease.get("expires")
            if not isinstance(expiry, (int, float)) or not math.isfinite(expiry):
                raise RuntimeError("previous IOS root hash launch is unconfirmed; "
                                   "operator must inspect its EEM policy")
            if time.time() < expiry:
                raise RuntimeError("previous IOS root hash may still be running")
        return _run_guestshell_root_hash(
            root_path, prefix, digest, stage_dir, lease_path, cli_configure_fn,
            sleep_fn, poll_attempts, poll_interval_s)


def _run_guestshell_root_hash(root_path, prefix, digest, stage_dir, lease_path,
                             cli_configure_fn, sleep_fn, poll_attempts,
                             poll_interval_s):
    sleep = time.sleep if sleep_fn is None else sleep_fn
    directory = tempfile.mkdtemp(prefix=".iris-root-hash-", dir=stage_dir)
    receipt_dir = prefix + "guest-share/iris/" + os.path.basename(directory)
    result_path = os.path.join(directory, "result")
    done_path = os.path.join(directory, "done")
    finished = False
    lease = {"path": root_path, "sha512": digest.lower(), "expires": None}
    try:
        _atomic_write_state(lease_path, lease)
        cli_configure_fn([
            "no event manager applet IRIS-ROOT-HASH",
            "event manager applet IRIS-ROOT-HASH authorization bypass",
            "event timer countdown time 2 maxrun 600",
            'action 010 cli command "enable"',
            'action 020 cli command "verify /sha512 %s"' % root_path,
            'action 030 file open result %s/result w' % receipt_dir,
            'action 040 file write result "$_cli_result"',
            'action 050 file close result',
            'action 060 file open done %s/done w' % receipt_dir,
            'action 070 file write done "complete"',
            'action 080 file close done',
        ])
        # Start the crash-recovery budget after configuration returns, never
        # before a possibly slow launch. Unknown launch errors retain None.
        lease["expires"] = time.time() + 625
        _atomic_write_state(lease_path, lease)
        for _ in range(poll_attempts):
            try:
                with open(done_path) as stream:
                    complete = stream.read(11) in (
                        "complete", "complete\n", "complete\r\n")
            except FileNotFoundError:
                complete = False
            if complete:
                finished = True
                with open(result_path) as stream:
                    output = stream.read(262145)
                if len(output) > 262144:
                    raise ValueError("IOS SHA-512 response exceeds size limit")
                return _parse_ios_sha512(output, root_path) == digest.lower()
            sleep(poll_interval_s)
        raise TimeoutError("bounded IOS SHA-512 policy did not produce a receipt")
    finally:
        try:
            cli_configure_fn(["no event manager applet IRIS-ROOT-HASH"])
            if finished or (lease["expires"] is not None
                            and time.time() >= lease["expires"]):
                _atomic_write_state(lease_path, {})
        finally:
            # This unique directory contains only this call's hash receipts.
            shutil.rmtree(directory)


def _root_present_from_dir(dir_out, fname, expected_size=None):
    """Steady-state presence verdict for the placed root copy, from one `dir`
    read. Pure (module-level so it's unit-testable); build_deps.root_present
    wraps it with the CLI call.

    True unless IOS positively says the file is gone. When `expected_size` is
    given, a parsed size that DISAGREES is False — a partial file left by an
    interrupted transfer must not pass as "still there".

    A row that is present but whose size can't be parsed returns True, for the
    same reason build_deps.root_present returns True when the `dir` call itself
    raises: one flaky or unparseable tick must not trigger a full ~GB re-copy,
    and a real loss shows up as plain absence on the next tick."""
    if not dir_out:
        return False
    if "%Error" in dir_out or "No such file" in dir_out:
        return False
    if fname not in dir_out:
        return False
    if expected_size is None:
        return True
    observed = _dir_size_of(dir_out, fname)
    if observed is None:
        return True
    return observed == expected_size


def _agent_reverify_root(fname, target_prefix, cli_execute_fn, emit_fn,
                        poll_attempts=180, poll_interval_s=5.0,
                        sleep_fn=None, expected_size=None):
    """Bless the target-FS root copy by presence AND exact size, independent
    of however the file arrived at the target-FS root.

    The contract this function owns: `dir <FS><fname>` must report a byte
    count matching `expected_size` (the catalog's declared size for this
    image) before the copy is called good. Presence alone is not a
    verdict — a copy that dies mid-transfer can leave a PARTIAL file at the
    destination rather than nothing. When `expected_size` is None, callers
    get the old presence-only behaviour (used where the caller has no
    catalog size to check against).

    Whatever lands the file may still be in flight when this function polls:
    a row that's present but the WRONG size partway through the poll window
    just means the transfer is still running, so polling continues. Only a
    size mismatch that persists all the way to the end of the poll budget is
    treated as a failure. There's nothing extra to clean up here: it's on
    whatever re-fires the copy on the next tick to clear any stale partial
    before retrying.

    This function makes no claim about how the file got there or whether any
    signature was checked as part of landing it — it does not establish
    content integrity or authenticity. The agent already computed a sha256
    over the staged file before the copy ran, and authenticity of that
    staged content is a server-side, publish-time property (the catalog
    entry the sha256 was checked against). This poll only confirms presence
    and exact catalog byte size at the target-FS root.

    A row that IS present but whose size can't be parsed out of the `dir`
    output (an unexpected format) is handled exactly like a wrong size: keep
    polling, and if it persists to the end of the budget, fail — but say so
    truthfully. Claiming the copy "never appeared" when it plainly did would
    send an operator looking for the wrong fault.

    Polls `dir <FS><fname>` and returns bool:
      * file appears with the expected size (or, when expected_size is None,
        appears at all) -> emit ROOTCOPY, return True
      * a size mismatch, or a present-but-unreadable size, persists through the
        whole poll budget, or the file never appears at all -> emit
        ROOTCOPY-FAIL naming which of those it was, return False.

    Default poll budget (180 * 5 s ≈ 895 s) is sized to track a copy path's
    typical ~900 s execution budget, so a legitimately slow ~1.2 GB copy
    isn't abandoned a few minutes early."""
    if sleep_fn is None:
        sleep_fn = _SLEEP    # late-bound so tests' _SLEEP stub reaches the poll

    emit_fn("ROOTCOPY-VERIFYING", "%s awaiting root copy" % fname)
    last_size = None
    # Records the outcome of the LAST poll that actually saw the row, so the
    # failure message below describes what was observed rather than guessing.
    size_unreadable = False
    for i in range(poll_attempts):
        try:
            dir_out = cli_execute_fn("dir %s%s" % (target_prefix, fname))
        except Exception:
            dir_out = ""
        if dir_out and "%Error" not in dir_out and "No such file" not in dir_out \
                and fname in dir_out:
            if expected_size is None:
                emit_fn("ROOTCOPY", "%s placed at flash root" % fname)
                return True
            observed = _dir_size_of(dir_out, fname)
            if observed is None:
                # Present, but the row didn't parse. Treat it like a wrong
                # size — keep polling — rather than declaring the copy absent.
                size_unreadable = True
            else:
                size_unreadable = False
                last_size = observed
                if last_size == expected_size:
                    emit_fn("ROOTCOPY", "%s placed at flash root, size verified "
                            "(%d bytes)" % (fname, expected_size))
                    return True
            # present but wrong/unreadable size: may still be mid-copy — keep
            # polling.
        if i < poll_attempts - 1:
            sleep_fn(poll_interval_s)
    if size_unreadable:
        emit_fn("ROOTCOPY-FAIL",
                "%s root copy present but size unreadable from dir output; "
                "cannot confirm the catalog's %s bytes — treated as unplaced"
                % (fname, expected_size))
    elif last_size is not None:
        emit_fn("ROOTCOPY-FAIL", "%s root copy size mismatch: dir shows %d, "
                "catalog says %d — partial copy treated as absent"
                % (fname, last_size, expected_size))
    else:
        emit_fn("ROOTCOPY-FAIL",
                "%s root copy never appeared at flash root" % fname)
    return False


def _agent_reverify_rename(fname, target_prefix, cli_execute_fn, emit_fn,
                           poll_attempts=12, poll_interval_s=5.0,
                           sleep_fn=None, expected_size=None):
    """Bless Phase 2 (the `rename` that puts the proven temp copy in place) by
    proving the rename itself MOVED those bytes — not merely that something of
    the expected size now happens to sit at `<fname>`.

    Presence-and-size at `<fname>` alone cannot tell a genuine rename apart
    from one that silently no-ops onto a file already sitting there of the
    same size (scrubber #130): IOS-XE `rename` is not the only command this
    file has found to no-op silently on some platform/AAA combination rather
    than error (see the `delete` note at _reclaim_bundle_impl's docstring and
    the EEM `copy` no-op noted in _copy_to_root_direct_impl's), and a
    same-size collision at the destination is exactly the ordinary same-name
    replacement flow this whole crash-safety sequence exists for. The temp
    name (`_root_copy_tmp_name(fname)`) is reserved and IRIS's own — no other
    writer in this fleet is expected to name anything that way — so its
    disappearance is the one piece of evidence a stale pre-existing file at
    `<fname>` cannot forge.

    Success requires BOTH facts, observed together in the SAME poll
    iteration:
      * `dir <FS><fname>` reports the expected size — identical rules to
        _agent_reverify_root's single-name poll: present-but-unreadable or
        wrong-size just keeps polling; only a mismatch persisting the whole
        budget fails.
      * `dir <FS><tmp>` reports the temp name is GONE. A `dir` call that
        itself raises is NOT read as proof of absence — that would let one
        flaky read masquerade as a completed rename — it is treated exactly
        like "still there": keep polling, and count it against success at
        the end of the budget like any other unresolved fact.

    Default poll budget (12 * 5s = 60s) tracks the rename applet's own
    `event none maxrun 60` (see the IRIS-COPYROOT Phase 2 template) — a
    directory-entry update, not a copy, so it does not need
    _agent_reverify_root's ~900s budget sized for a real ~1.2 GB data
    transfer (scrubber #140; that function still owns Phase 1's poll, on its
    own default).

    Returns bool; emits ROOTCOPY-VERIFYING/ROOTCOPY/ROOTCOPY-FAIL like
    _agent_reverify_root, but a no-op rename gets its own honest message
    naming the temp file that survived, rather than a generic size mismatch —
    an operator chasing "cannot confirm the rename landed" and one chasing
    "the copy never reached full size" need different next steps."""
    if sleep_fn is None:
        sleep_fn = _SLEEP    # late-bound so tests' _SLEEP stub reaches the poll

    tmp = _root_copy_tmp_name(fname)
    emit_fn("ROOTCOPY-VERIFYING", "%s awaiting rename into place" % fname)
    last_size = None
    size_unreadable = False
    fname_ok = False
    tmp_gone = False
    for i in range(poll_attempts):
        try:
            dir_out = cli_execute_fn("dir %s%s" % (target_prefix, fname))
        except Exception:
            dir_out = ""
        fname_ok = False
        if dir_out and "%Error" not in dir_out and "No such file" not in dir_out \
                and fname in dir_out:
            if expected_size is None:
                fname_ok = True
                size_unreadable = False
            else:
                observed = _dir_size_of(dir_out, fname)
                if observed is None:
                    size_unreadable = True
                else:
                    size_unreadable = False
                    last_size = observed
                    fname_ok = (observed == expected_size)
        try:
            tmp_out = cli_execute_fn("dir %s%s" % (target_prefix, tmp))
        except Exception:
            tmp_out = None       # unreadable: NOT proof of absence, see docstring
        if tmp_out is None:
            tmp_gone = False
        else:
            tmp_gone = not (tmp_out and "%Error" not in tmp_out
                            and "No such file" not in tmp_out and tmp in tmp_out)
        if fname_ok and tmp_gone:
            if expected_size is None:
                emit_fn("ROOTCOPY",
                        "%s placed at flash root, rename confirmed" % fname)
            else:
                emit_fn("ROOTCOPY", "%s placed at flash root, size verified "
                        "(%d bytes), rename confirmed" % (fname, expected_size))
            return True
        if i < poll_attempts - 1:
            sleep_fn(poll_interval_s)
    if fname_ok and not tmp_gone:
        emit_fn("ROOTCOPY-FAIL",
                "%s rename did not land: %s%s is still present, so the file "
                "at %s%s cannot be confirmed as the bytes this attempt "
                "proved — treated as unplaced"
                % (fname, target_prefix, tmp, target_prefix, fname))
    elif size_unreadable:
        emit_fn("ROOTCOPY-FAIL",
                "%s root copy present but size unreadable from dir output; "
                "cannot confirm the catalog's %s bytes — treated as unplaced"
                % (fname, expected_size))
    elif last_size is not None:
        emit_fn("ROOTCOPY-FAIL", "%s root copy size mismatch: dir shows %d, "
                "catalog says %d — partial copy treated as absent"
                % (fname, last_size, expected_size))
    else:
        emit_fn("ROOTCOPY-FAIL",
                "%s root copy never appeared at flash root" % fname)
    return False


def _copy_to_root_impl(fname, target_prefix, cli_configure_fn, cli_execute_fn,
                       emit_fn, reverify_fn=_agent_reverify_root,
                       copy_source=None, running_image_fn=None,
                       expected_size=None, rename_reverify_fn=_agent_reverify_rename):
    """Copy the staged image to the target filesystem root under a RESERVED
    TEMP NAME, prove it, and only then rename it over the real name — so
    `<fname>` (whatever it holds now — an older copy, nothing, or the file
    the BOOT variable names) is never deleted ahead of a copy that might fail
    or lose power mid-transfer. Two IRIS-COPYROOT EEM applet runs do the
    privileged work inside native IOS (operator requirement + `authorization
    bypass` for AAA nodes), because the device's guestshell can't run `copy`
    or an overwriting `rename` directly (both prompt for confirmation, which
    hangs the guestshell `cli` module the same way an interactive `copy`
    does):

      Phase 1 — stage and prove, never touching `<fname>`:
        1. After confirming `<fname>` is not the running image, `delete
           /force <FS><fname>.iris-tmp` clears any stale leftover from an
           earlier interrupted attempt at the reserved temp name
           (_root_copy_tmp_name) — always safe, since that name is IRIS's own
           and can never be the running image or the BOOT target. Harmless if
           no such file exists (`file prompt quiet` suppresses the prompt).
        2. `copy <FS>/guest-share/iris/<fname> <FS><fname>.iris-tmp` — a plain
           copy, no in-band signature check, landing at the temp name.
        reverify_fn then polls the TEMP name for presence + exact catalog
        size. A False here means the real name was NEVER TOUCHED: the device
        is exactly as bootable as before this attempt started.

      Phase 2 — put the proven bytes in place (only reached once Phase 1's
        reverify has passed):
        3. `rename <FS><fname>.iris-tmp <FS><fname>` — a directory-entry
           update, not a data transfer (IOS accepts an existing destination
           the same way `copy` does, silently confirmed by `file prompt
           quiet`), so this is the only step that ever touches `<fname>`, and
           it is as short as this driver can make it — no separate delete of
           the old `<fname>` precedes it, so there is no client-orchestrated
           window where `<fname>` is definitely gone and the replacement is
           not yet in place. rename_reverify_fn then polls BOTH `<fname>`
           (presence + exact size) AND the temp name (must now be GONE) for
           the final verdict, regardless of whether the rename command
           itself raised (a raise here is ambiguous about whether IOS
           actually completed it, not evidence either way) — presence and
           size at `<fname>` alone cannot tell a genuine rename apart from
           one that silently no-ops onto a pre-existing file of the same
           size (scrubber #130); the temp name's disappearance is what the
           no-op case cannot forge.

    Each applet logs a NEUTRAL breadcrumb only — it makes no pass/fail claim.
    Phase 1's verdict belongs entirely to reverify_fn (_agent_reverify_root)
    and Phase 2's to rename_reverify_fn (_agent_reverify_rename) — see each
    one's docstring for its contract. Both phases reuse the SAME applet name
    (IRIS-COPYROOT, redefined between runs) so the uninstall scripts' existing
    `no event manager applet IRIS-COPYROOT` keeps covering it without
    changes.

    Module-level + injected callables so it's unit-testable. Returns True/False
    — or ROOT_COPY_NOT_ATTEMPTED when it gives up before any IOS command runs
    (either running-image refusal, or Phase 1's applet run raising before its
    delete-first can be assumed to have executed), because the caller's
    terminal reclaim must not treat those as "our partial is at the temp
    name".

    `copy_source` (optional) overrides the copy SOURCE. Default (None) is
    the Guest Shell scratch on the staging FS (`<FS>/guest-share/iris/<fname>`)
    — the C9300 path, unchanged. The IOx path SCP-pushes its local scratch to
    that same IOS-visible location before using the direct SSH copy helper. The
    destination is always the target-FS root (via the temp name, then a
    rename).

    `expected_size` is forwarded unchanged to reverify_fn (Phase 1) and
    rename_reverify_fn (Phase 2); None (the default) keeps the old
    presence-only behaviour for callers with no catalog size."""
    if running_image_fn is not None:
        running = running_image_fn()
        if not running:
            emit_fn("ROOTCOPY-REFUSED",
                    "%s running image unknown; refusing destructive replacement "
                    "(nothing was deleted — no IOS command ran)" % fname)
            return ROOT_COPY_NOT_ATTEMPTED
        if _ios_basename(running).casefold() == fname.casefold():
            emit_fn("ROOTCOPY-REFUSED",
                    "%s is the running image; refusing destructive replacement "
                    "(nothing was deleted — no IOS command ran)" % fname)
            return ROOT_COPY_NOT_ATTEMPTED
    src = (copy_source(fname, target_prefix) if copy_source
           else "%s/guest-share/iris/%s" % (target_prefix, fname))
    tmp = _root_copy_tmp_name(fname)
    cli_configure_fn([
        "no event manager applet IRIS-COPYROOT",
        "event manager applet IRIS-COPYROOT authorization bypass",
        "event none maxrun 900",
        'action 010 cli command "enable"',
        'action 020 cli command "delete /force %s%s"' % (target_prefix, tmp),
        'action 030 cli command "copy %s %s%s"' % (src, target_prefix, tmp),
        'action 040 syslog msg "ROOTCOPY-ATTEMPTED %s"' % fname,
    ])
    try:
        cli_execute_fn("event manager run IRIS-COPYROOT")
    except Exception as e:
        # The applet never fired (or we cannot tell that it did), so its
        # action 020 delete-first cannot be assumed to have run. Anything at
        # the temp name is therefore NOT provably our partial: report the
        # failure, but withhold the reclaim authorisation. `<fname>` itself
        # was never referenced by this applet at all.
        emit_fn("ROOTCOPY-FAIL",
                "%s applet run raised before any IOS work could be confirmed: "
                "%s" % (fname, e))
        return ROOT_COPY_NOT_ATTEMPTED
    if not reverify_fn(tmp, target_prefix, cli_execute_fn, emit_fn,
                       expected_size=expected_size):
        # The temp copy never proved good. `<fname>` — whatever it held
        # before this attempt, BOOT target or not — was never referenced by
        # any command above, so the device remains exactly as bootable as it
        # was before this attempt started.
        return False
    # Phase 2: the new bytes are proven present and exactly the right size,
    # still under the temp name. A second, short applet run puts them in
    # place with a single rename — see the docstring above for why this is
    # the smallest window this driver can make the replacement's exposure.
    cli_configure_fn([
        "no event manager applet IRIS-COPYROOT",
        "event manager applet IRIS-COPYROOT authorization bypass",
        "event none maxrun 60",
        'action 010 cli command "enable"',
        'action 020 cli command "rename %s%s %s%s"'
        % (target_prefix, tmp, target_prefix, fname),
        'action 030 syslog msg "ROOTCOPY-PLACED %s"' % fname,
    ])
    try:
        cli_execute_fn("event manager run IRIS-COPYROOT")
    except Exception as e:
        # Unlike Phase 1, a raise here is NOT treated as "nothing happened":
        # Phase 1 already proved good bytes exist at the temp name, so the
        # only open question is whether the rename itself landed.
        # rename_reverify_fn below is the actual verdict either way.
        emit_fn("ROOTCOPY-FAIL",
                "%s rename-into-place applet raised; the verified bytes at "
                "%s are unharmed either way, and the dir check below is the "
                "real verdict on whether the rename landed: %s"
                % (fname, tmp, e))
    return rename_reverify_fn(fname, target_prefix, cli_execute_fn, emit_fn,
                              expected_size=expected_size)


def _ios_rename_refusal(rename_out):
    """The `%Error renaming ...` line IOS printed for a `rename` it refused, or
    None. Only an explicit refusal in the command's own output counts — an
    empty output is the ordinary silent success, and a raise (None here) is
    ambiguous and stays with the dir-based verdict."""
    if not isinstance(rename_out, str):
        return None
    for line in rename_out.splitlines():
        if line.lstrip().startswith("%Error renaming"):
            return line.strip()
    return None


def _copy_to_root_direct_impl(fname, target_prefix, cli_execute_fn, emit_fn,
                              reverify_fn=_agent_reverify_root, copy_source=None,
                              delete_source_on_success=False,
                              running_image_fn=None, expected_size=None,
                              rename_reverify_fn=_agent_reverify_rename):
    """Copy the staged image to the target-FS root by running plain `copy`/
    `rename` commands DIRECTLY in the agent's IOS vty — no EEM applet. This is
    the container / SSH-to-self (IE-3x00) path.

    The IRIS-COPYROOT applet offload (see _copy_to_root_impl) exists ONLY because
    the C9300's Guest Shell `cli` module can't drive an interactive `copy`
    (it hangs). The IE-3x00 agent reaches IOS over a real SSH-to-self vty
    (identical to `lab/device-run.sh`), which runs `copy` to completion — and
    on that platform/IOS-XE the EEM `action cli command "copy …"` is a NO-OP
    (the applet completes in ~3 s reporting success but transfers nothing),
    so the applet path is both unnecessary and broken here.

    Same two-phase stage-then-place sequence _copy_to_root_impl uses, issued
    directly instead of through an EEM applet:

      Phase 1 — stage and prove, never touching `<fname>`:
        1. After confirming `<fname>` is not the running image, `delete
           /force <FS><fname>.iris-tmp` clears any stale leftover from an
           earlier interrupted attempt at the reserved temp name
           (_root_copy_tmp_name) — always safe, since that name is IRIS's own
           and can never be the running image or the BOOT target (`file
           prompt quiet` suppresses the confirmation prompt; harmless if
           absent).
        2. `copy <src> <FS><fname>.iris-tmp` — a plain copy, no in-band
           signature check, landing at the temp name. `copy` is synchronous,
           so the file is present the moment it returns (though possibly
           still short of its final size on a slow transfer).
        reverify_fn then polls the TEMP name for presence + exact catalog
        size. A False here means `<fname>` was NEVER TOUCHED by this attempt:
        the device is exactly as bootable as before this attempt started.

      Phase 2 — put the proven bytes in place (only reached once Phase 1's
        reverify has passed):
        3. `rename <FS><fname>.iris-tmp <FS><fname>` — a directory-entry
           update, not a data transfer (IOS accepts an existing destination
           the same way `copy` does, silently confirmed by `file prompt
           quiet`), so this is the only step that ever touches `<fname>`, and
           it is as short as this driver can make it — no separate delete of
           the old `<fname>` precedes it, so there is no window where
           `<fname>` is definitely gone and the replacement is not yet in
           place. rename_reverify_fn then polls BOTH `<fname>` (presence +
           exact size) AND the temp name (must now be GONE) for the final
           verdict, regardless of whether the rename command itself raised
           (a raise here is ambiguous about whether IOS actually completed
           it, not evidence either way) — presence and size at `<fname>`
           alone cannot tell a genuine rename apart from one that silently
           no-ops onto a pre-existing file of the same size (scrubber #130);
           the temp name's disappearance is what the no-op case cannot
           forge.

    Phase 1's verdict belongs entirely to reverify_fn (_agent_reverify_root)
    and Phase 2's to rename_reverify_fn (_agent_reverify_rename) — see each
    one's docstring for its contract (`expected_size` is forwarded unchanged
    to both). Keeps the success-log gating identical to the applet path and
    unit-testable. Returns True/False — or
    ROOT_COPY_NOT_ATTEMPTED when it gives up before Phase 1's delete-first
    completes (either running-image refusal, or the delete itself raising),
    because the caller's terminal reclaim must not treat those as "our
    partial is at the temp name". A `copy` that raises AFTER Phase 1's
    delete-first is a plain False: that leftover really is ours (at the temp
    name — `<fname>` itself is still untouched). `copy_source` overrides the
    SOURCE like _copy_to_root_impl."""
    if running_image_fn is not None:
        running = running_image_fn()
        if not running:
            emit_fn("ROOTCOPY-REFUSED",
                    "%s running image unknown; refusing destructive replacement "
                    "(nothing was deleted — no IOS command ran)" % fname)
            return ROOT_COPY_NOT_ATTEMPTED
        if _ios_basename(running).casefold() == fname.casefold():
            emit_fn("ROOTCOPY-REFUSED",
                    "%s is the running image; refusing destructive replacement "
                    "(nothing was deleted — no IOS command ran)" % fname)
            return ROOT_COPY_NOT_ATTEMPTED
    src = (copy_source(fname, target_prefix) if copy_source
           else "%s/guest-share/iris/%s" % (target_prefix, fname))
    tmp = _root_copy_tmp_name(fname)
    tmp_dst = "%s%s" % (target_prefix, tmp)
    dst = "%s%s" % (target_prefix, fname)
    try:
        cli_execute_fn("delete /force %s" % tmp_dst)
    except Exception as e:
        # The temp-name delete-first itself failed, so it was never cleared —
        # but `<fname>` was never referenced either way. Withhold reclaim
        # authorisation.
        emit_fn("ROOTCOPY-FAIL",
                "%s temp-name delete-first raised; no copy attempted: %s"
                % (fname, e))
        return ROOT_COPY_NOT_ATTEMPTED
    try:
        cli_execute_fn("copy %s %s" % (src, tmp_dst))
    except Exception as e:
        # delete-first DID run: whatever is at the temp name now is our own
        # partial, so a plain False (reclaim-authorising) is correct here.
        # `<fname>` itself is untouched either way.
        emit_fn("ROOTCOPY-FAIL", "%s copy to the temp name raised: %s"
                % (fname, e))
        return False
    if not reverify_fn(tmp, target_prefix, cli_execute_fn, emit_fn,
                       expected_size=expected_size):
        # The temp copy never proved good. `<fname>` — whatever it held
        # before this attempt, BOOT target or not — was never referenced by
        # any command above, so the device remains exactly as bootable as it
        # was before this attempt started.
        return False
    # Phase 2: the new bytes are proven present and exactly the right size,
    # still under the temp name. One rename puts them in place — see the
    # docstring above for why this is the smallest window this driver can
    # make the replacement's exposure.
    try:
        rename_out = cli_execute_fn("rename %s %s" % (tmp_dst, dst))
    except Exception as e:
        # Unlike the copy above, a raise here is NOT treated as "nothing
        # happened": Phase 1 already proved good bytes exist at the temp
        # name, so the only open question is whether the rename itself
        # landed. rename_reverify_fn below is the actual verdict either way.
        rename_out = None
        emit_fn("ROOTCOPY-FAIL",
                "%s rename into place raised; the verified bytes at %s are "
                "unharmed either way, and the dir check below is the real "
                "verdict on whether the rename landed: %s" % (fname, tmp, e))
    refused = _ios_rename_refusal(rename_out)
    if refused:
        # IOS answered the rename with an explicit refusal, so nothing moved:
        # `<fname>` still holds whatever it held, and the proven bytes are
        # still at the temp name. Observed verbatim on an IE-3400-8T2S
        # (IOS-XE 17.15.4, `file prompt quiet`) when the real name already
        # existed at the sdflash: root — this release's `rename` does not
        # overwrite an existing destination, quiet prompts or not:
        #   %Error renaming sdflash:<f>.iris-tmp to sdflash:<f> (File exists)
        # Polling the pair for 60 s would only re-derive the same verdict,
        # and its generic "cannot be confirmed" wording would send an operator
        # looking for a lost rename rather than at the file in the way. The
        # pre-copy adoption probe (_try_adopt_guestshell_root) is what keeps
        # a byte-identical existing file from reaching this point at all.
        emit_fn("ROOTCOPY-FAIL",
                "%s rename into place refused by IOS, so %s was left exactly "
                "as it was and the verified bytes remain at %s (this IOS "
                "release does not rename over an existing file): %s"
                % (fname, dst, tmp_dst, refused))
        return False
    ok = rename_reverify_fn(fname, target_prefix, cli_execute_fn, emit_fn,
                            expected_size=expected_size)
    # In container mode the scp-pushed guest-share scratch is a transfer
    # intermediary (the swarm seeds from the CAF-persistent stage_dir), so a
    # verified placement deletes it — otherwise a duplicate image doubles
    # steady-state target-FS usage. Kept on failure: the next tick re-runs
    # copy from it instead of re-pushing over the slow scp path.
    if ok and delete_source_on_success:
        try:
            cli_execute_fn("delete /force %s" % src)
        except Exception:
            pass
    return ok


def _reclaim_bundle_impl(target_prefix, names, cli_configure_fn, cli_execute_fn):
    """Delete image artifacts at the target-FS root via the one-shot
    IRIS-RECLAIM-BUNDLE authorization-bypass applet (AAA nodes silently no-op
    a raw exec `delete`). Callers own the never-delete-that guarantee: the
    bundle-mode download gate passes only names outside its protect set
    (running/staging/seeding image + IRIS's own root copy), the replaced-root
    cleanup passes only re-whitelisted IRIS-placed root copies, and the
    failed-placement reclaim (_reclaim_failed_root_copy) passes the single name
    an attempt's own delete-first had already cleared, and only after its own
    running-image check clears it.
    Fire-and-forget — callers that need proof re-check afterwards (the
    replaced-root cleanup verifies file presence; the download gate re-reads
    free space).

    Module-level + injected callables so it's unit-testable."""
    if not names:
        return
    actions = ['action 010 cli command "enable"']
    for i, n in enumerate(names, start=2):
        actions.append('action %03d cli command "delete /force %s%s"'
                       % (i * 10, target_prefix, n))
    cli_configure_fn([
        "no event manager applet IRIS-RECLAIM-BUNDLE",
        "event manager applet IRIS-RECLAIM-BUNDLE authorization bypass",
        "event none maxrun 120",
    ] + actions)
    cli_execute_fn("event manager run IRIS-RECLAIM-BUNDLE")


def _share_settings(cfg):
    """(share_dir, share_ios_path) for the C9k SSD share mount. The app-hosting
    run-opts set the environment (the normal path); conf keys are the fallback
    so a hand-dropped config can steer it too. Empty strings = no share."""
    return (os.environ.get("IRIS_SHARE_DIR") or cfg.get("share_dir") or "",
            os.environ.get("IRIS_SHARE_IOS_PATH")
            or cfg.get("share_ios_path") or "")


# IRIS stages at the share ROOT, never in a subdirectory: on the C9300 SSD
# share (ext4 + seclabel), a directory the container creates becomes
# inaccessible to the container itself once IOS-side file ops touch it
# (hardware-observed: even `ls` of the agent-created subdir returned EACCES
# for a uid-0 container shell, while 100 MB writes to the CAF-created share
# root ran at 1.5 GB/s). Isolation therefore comes from a NAME PREFIX: every
# file IRIS writes or sweeps here starts with "iris-", and operator/CAF files
# at the root are never touched. The final copy reads the fixed staged name
# and writes the REAL image name to the target FS — the staged name is
# cosmetic. Content was already verified by sha256 before staging; the agent
# attests this placement by exact byte size against the catalog. The swarm
# seeds from the CAF-persistent stage_dir copy, never from the share.
_SHARE_PREFIX = "iris-"
_SHARE_PROBE = "iris-probe.txt"
_SHARE_PROBE_BODY = "iris"      # the probe's exact bytes; `dir` must report len()
_SHARE_STAGE = "iris-staged.bin"


def _stage_via_share_impl(fname, stage_dir, share_dir, share_ios_path,
                          copy_direct_fn, emit_fn, cli_execute_fn):
    """Land the downloaded scratch in the bind-mounted app-hosting share
    (C9k: usbflash1:iox_host_data_share, mounted into the container via
    run-opts -v), then have IOS place it with an INTERNAL disk-to-disk plain
    `copy` — no scp, no control-plane punt path, no CoPP ceiling.

    Everything IRIS writes lives at the share root under the reserved `iris-`
    filename prefix, so the orphan sweep below can never touch operator files
    in the shared CAF directory. Each attempt sweeps only that prefix — a tick
    killed mid-transfer (re-onboard's app teardown, CAF
    restart, power loss) can strand a full-size image or .part there, and
    nothing else would ever reclaim the space.

    Before committing to the multi-GB copy, a tiny probe file is written and
    `dir`-checked THROUGH IOS: the bind mount proves only the container side,
    not that share_ios_path names this box's view of the same directory (a
    stacked C9300 can enumerate the SSD differently; an operator override can
    be wrong). An IOS-unreadable share must fall back to scp — without the
    probe it burned a full SSD write plus a ~15-minute reverify timeout per
    tick, wedging the device while the working fallback sat suppressed.

    Returns None when the share cannot be used (unconfigured, not mounted,
    probe failed, or the local copy failed) so the caller falls back to the
    scp push. Otherwise returns copy_direct_fn's bool verdict: an IOS-side
    placement failure AFTER a good probe is FINAL — scp would push the
    same bytes. The transient share copy is always removed (the swarm seeds
    from the scratch under stage_dir, not from the share)."""
    if not (share_dir and share_ios_path and os.path.isdir(share_dir)):
        return None

    def _sweep():
        # ONLY files carrying OUR prefix, at the share root — operator and
        # CAF files live at the same level and must never be touched
        try:
            for leftover in os.listdir(share_dir):
                if leftover.startswith(_SHARE_PREFIX):
                    try:
                        os.remove(os.path.join(share_dir, leftover))
                    except OSError:
                        pass
        except OSError:
            pass

    _sweep()
    probe = os.path.join(share_dir, _SHARE_PROBE)
    try:
        with open(probe, "w") as stream:
            stream.write(_SHARE_PROBE_BODY)
        listing = cli_execute_fn("dir %s/%s" % (share_ios_path, _SHARE_PROBE))
        # A parsed `dir` row of the probe's exact size — never a substring
        # test. IOS answers a missing file with `%Error opening
        # <path>/iris-probe.txt (No such file or directory)`, which ECHOES the
        # name and passed the old check: the multi-GB share copy then ran, the
        # IOS copy failed from an unreadable source, and the scp fallback
        # stayed suppressed — the exact wedge this probe exists to prevent.
        if (not listing or "%Error" in listing or "No such file" in listing
                or _dir_size_of(listing, _SHARE_PROBE) != len(_SHARE_PROBE_BODY)):
            raise OSError("IOS cannot read %s" % share_ios_path)
    except Exception as e:
        emit_fn("SHARE-FALLBACK",
                "%s share probe failed (%s); falling back to scp" % (fname, e))
        _sweep()
        return None
    local = os.path.join(stage_dir, fname)
    staged = os.path.join(share_dir, _SHARE_STAGE)
    part = os.path.join(share_dir, _SHARE_STAGE + ".part")
    try:
        # Chunked read/write (shutil.copyfile's sendfile fast path is
        # unreliable across this bind mount).
        with open(local, "rb") as src, open(part, "wb") as dst:
            shutil.copyfileobj(src, dst, length=1 << 20)
        os.replace(part, staged)
    except OSError as e:
        emit_fn("SHARE-FALLBACK",
                "%s share copy failed (%s); falling back to scp" % (fname, e))
        _sweep()
        return None
    try:
        # The final copy reads the fixed staged name and writes the REAL
        # image name to the target FS (the caller's dst) — the source name
        # is cosmetic; the agent attests placement afterward by exact byte
        # size against the catalog.
        return copy_direct_fn(
            lambda f, target_prefix: "%s/%s" % (share_ios_path, _SHARE_STAGE))
    finally:
        _sweep()


# ---- on-box wiring (not exercised by unit tests) ----

def _instruction_platform(platform, cfg):
    """Map the established launcher/storage profiles to the signed platform."""
    if platform == "iox":
        return "iox"
    if platform == "xr-appmgr" \
            or (not platform and (cfg.get("mode") or "").strip() == "xr"):
        return "xr-appmgr"
    if (not platform
            and cfg.get("stage_dir") == "/bootflash/guest-share/iris"
            and cfg.get("target_fs") == "bootflash:"):
        return "router"
    return "guestshell"


def _with_instruction_step(deps, cfg, conf_path, platform):  # pragma: no cover
    """Attach the contained instruction and loopback aria2 runtime."""
    # Preserve the established platform-dispatch seam: tests and downstream
    # wrappers may return an opaque sentinel from a substituted builder.  Only
    # the real dependency contract can safely receive runtime wiring.
    if (getattr(deps, "_fields", None) != Deps._fields
            or not callable(getattr(deps, "_replace", None))):
        return deps
    import instr

    runtime_platform = _instruction_platform(platform, cfg)
    paths = instr.paths_for(runtime_platform, cfg)
    verifier = instr.SSHVerifier(
        shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen",
        paths["signers"], paths["root_signers"], paths["work_dir"])
    current_boot_id = instr.boot_id()

    def instruction_step(cfg, state, hints, catalog_date, cache_only=False,
                         verification_attempts=None):
        return instr.run_instruction_step(
            cfg, state, deps.catalog, hints, catalog_date,
            runtime_platform, paths["work_dir"], current_boot_id,
            time.monotonic(), verifier,
            lambda updated: agent_config.write_conf(conf_path, updated),
            deps.emit, checkpoint=deps.checkpoint, cache_only=cache_only,
            verification_attempts=verification_attempts)

    endpoint = None
    secret = None
    try:
        port_text = str(cfg["rpc_port"])
        if not port_text.isdigit():
            raise ValueError
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError
        configured_secret = cfg.get("rpc_secret", "")
        if (not isinstance(configured_secret, str)
                or len(configured_secret) > 128):
            raise ValueError
        secret = agent_config.validate_single_line(
            "rpc_secret", configured_secret)
        if not secret:
            secret = "iris"
        endpoint = "http://127.0.0.1:%d/jsonrpc" % port
    except (KeyError, TypeError, ValueError):
        pass

    if endpoint is None:
        def aria_rpc(_method, _params):
            raise InstructionApplyError("RPC unavailable")
    else:
        def aria_rpc(method, params):
            if not isinstance(method, str) or not isinstance(params, list):
                raise InstructionApplyError("invalid RPC request")
            payload = json.dumps({
                "jsonrpc": "2.0", "id": "p", "method": method,
                "params": ["token:" + secret] + params,
            }, separators=(",", ":")).encode("ascii")
            request = urllib.request.Request(
                endpoint, data=payload,
                headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    raw = response.read(64 * 1024 + 1)
                if len(raw) > 64 * 1024:
                    raise InstructionApplyError("RPC response too large")
                decoded = json.loads(raw.decode("utf-8"))
                if (not isinstance(decoded, dict)
                        or set(decoded) != {"jsonrpc", "id", "result"}
                        or decoded.get("jsonrpc") != "2.0"
                        or decoded.get("id") != "p"):
                    raise InstructionApplyError("invalid RPC response")
                return decoded["result"]
            except InstructionApplyError:
                raise
            except Exception:
                # Never expose a JSON-RPC error body, credential-bearing URL or
                # transport exception text to callers, emits or heartbeats.
                raise InstructionApplyError("RPC unavailable") from None

    defaults = {}
    aria_add = deps.aria_add
    wrapper = _instruction_aria_add_protocol(aria_add)
    if wrapper is not None:
        aria_add = wrapper[1]()
    return deps._replace(
        instruction_step=instruction_step, aria_rpc=aria_rpc,
        torrent_defaults=defaults,
        aria_add=_InstructionAriaAdd(aria_add, defaults))


def build_deps(cfg, conf_path, state_path=None):  # pragma: no cover
    # One container selector owns both the backend and storage profile. An
    # absent selector is the established Guest Shell path; container
    # entrypoint.sh itself requires one and persists it before reaching here.
    platform = (os.environ.get("IRIS_DEVICE_PLATFORM")
                or cfg.get("device_platform") or "").strip()
    agent_config.validate_device_platform(platform)
    legacy_xr = (not platform and (cfg.get("mode") or "").strip() == "xr")
    if platform == "xr-appmgr" or legacy_xr:
        import xr_deps
        return _with_instruction_step(
            xr_deps.build_deps(cfg, conf_path, state_path),
            cfg, conf_path, platform)
    import base64
    import urllib.request
    import catalog_client

    # Guest Shell `cli` on the C9300 (default, unchanged) or SSH-to-self in the
    # IOx profile; cli_ssh.select_cli reads the same device-platform key. Bound
    # (and `emit` defined) BEFORE make_catalog_context below: its fail-closed
    # path calls the error callback SYNCHRONOUSLY, unlike copy_to_root/reclaim
    # further down whose closures over `emit`/`cli_execute` aren't invoked
    # until well after build_deps has returned. Calling make_catalog_context
    # first (as this used to) reached that callback before `emit` -- itself
    # relying on `cli_execute` -- had been assigned in this scope at all,
    # which is a NameError, not a warning: only ever missed because build_deps
    # is `# pragma: no cover` and the unit tests exercise make_catalog_context
    # directly (test_catalog_tls.py), bypassing this wiring entirely.
    import cli_ssh
    cli_execute, cli_configure = cli_ssh.select_cli(cfg)

    def emit(mnemonic, msg):
        _emit_impl(cli_execute, mnemonic, msg)

    ctx = make_catalog_context(cfg, lambda m: emit("TLS-ERROR", m))
    catalog = catalog_client.CatalogClient(
        cfg["catalog_url"], cfg["catalog_token"], context=ctx,
        tracker_bearer=(platform == "iox"))

    def refresh():
        # Thin wrapper — the POST + client rebind + atomic conf rewrite +
        # reload lives in the module-level _refresh_impl so it's unit-testable.
        # Pass the CLIENT, not a bound method: _refresh_impl re-points
        # catalog.token after the POST. Returns the reloaded cfg or None
        # (best-effort).
        return _refresh_impl(cfg, conf_path, catalog, emit)

    # IE3x00 IOx app: IOx can't bind-mount sdflash: into the container, and inbound
    # to the container is blocked, so the agent can't write the IOS-visible SD
    # directly. Instead it scp-PUSHES the downloaded scratch to sdflash:guest-share/
    # iris via the device's SCP server (container -> device, the proven direction —
    # same as the SSH-to-self CLI), then the SSH vty runs a plain
    # `copy sdflash:guest-share/iris/<img> sdflash:<img>` — byte-identical
    # to the C9300 flash:guest-share -> flash: flow. Guest Shell (C9300) writes its
    # scratch via the in-VM mount, so it pushes nothing here.
    _legacy_runtime = (os.environ.get("IRIS_RUNTIME_MODE")
                       or cfg.get("runtime_mode") or "guestshell")
    _container_iox = (platform == "iox"
                      or (not platform and _legacy_runtime == "container"))
    _transport = getattr(cli_execute, "__self__", None)   # SSHCli in container mode

    def _push_scratch(fname, target_prefix):
        # create the IOS-side scratch dir (idempotent; file prompt quiet => no
        # prompt) then scp the downloaded file into it so the placement copy
        # has a source IOS can read.
        for d in ("%sguest-share" % target_prefix,
                  "%sguest-share/iris" % target_prefix):
            try:
                cli_execute("mkdir %s" % d)
            except Exception:
                pass
        local = os.path.join(cfg["stage_dir"], fname)
        _transport.put(local, "%sguest-share/iris/%s" % (target_prefix, fname))

    def copy_to_root(fname, target_prefix="flash:", expected_size=None):
        # Thin wrapper — the actual flow lives in module-level impls so
        # behavioural tests can inject all callables and prove the success log
        # is gated by _agent_reverify_root's Phase 1 pass and
        # _agent_reverify_rename's Phase 2 pass. expected_size is forwarded
        # unchanged to whichever impl the platform branch below selects, and
        # from there to both functions' presence + exact-size contracts.
        running = running_image()
        if not running:
            emit("ROOTCOPY-REFUSED",
                 "%s running image unknown; refusing destructive replacement"
                 % fname)
            # Transient (SSH/parse glitch), not a copy failure — a plain False
            # here would feed the same copy_attempts counter as a real
            # failure and could dead-end the copy at copy_failed on nothing
            # but a few flaky `show version` reads. See
            # ROOT_COPY_RUNNING_IMAGE_UNKNOWN.
            return ROOT_COPY_RUNNING_IMAGE_UNKNOWN
        if _ios_basename(running).casefold() == fname.casefold():
            emit("ROOTCOPY-REFUSED",
                 "%s is the running image; refusing destructive replacement "
                 "(nothing was deleted — no IOS command ran)" % fname)
            # NOT plain False: this refusal happens before any IOS command, so
            # the delete-first never ran and the file at that name is the
            # RUNNING IMAGE. A False here would authorise the terminal reclaim
            # to delete it. Counts as an attempt all the same — see
            # ROOT_COPY_NOT_ATTEMPTED.
            return ROOT_COPY_NOT_ATTEMPTED
        # Freeze the confirmed value for this operation. Re-querying show version
        # after a 1.2 GB scratch transfer adds failure modes without improving the
        # basename safety decision made before any destructive command.
        confirmed_running = lambda: running
        if _container_iox and _transport is not None:
            # C9k container: the SSD share (usbflash1:iox_host_data_share) is
            # bind-mounted at IRIS_SHARE_DIR, so the scratch lands there at
            # disk speed and IOS places it with an internal disk-to-disk plain
            # `copy` — no scp, no CoPP-policed punt traffic. None =
            # share unusable -> fall through to the scp push below.
            share_dir, share_ios_path = _share_settings(cfg)
            if share_dir:
                shared = _stage_via_share_impl(
                    fname, cfg["stage_dir"], share_dir, share_ios_path,
                    lambda copy_source: _copy_to_root_direct_impl(
                        fname, target_prefix, cli_execute, emit,
                        copy_source=copy_source,
                        running_image_fn=confirmed_running,
                        expected_size=expected_size),
                    emit, cli_execute)
                if shared is not None:
                    return shared
            # IE-3x00 / container fallback: push the scratch onto the
            # IOS-visible SD, then run a plain `copy` DIRECTLY over the
            # SSH-to-self vty. The EEM applet offload is only needed for the
            # C9300 Guest Shell cli module (can't drive interactive copy); a
            # real vty runs copy fine, and the EEM `cli command "copy"` action
            # is a no-op on this platform — so the direct path is both correct
            # and necessary.
            try:
                _push_scratch(fname, target_prefix)
            except Exception as e:
                # Pure container-side transfer failure: no IOS command ran, so
                # no delete-first cleared the target name.
                emit("ROOTCOPY-FAIL",
                     "%s scp push to %s failed before any IOS work: %s"
                     % (fname, target_prefix, e))
                return ROOT_COPY_NOT_ATTEMPTED
            # NOTE: like the Guest Shell path, placement transiently needs
            # ~2x the image on the target FS (scratch + root copy); the
            # verified-delete below reclaims the scratch afterwards.
            return _copy_to_root_direct_impl(fname, target_prefix,
                                             cli_execute, emit,
                                             delete_source_on_success=True,
                                             running_image_fn=confirmed_running,
                                             expected_size=expected_size)
        return _copy_to_root_impl(fname, target_prefix,
                                  cli_configure, cli_execute, emit,
                                  running_image_fn=confirmed_running,
                                  expected_size=expected_size)

    def reclaim():
        # Free flash with `install remove inactive` — the ONLY automated reclaim
        # (we never delete image files). The catch: it is INTERACTIVE
        # ("Do you want to remove the above files? [y/n]") and the Guest Shell `cli`
        # module can't answer a raw prompt — so a plain `cli_execute` starts the op,
        # takes the install lock, and HANGS, wedging every later install attempt.
        # Fix: answer the prompt from inside a native EEM applet (cli `... pattern
        # "[y/n]"` then a "y"), driven by `event none` + `event manager run` — the
        # same idiom as IRIS-COPYROOT (syslog-trigger/$_arg1 proved unreliable on
        # 17.18; AAA nodes need `authorization bypass`). Stage-only: this reclaims
        # inactive packages only — it never install add/activate/commit or reload.
        # Defensive: if an install op is already running, don't stack onto it.
        # This pre-check catches the versions that DO advertise a running
        # operation in the summary. It is not sufficient on its own: a C9300
        # on 17.18.3 was observed refusing `install remove inactive` while
        # `show install summary` showed only committed packages and an
        # inactive auto-abort timer, so the refusal is caught again below,
        # where IOS actually reports it. Returns False, never None, so the
        # caller does not burn its once-guard on a skip.
        try:
            summ = cli_execute("show install summary")
            if "operation" in summ.lower() and "progress" in summ.lower():
                emit("RECLAIM", "install op already in progress; skipping reclaim")
                return False
        except Exception:
            pass
        cli_configure([
            "no event manager applet IRIS-RECLAIM",
            "event manager applet IRIS-RECLAIM authorization bypass",
            "event none maxrun 600",
            'action 010 cli command "enable"',
            'action 020 cli command "install remove inactive" pattern "[y/n]"',
            'action 030 cli command "y"',
        ])
        out = cli_execute("event manager run IRIS-RECLAIM")
        if install_reclaim_refused(out):
            # The device holds the install lock. Nothing was freed, and the
            # lock clears on its own, so report the no-op and let the next
            # tick try again rather than spending the image's one attempt.
            emit("RECLAIM", "install op already running; reclaim did not run")
            return False
        return True

    def boot_image():
        # Basename of the BOOT variable's target from `show boot` (read-only),
        # for the reclaim protect sets. "" when IOS reports no BOOT target;
        # None when the read itself failed (_show folds a raise into "", and a
        # real `show boot` is never empty), so callers refuse destructive work
        # rather than guess.
        sb = _show("show boot")
        if not sb.strip():
            return None
        path = flash_target.boot_path(sb)
        return _ios_basename(path) if path else ""

    def aria_add(torrent_path, dest_dir):
        rpc = "http://127.0.0.1:%s/jsonrpc" % cfg["rpc_port"]
        with open(torrent_path, "rb") as f:
            tb = base64.b64encode(f.read()).decode()
        params = ["token:" + cfg["rpc_secret"], tb, [],
                  _aria_torrent_options(
                      cfg, dest_dir, conf_path,
                      require_tracker_bearer=(platform == "iox"))]
        payload = json.dumps({"jsonrpc": "2.0", "id": "a",
                              "method": "aria2.addTorrent",
                              "params": params}).encode()
        req = urllib.request.Request(rpc, data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as response:
            return _aria_add_result(response.read())

    def _rpc(method, params):
        payload = json.dumps({"jsonrpc": "2.0", "id": "p", "method": method,
                              "params": ["token:" + cfg["rpc_secret"]] + params}
                             ).encode()
        req = urllib.request.Request(
            "http://127.0.0.1:%s/jsonrpc" % cfg["rpc_port"], data=payload,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode()).get("result", [])

    def aria_stats(stage_path):
        # Telemetry seam (#13) — thin wrapper over the module-level impl so
        # the gid matching + never-raise contract are unit-tested off-box.
        return _aria_stats_impl(_rpc, stage_path)

    def aria_peers(stage_path):
        return _aria_peers_impl(_rpc, stage_path)

    def aria_session():
        return _aria_session_impl(_rpc)

    def purge_others(keep_filenames, keep_ids):
        # Keep the WHOLE assigned SET, not one survivor: a device stages every
        # image the server assigned it, so anything outside that set is what
        # this sweep is for. (Called with a single survivor it would delete the
        # other assigned images' downloads and staged files.)
        keep_filenames = list(keep_filenames)
        # 1. drop every download outside the assigned set from aria2c
        for gid, names in _aria_downloads(_rpc):
            if not any(k in names for k in keep_filenames):
                _aria_drop(_rpc, gid)
        # 2. delete stale staged image artifacts (never the agent's own files)
        import glob
        keep = set()
        for keep_filename in keep_filenames:
            keep.update((keep_filename, keep_filename + ".aria2",
                         # this image's own peer-transfer snapshot: it may be
                         # sitting here waiting for the completion tick to fold
                         # it in
                         keep_filename
                         + telemetry_report.PEER_TRANSFER_SIDECAR_SUFFIX))
        keep.update(keep_id + ".torrent" for keep_id in keep_ids)
        for path in glob.glob(os.path.join(cfg["stage_dir"], "*")):
            base = os.path.basename(path)
            if base in keep:
                continue
            if base.endswith((".bin", ".torrent", ".aria2",
                              telemetry_report.PEER_TRANSFER_SIDECAR_SUFFIX)):
                try:
                    os.remove(path)
                except OSError:
                    pass

    def root_present(fname, prefix="flash:", expected_size=None):
        # Cheap existence check of the staged root copy (no hashing).
        # IOS says it's gone -> False (re-copy). cli_execute itself raised
        # (transient glitch) -> True, so one flaky tick doesn't trigger a full
        # 1.2 GB re-copy; a real loss still shows as "No such file" next tick.
        # The verdict on the output itself lives in the module-level
        # _root_present_from_dir so it's unit-testable off-box (including the
        # present-but-unparseable case, which is tolerated for exactly the same
        # reason as the raise above).
        try:
            out = cli_execute("dir %s%s" % (prefix, fname))
        except Exception:
            return True
        return _root_present_from_dir(out, fname, expected_size)

    def remove_stage(path):
        try:
            os.remove(path)
        except OSError:
            pass

    def aria_remove(filename):
        # Drop THIS image's download from aria2 so a fresh addTorrent actually
        # re-downloads. aria2 refuses a duplicate info_hash, so a stale
        # completed/seeding entry (e.g. after the staged file was deleted)
        # silently swallows the re-add. Mirrors purge_others' removal, but
        # targets the kept image instead of the others.
        for gid, names in _aria_downloads(_rpc):
            if filename in names:
                _aria_drop(_rpc, gid)

    def _show(cmd):
        try:
            return cli_execute(cmd)
        except Exception:
            return ""

    def detect_mode():
        return flash_target.detect_mode(_show("show version"),
                                        _show("show boot"))

    _gsf_cache = []   # memoized guest-share FS probe (closure cell)

    def _guest_share_fs(fss):
        """IOS prefix of the writable disk that actually holds guest-share/, or
        None. Probed once (memoized): guest-share exists whenever guestshell is
        up (the agent runs inside it). C9300 -> flash:, IE3k -> sdflash:."""
        if _gsf_cache:
            return _gsf_cache[0]
        found = None
        for f in fss:
            if f["type"] != "disk" or "rw" not in f["flags"]:
                continue
            # Probe every prefix IRIS may actually name, not just the first:
            # crashinfo: is never selectable, and a disk that exposes it
            # alongside real prefixes (Catalyst 8000V) is still a candidate.
            for prefix in flash_target.selectable_prefixes(f):
                if "Directory of" in _show("dir %sguest-share" % prefix):
                    found = prefix
                    break
            if found:
                break
        _gsf_cache.append(found)
        return found

    def target_fs():
        sb = _show("show boot")
        fss = flash_target.parse_file_systems(_show("show file systems"))
        gsf = _guest_share_fs(fss)
        mdl = flash_target.device_model(_show("show version"))
        preferred = cfg.get("target_fs", "").strip()
        prefix = _choose_ios_stage_prefix(
            platform, fss, mdl, gsf, preferred, flash_target.boot_path(sb))
        if not prefix:
            emit("TARGET-FS",
                 "no writable IOS staging filesystem could be proved from "
                 "show/dir output; refusing to stage")
            raise RuntimeError("no proved writable IOS staging filesystem")
        if preferred and prefix != preferred:
            emit("TARGET-FS",
                 "configured %s is not a writable IOS disk; using %s"
                 % (preferred, prefix))
        free = next((f["free"] for f in fss
                     if prefix in f["prefixes"] and f["free"] is not None), None)
        if free is None:                       # fallback: dir <prefix>
            try:
                free = flashcheck.parse_free_bytes(_show("dir %s" % prefix))
            except ValueError:
                free = 0
        return prefix, free

    def free_bytes(prefix="flash:"):
        # Cheap free-space read for the heartbeat only (a single `dir <stage_fs>`),
        # so the steady-state "ready" tick doesn't run `show file systems` every
        # 60s (spec 4.5: no steady-state CLI churn). The gates call target_fs()
        # directly for the media-aware free figure they act on.
        try:
            return flashcheck.parse_free_bytes(_show("dir %s" % prefix))
        except ValueError:
            return 0

    def running_image():
        return flash_target.running_image(_show("show version"))

    def reclaimable(target_prefix, protect):
        return flash_target.reclaimable_artifacts(
            _show("dir %s" % target_prefix), protect)

    def reclaim_bundle(target_prefix, names):
        # Thin wrapper — the applet templating lives in the module-level impl
        # so it's unit-tested off-box. Serves the bundle-mode download gate,
        # the replaced-root cleanup, and the failed-placement reclaim in
        # run_once (see each caller's docstring for its safety guarantee).
        #
        # Platform split mirrors copy_to_root's. The EEM applet exists because
        # the C9300 Guest Shell `cli` module can't drive privileged exec work,
        # and a raw exec `delete` silently no-ops on AAA/TACACS-managed nodes
        # without `authorization bypass`. The container / SSH-to-self platforms
        # reach IOS over a real vty, where `delete /force` runs directly — the
        # same command _copy_to_root_direct_impl already issues there before
        # every copy. Best-effort per name so one failure can't strand the rest.
        if _container_iox and _transport is not None:
            for n in names:
                try:
                    cli_execute("delete /force %s%s" % (target_prefix, n))
                except Exception as e:
                    emit("RECLAIM-FAIL",
                         "%s%s delete failed: %s" % (target_prefix, n, e))
            return
        _reclaim_bundle_impl(target_prefix, names, cli_configure, cli_execute)

    def version():
        try:
            out = cli_execute("show version | include Cisco IOS XE Software")
            return out.strip().split(",")[-1].strip() or "unknown"
        except Exception:
            return "unknown"

    def model():
        # Hardware model (e.g. C9300-48UXM / IE-3400-8T2S) for the swarm map.
        return flash_target.device_model(_show("show version"))

    def checkpoint(state):
        # Durable pre-POST persistence of identity/sequence facts. Wired to the
        # same state path main() uses for the ordinary final save, so a crash
        # after a checkpointed POST restarts with the frozen id/sequence.
        _atomic_write_state(state_path, state)

    deps = Deps(
        catalog=catalog, emit=emit, boot_image=boot_image,
        aria_add=aria_add,
        file_size=lambda p: os.path.getsize(p) if os.path.exists(p) else None,
        verify=lambda p, sha: verify_image.sha256_matches(p, sha),
        free_bytes=free_bytes, version=version, copy_to_root=copy_to_root,
        purge_others=purge_others, reclaim=reclaim,
        root_present=root_present, remove_stage=remove_stage,
        aria_remove=aria_remove,
        detect_mode=detect_mode, target_fs=target_fs,
        running_image=running_image, reclaimable=reclaimable,
        reclaim_bundle=reclaim_bundle, model=model, refresh=refresh,
        aria_stats=aria_stats, aria_peers=aria_peers,
        io_transfer=_container_iox,
        checkpoint=checkpoint, aria_session=aria_session,
        copy_in_place=False,
        root_file_size=lambda name, prefix: _ios_root_file_size(
            name, prefix, cli_execute),
        # IOx has a real vty: hash synchronously. The Guest Shell's
        # `cli` module cannot sit through a long command, hence its
        # asynchronous EEM policy and attestation files instead.
        verify_root=(
            (lambda name, prefix, digest: _verify_iox_root(
                name, prefix, digest, cli_execute))
            if _container_iox else
            (lambda name, prefix, digest: _verify_guestshell_root(
                name, prefix, digest, cfg["stage_dir"], cli_configure))))
    return _with_instruction_step(deps, cfg, conf_path, platform)


# Tick results for which main() exits NON-ZERO (#232). Both launchers key
# their failure backoff on the agent's exit status (entrypoint.sh
# next_tick_sleep, bootstrap.sh BACKOFF_FILE -- issue #59), and both document
# that backoff as covering "catalog unreachable, timed out, or answering a
# non-2xx status". run_once contains exactly that case into the string
# "catalog-unavailable" and returned it with exit 0, so the backoff only ever
# engaged for an uncontained crash and a catalog outage kept every device
# re-polling on the ordinary cadence. The state file is still written and the
# result still printed before the exit code is raised; the other contained
# results (no assignment, a local instruction apply failure, a per-image
# staging error) are not catalog-plane failures and keep exit 0.
_BACKOFF_RESULTS = frozenset(("catalog-unavailable",))


def _tick_exit_code(result):
    return 1 if result in _BACKOFF_RESULTS else 0


def main():  # pragma: no cover
    conf_path = os.environ.get(
        "IRIS_AGENT_CONF", "/flash/guest-share/iris/iris-agent.conf")
    state_path = os.environ.get(
        "IRIS_AGENT_STATE", "/flash/guest-share/iris/iris-agent.state")

    # single-instance lock: a run can outlive the 60s EEM tick (hashing a 1.2 GB
    # image takes minutes on the device CPU). Without this, overlapping runs race
    # on the state file and double-fire the root copy.
    import fcntl
    lock = open(os.path.join(os.path.dirname(state_path), "iris-agent.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("busy (previous run still active)")
        return

    cfg = agent_config.load(conf_path)
    if cfg.get("device_platform") in ("iox", "xr-appmgr"):
        tick_seconds = _normalize_tick_seconds(
            os.environ.get("IRIS_TICK_SECONDS"))
    else:
        tick_seconds = 60
    load_error = None
    try:
        with open(state_path) as f:
            state = json.load(f)
    except FileNotFoundError:
        state = {}
    except Exception as e:
        state = {}
        load_error = e
    deps = build_deps(cfg, conf_path, state_path)
    if load_error is not None:
        deps.emit("STATE-LOAD-FAIL",
                  "%s unreadable; starting with empty state: %s"
                  % (state_path, load_error))
    result = run_once(cfg, deps, state, tick_seconds)
    try:
        # Ordinary final state save: durable, best-effort. A crash-critical
        # identity/sequence fact was already checkpointed BEFORE its POST, so
        # losing this outer save only costs progress, never idempotency.
        _atomic_write_state(state_path, state)
    except Exception as e:
        deps.emit("STATE-WRITE-FAIL", "%s persistence failed: %s"
                  % (state_path, e))
    print(result)
    return _tick_exit_code(result)


if __name__ == "__main__":
    if "--once" in sys.argv or len(sys.argv) == 1:
        # None (the "busy" early return) exits 0 like the ordinary tick.
        sys.exit(main())
