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
import json
import os
import random
import re
import shutil
import sys
import time

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

Deps = collections.namedtuple(
    "Deps", "catalog emit ios aria_add file_size verify free_bytes version "
            "copy_to_root purge_others reclaim root_present remove_stage "
             "aria_remove detect_mode target_fs running_image reclaimable "
             "reclaim_bundle model refresh aria_stats aria_peers io_transfer")


def _heartbeat(image, deps, stage_state="staging", target_fs=None,
               tele_on=True, stage_error=None):
    return {"current_image_id": image["id"],
            "free_flash_bytes": deps.free_bytes(target_fs or "flash:"),
            "version": deps.version(),
             "model": deps.model(),
             "stage_state": stage_state,
             "stage_error": stage_error,
             "target_fs": target_fs,
            "telemetry_enabled": bool(tele_on)}


def _send_heartbeat(deps, sid, payload):
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
        return deps.catalog.heartbeat(sid, payload)
    except Exception as e:
        deps.emit("HEARTBEAT-FAIL", "%s heartbeat failed (ignored): %s" % (sid, e))
        return None


# telemetry (#13): completion-jitter sleep as a module seam so tests can stub
# it (real jitter is up to JITTER_MAX seconds per send).
_SLEEP = time.sleep


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
        telemetry_report.record_success(state)
        deps.emit("TELEMETRY", "%s report sent (%s)"
                  % (img_id, report.get("event")))
        return True
    except Exception as e:
        telemetry_report.record_failure(state)
        deps.emit("TELEMETRY-FAIL", "%s report failed (ignored): %s"
                  % (img_id, e))
        return False


def _telemetry_tick(cfg, deps, state, img_id, stage, phase, hb_resp, now):
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
        # Deliberately NO record_success on a good heartbeat — only a
        # delivered REPORT resets the streak (_send_report), so a new agent
        # talking to an old server (heartbeats fine, report POSTs 404) still
        # backs off instead of resetting the streak every tick.
        if hb_resp is None:
            telemetry_report.record_failure(state)
        st = state.setdefault(img_id, {})
        tele = st.setdefault("tele", {})
        # self-heal state poisoned by the pre-2026.07.04.7 pull-sampling bug
        # (fabricated multi-GB tx rows on finished transfers) — cheap and
        # idempotent, so it simply runs every tick
        if telemetry_report.heal_post_completion_contamination(tele):
            deps.emit("TELEMETRY-HEAL",
                      "%s dropped fabricated post-completion peer rows" % img_id)
        if phase == "downloading" and "started_ts" not in tele:
            tele["started_ts"] = now
        if phase in ("downloading", "seeding-only"):
            telemetry_report.integrate_peers(tele, deps.aria_peers(stage), now)
        if phase in ("copied", "seeding-only") and not tele.get("done_ts"):
            # One-time completion snapshot, taken while aria2 still holds the
            # download (before purge/removeDownloadResult/daemon bounces).
            # Take ONE final per-peer sample first so at least one real-elapsed
            # window lands even on a fast download (the accumulated weights
            # drive per-peer share when the total is attributed). The
            # seeding-only path already sampled this tick above, so only the
            # 'copied' completion needs the extra sample. Best-effort: a
            # peer-RPC hiccup here must never block marking done.
            if phase == "copied":
                try:
                    telemetry_report.integrate_peers(
                        tele, deps.aria_peers(stage), now)
                except Exception:
                    pass
            tele["done_ts"] = now
            stats = deps.aria_stats(stage)
            if stats:
                tele["total_bytes"] = int(stats.get("completedLength", 0) or 0)
            elapsed = max(now - tele.get("started_ts", now), 0.0)
            tele["elapsed_s"] = elapsed
            if elapsed > 0 and tele.get("total_bytes"):
                tele["avg_bps"] = int(tele["total_bytes"] / elapsed)
            tele["sha_ok"] = bool(st.get("done"))
        # Arm exactly one completion report per image. staging-complete
        # upgrades an armed-but-unsent seeding-only report (the copy gate
        # cleared on a later tick).
        if phase == "copied" and st.get("copied") \
                and tele.get("event") != "staging-complete":
            tele["event"] = "staging-complete"
            tele["report_pending"] = True
            tele["report_attempts"] = 0
            tele["report_next_ts"] = 0.0
        elif phase == "seeding-only" and not tele.get("event"):
            tele["event"] = "seeding-only"
            tele["report_pending"] = True
            tele["report_attempts"] = 0
            tele["report_next_ts"] = 0.0
        # GUI pull: fresh report THIS tick, independent of the pending
        # report's backoff. On a steady tick the pull re-sends the COMPLETED
        # transfer's stats FROZEN — deliberately NO fresh sample. The per-peer
        # numbers are rate-integrations (speed x elapsed-since-last-sample,
        # clamped at ELAPSED_CLAMP) which are only meaningful while sampling
        # runs every tick; a sparse pull-time sample extrapolates one
        # instantaneous reading across the whole clamp window and MUTATES a
        # finished transfer's table (hardware-observed: a device seeding a
        # neighbor's download at LAN speed accumulated ~12 GB phantom tx on a
        # 1.26 GB image across three pulls, and the neighbor got injected as a
        # bogus rx row via the even-split fallback). No local retry
        # bookkeeping: the server keeps the directive until a report ARRIVES,
        # so a failed send is re-flagged on the next heartbeat anyway.
        if telemetry_report.pull_requested(hb_resp):
            _send_report(cfg, deps, state, img_id,
                         telemetry_report.build_report(cfg, state, img_id,
                                                       "pull", now))
        # Pending completion report: tier-gated with exponential backoff.
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
                        tele["report_attempts"], now)
                else:
                    report = telemetry_report.build_report(
                        cfg, state, img_id, tele.get("event")
                        or "staging-complete", now)
                    if tier == "constrained":
                        report = telemetry_report.trim_report(report)
                    if _send_report(cfg, deps, state, img_id, report):
                        tele["report_pending"] = False
                        tele["report_sent_ts"] = now
                    else:
                        tele["report_attempts"] = \
                            tele.get("report_attempts", 0) + 1
                        tele["report_next_ts"] = telemetry_report.next_backoff_ts(
                            tele["report_attempts"], now)
    except Exception as e:
        try:
            deps.emit("TELEMETRY-FAIL", "telemetry tick failed (ignored): %s" % e)
        except Exception:
            pass


def _protect_set(image, state):
    """Files reclaim must never delete: the running image, the image being
    staged (+ its torrent/aria2 sidecars), and IRIS's own placed root copy."""
    keep = {image["filename"], image["filename"] + ".aria2",
            image["id"] + ".torrent"}
    rf = state.get("root_file")
    if rf:
        keep.add(rf)
    return keep


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

    A skip/no-op returns False so the next tick retries once the transient
    clears."""
    if mode == "install":
        deps.reclaim()
        return True
    if mode == "bundle":
        running = deps.running_image()
        if running is None:
            return False
        protect = _protect_set(image, state)
        protect.add(running)
        names = deps.reclaimable(target_prefix, protect)
        if names:
            deps.reclaim_bundle(target_prefix, names)
            return True
    return False


def run_once(cfg, deps, state):
    # Self-refresh the catalog token BEFORE any catalog work, once it's past
    # half-life (or its expiry is unknown). Best-effort: deps.refresh() does the
    # POST + atomic conf rewrite and returns the updated cfg, or None on failure
    # — on failure we log and proceed on the CURRENT token (a 7d TTL + half-life
    # refresh leaves a ~3.5d retry buffer, so a few failed ticks never strand
    # the device).
    if needs_refresh(time.time(),
                     int(float(cfg.get("token_expires_at", 0) or 0)),
                     _TOKEN_TTL, _TOKEN_REFRESH_AT):
        new_cfg = deps.refresh()
        if new_cfg is None:
            deps.emit("TOKEN-REFRESH-FAIL",
                      "catalog token refresh failed; proceeding on current token")
        else:
            cfg = new_cfg
    sid = cfg["device_id"]
    stage_dir = cfg["stage_dir"]
    tele_on = telemetry_report.enabled(cfg)

    # Upgrade from an older agent: clear "copied" so the next copy_to_root
    # re-verifies the flash-root copy instead of trusting the old flag.
    # Keep root_file — the reassignment cleanup below needs it to delete the
    # old root copy. Only emit UPGRADE if we actually cleared something.
    if state.get("schema_version", 1) < _STATE_SCHEMA:
        cleared = False
        for v in state.values():
            if isinstance(v, dict) and v.get("copied"):
                v["copied"] = False
                cleared = True
        state["schema_version"] = _STATE_SCHEMA
        if cleared:
            deps.emit("UPGRADE", "re-verifying flash-root copy after upgrade")

    policy = deps.catalog.get_policy(sid)
    img_id = policy.get("approved_image_id")
    if not img_id:
        return "no-assignment"
    image = deps.catalog.get_image(img_id)
    if image is None:
        deps.emit("ERROR", "assigned image %s not in catalog" % img_id)
        return "no-image"

    # Reject a bad catalog filename before it reaches any IOS command.
    fname = image["filename"]
    if not _FILENAME_RE.match(fname):
        deps.emit("ERROR",
                  "rejected catalog filename (must match %s): %r"
                  % (_FILENAME_RE.pattern, fname))
        return "bad-filename"

    stage = os.path.join(stage_dir, fname)
    size = int(image["size"])

    # steady state: image done + copied -> just heartbeat. Do NOT re-hash the
    # 1.2 GB file every tick — hashing takes longer than the 60s timer and the
    # overlapping runs double-fired the root copy (two concurrent IOS copies
    # interleave into a corrupt oversized file).
    # Self-heal: the short-circuit holds ONLY while the catalog content (sha) is
    # unchanged AND both the staged and flash-root copies still exist — all cheap
    # checks (no hashing). If content changed, or either copy went missing, fall
    # through to re-acquire (re-download a missing/stale staged file; re-copy a
    # missing root file).
    done_st = state.get(img_id, {})
    if state.get("image_id") == img_id and done_st.get("done") \
            and done_st.get("copied"):
        content_ok = done_st.get("sha", image["sha256"]) == image["sha256"]
        staged_ok = deps.file_size(stage) is not None
        root_ok = deps.root_present(image["filename"], state.get("stage_fs", "flash:"))
        if content_ok and staged_ok and root_ok:
            hb = _send_heartbeat(deps, sid,
                                 _heartbeat(image, deps, "ready",
                                            target_fs=state.get("stage_fs"),
                                            tele_on=tele_on))
            _telemetry_tick(cfg, deps, state, img_id, stage, "steady",
                            hb, time.time())
            return "complete"
        deps.emit("RECHECK", "%s re-acquiring (content=%s staged=%s root=%s)"
                  % (image["filename"], content_ok, staged_ok, root_ok))
        if staged_ok and not content_ok:
            deps.remove_stage(stage)      # stale content on disk -> drop, re-download
            staged_ok = False
        done_st["done"] = staged_ok       # keep 'done' only for a root-only loss
        done_st["copied"] = False         # always re-copy

    # reassigned to a DIFFERENT image? clean up everything from the old one FIRST
    # (operator requirement: no stale files on the device). Removes the old torrent
    # from aria2c, deletes old staged files, and deletes the old flash-root copy —
    # but ONLY the one IRIS itself placed there (tracked in state).
    prev = state.get("image_id")
    if prev and prev != img_id:
        deps.purge_others(image["filename"], img_id)
        old_root = state.get("root_file")
        # Re-check the whitelist before interpolating into a destructive delete,
        # in case the state file was hand-edited.
        if old_root and old_root != image["filename"] \
                and _FILENAME_RE.match(old_root):
            deps.ios("delete /force %s%s"
                     % (state.get("stage_fs", "flash:"), old_root))
            deps.emit("CLEANUP", "removed replaced image %s (now %s)"
                      % (old_root, img_id))
            state.pop("root_file", None)
        state.pop(prev, None)             # old image's done/copied flags
    state["image_id"] = img_id

    # already downloaded AND aria2 finished? aria2 keeps a "<file>.aria2" control
    # file until the download is fully done; checking it avoids hashing a file that
    # has reached full size but whose last pieces aren't on disk yet (a race that
    # produced spurious sha mismatches on the 60s timer).
    downloading = deps.file_size(stage + ".aria2") is not None
    if deps.file_size(stage) == size and not downloading:
        if deps.verify(stage, image["sha256"]):
            # state is PER-IMAGE: a reassignment to a new image id must go through
            # the full DONE + copy-to-root cycle again, untouched by the old one.
            st = state.setdefault(img_id, {})
            st["sha"] = image["sha256"]    # record verified content (change-detect)
            if not st.get("done"):
                st["done"] = True
                deps.emit("DONE", "%s complete sha256-ok id=%s"
                          % (image["filename"], img_id))
            # Place at flash root via NATIVE EEM. The agent templates the
            # IRIS-COPYROOT applet and fires it; the applet clears any stale
            # same-named leftover, then runs `copy /verify` (copy + Cisco
            # signature, enforced by IOS in one step — a bad signature fails the
            # copy and deletes the destination). The agent then polls for the
            # file at flash root: presence proves THIS attempt's copy/verify
            # passed. copy_to_root returns False if the file never appears ->
            # st['copied'] stays False so the next tick retries.
            # Copy gate: placing the flash-root copy needs room for a SECOND
            # full-size image alongside the staged/seeding scratch. On a tight
            # device that fit one image but not two, degrade to keep-seeding-only
            # — the staged file keeps feeding the swarm, the running image is
            # untouched, and we surface the shortfall instead of failing a copy.
            if not st.get("copied"):
                mode = deps.detect_mode()
                target_prefix, free = deps.target_fs()
                state["stage_fs"] = target_prefix
                if not flashcheck.has_room(free, size):
                    # Only burn the once-guard when reclaim ACTUALLY ran — a
                    # transient mode=None (or unconfirmable running image) does
                    # nothing, so leave the guard clear to retry next tick.
                    if not st.get("copy_reclaim_tried"):
                        if _reclaim_for_mode(deps, mode, target_prefix,
                                             image, state):
                            st["copy_reclaim_tried"] = True
                            target_prefix, free = deps.target_fs()
                    if not flashcheck.has_room(free, size):
                        st["blocked_no_space"] = True
                        deps.emit("FLASH-FULL",
                                  "%s staged+seeding, no room for flash-root copy "
                                  "(free=%d need>=%d mode=%s)"
                                  % (image["filename"], free,
                                     size + flashcheck.HEADROOM, mode))
                        hb = _send_heartbeat(
                            deps, sid, _heartbeat(image, deps,
                                                  "flash_full_seeding_only",
                                                  target_fs=state.get("stage_fs"),
                                                  tele_on=tele_on))
                        _telemetry_tick(cfg, deps, state, img_id, stage,
                                        "seeding-only", hb, time.time())
                        return "seeding-only"
                st.pop("blocked_no_space", None)
                # Container-mode IOx devices must SCP the completed image into
                # IOS-visible storage before the final copy /verify. That large
                # transfer blocks this agent process, so publish its state first
                # instead of leaving the Console on ambiguous "staging".
                if deps.io_transfer:
                    _send_heartbeat(
                        deps, sid, _heartbeat(image, deps, "transferring_to_ios",
                                              target_fs=target_prefix,
                                              tele_on=tele_on))
                if deps.copy_to_root(image["filename"], target_prefix):
                    st["copied"] = True
                    state["root_file"] = image["filename"]   # ours; safe to replace later
                    st.pop("stage_error", None)
                else:
                    st["stage_error"] = (
                        "final IOS placement failed; inspect IRIS ROOTCOPY-FAIL")
            # "ready" only when the flash-root copy is actually placed; a failed
            # copy_to_root (signature fail / never appeared) keeps "staging" so
            # the heartbeat never claims a verified root copy that isn't there.
            hb = _send_heartbeat(
                deps, sid, _heartbeat(image, deps,
                                       "ready" if st.get("copied") else "staging",
                                       target_fs=state.get("stage_fs"),
                                       tele_on=tele_on,
                                       stage_error=st.get("stage_error")))
            _telemetry_tick(cfg, deps, state, img_id, stage, "copied",
                            hb, time.time())
            return "complete"
        deps.emit("ERROR", "%s sha256 MISMATCH - discarding" % image["filename"])
        deps.remove_stage(stage)          # drop the bad file so the next tick re-downloads
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
    if not flashcheck.has_room(free, size):
        st = state.setdefault(img_id, {})
        # Burn the once-guard only when reclaim actually ran (a no-op on a
        # transient mode=None must not permanently disable reclaim).
        if not st.get("reclaim_tried"):
            if _reclaim_for_mode(deps, mode, target_prefix, image, state):
                st["reclaim_tried"] = True
                target_prefix, free = deps.target_fs()
        if not flashcheck.has_room(free, size):
            # Nothing is staged yet on this path, so the device is NOT seeding —
            # report plain flash_full (reserve flash_full_seeding_only for the
            # copy gate, where the scratch is downloaded and feeding the swarm).
            deps.emit("FLASH-FULL",
                      "%s no room to stage (free=%d need>=%d mode=%s)"
                      % (image["filename"], free, size + flashcheck.HEADROOM,
                         mode))
            hb = _send_heartbeat(
                deps, sid, _heartbeat(image, deps, "flash_full",
                                      target_fs=state.get("stage_fs"),
                                      tele_on=tele_on))
            _telemetry_tick(cfg, deps, state, img_id, stage, "no-space",
                            hb, time.time())
            return "no-space"

    # stage the torrent, then kick aria2c — but ONLY if the image file isn't there
    # yet. aria2 writes the file as soon as it starts, so a present (partial) file
    # means a download is already in progress; the 60 s EEM timer must NOT
    # re-addTorrent it (that would duplicate/corrupt the download).
    torrent = os.path.join(stage_dir, img_id + ".torrent")
    if deps.file_size(torrent) is None:
        deps.catalog.download_torrent(img_id, torrent)
    have = deps.file_size(stage)
    if have is None:
        # clear any stale/phantom aria2 entry (e.g. a completed seed whose staged
        # file was deleted) so addTorrent actually re-downloads instead of being a
        # silent no-op on the duplicate info_hash.
        deps.aria_remove(image["filename"])
        deps.aria_add(torrent, stage_dir)
        deps.emit("STAGING", "downloading %s via private swarm" % image["filename"])
    else:
        # one progress line per agent run (60s) — NOT a separate fast timer (the
        # old 10s IRIS-MONITOR raced and spammed). Computed from the on-disk size.
        deps.emit("PROGRESS", "%s %d%% (%dMB/%dMB)"
                  % (image["filename"], have * 100 // size, have >> 20, size >> 20))
    hb = _send_heartbeat(deps, sid, _heartbeat(image, deps,
                                               target_fs=state.get("stage_fs"),
                                               tele_on=tele_on))
    _telemetry_tick(cfg, deps, state, img_id, stage, "downloading",
                    hb, time.time())
    return "downloading"


# ---- catalog TLS context selection (#12: verify-if-present) ----
# Pure + unit-tested (test_catalog_tls.py) so the verify/warn branch is covered
# off-box even though build_deps itself is `# pragma: no cover`.

def make_catalog_context(cfg, warn):
    """Return the ssl.SSLContext for the catalog connection.

    verify-if-present (LOCKED back-compat, spec §4.6):
      * catalog_ca set AND the file exists -> a VERIFYING context
        (ssl.create_default_context(cafile=...) does full chain + hostname/IP-SAN
        validation; catalog_url uses the SAN IP so the match succeeds);
      * otherwise -> today's UNVERIFIED context, but call warn(msg) once so an
        agent-only upgrade (new bundle, old config with no catalog_ca) does NOT
        break the running fleet — it just logs that TLS is not pinned.
    `warn` is the agent's syslog emit (injected so this is testable off-box)."""
    import os
    import ssl
    ca = cfg.get("catalog_ca")
    if ca and os.path.exists(ca):
        return ssl.create_default_context(cafile=ca)
    warn("catalog_ca not set or file missing - TLS NOT verified (legacy); "
         "re-run installer to pin")
    return ssl._create_unverified_context()


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


def _refresh_impl(cfg, conf_path, refresh_token_fn, emit_fn):
    """Refresh the catalog token and persist the new secret bag.

    1. POST token-refresh (refresh_token_fn) -> {catalog_token, expires_at,
       announce_token, rpc_secret}.
    2. Merge into a copy of cfg, atomically rewrite conf_path, return the
       reloaded cfg.

    Best-effort: ANY failure (network, write) logs TOKEN-REFRESH-FAIL and
    returns None so the caller proceeds on the current in-memory cfg. On the
    POST-failure path the on-disk conf is never touched (no partial write).
    Module-level + injected callables so it's unit-testable; build_deps wires
    the real CatalogClient.refresh_token + emit."""
    sid = cfg["device_id"]
    try:
        bag = refresh_token_fn(sid)
    except Exception as e:
        emit_fn("TOKEN-REFRESH-FAIL", "%s refresh POST failed: %s" % (sid, e))
        return None
    new_cfg = dict(cfg)
    new_cfg["catalog_token"] = bag["catalog_token"]
    new_cfg["token_expires_at"] = str(bag["expires_at"])
    # announce_token + rpc_secret are returned as-is (not rotated here); persist
    # them so aria2's NEXT launch picks them up.
    if bag.get("announce_token") is not None:
        new_cfg["announce_token"] = bag["announce_token"]
    if bag.get("rpc_secret") is not None:
        new_cfg["rpc_secret"] = bag["rpc_secret"]
    try:
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


def _find_aria_gid(rpc, stage_path):
    """Locate the aria2 gid whose download owns the staged file at stage_path.

    Basename match against each download's files paths — the same idiom
    purge_others uses — checking tellActive first (live download / seed), then
    tellStopped (finished). Returns the gid string or None when no download
    matches. May raise on rpc failure (callers wrap)."""
    fname = os.path.basename(stage_path)
    for call, extra in (("aria2.tellActive", []),
                        ("aria2.tellStopped", [0, 100])):
        for d in rpc(call, extra + [["gid", "files"]]):
            names = [os.path.basename(f.get("path", ""))
                     for f in d.get("files", [])]
            if fname in names:
                return d["gid"]
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
                            "downloadSpeed", "uploadSpeed", "connections"]])
        # _rpc defaults a missing "result" to [] — never leak a non-dict out.
        return status if isinstance(status, dict) else None
    except Exception:
        return None


def _aria_peers_impl(rpc, stage_path):
    """Simplified aria2.getPeers rows for the staged file's download:
    [{'ip', 'downloadSpeed', 'uploadSpeed'}] (values are aria2's strings;
    missing keys default to ''/'0'). Returns [] on no matching download / ANY
    error (getPeers on a stopped download is an aria2 error). NEVER raises."""
    try:
        gid = _find_aria_gid(rpc, stage_path)
        if gid is None:
            return []
        return [{"ip": p.get("ip", ""),
                 "downloadSpeed": p.get("downloadSpeed", "0"),
                 "uploadSpeed": p.get("uploadSpeed", "0")}
                for p in rpc("aria2.getPeers", [gid])]
    except Exception:
        return []


# ---- agent-side root-copy re-verification (module-level so it's unit-testable
# with injected cli_execute / sha256 callables; build_deps below wires it up
# with the real on-box implementations) ----

def _agent_reverify_root(fname, target_prefix, cli_execute_fn, emit_fn,
                        poll_attempts=180, poll_interval_s=5.0,
                        sleep_fn=time.sleep):
    """Bless the target-FS root copy once the IRIS-COPYROOT applet's
    `copy /verify` has completed.

    We trust `copy /verify`: IOS copies the file AND enforces the Cisco
    signature in one step, and a failed signature fails the copy and deletes
    the destination. The applet deletes any stale same-named leftover BEFORE
    the copy (see _copy_to_root_impl), so after it runs a file at
    <FS><fname> can only be one this attempt's `copy /verify` wrote and
    signature-verified. That makes file presence a sound, attempt-scoped
    verdict — and the device's guestshell can't read the FS root as a file or
    run `verify` (it hangs) anyway, so `dir <FS><fname>` (a small, fast cli
    call) is all it needs.

    Polls `dir <FS><fname>` and returns bool:
      * file appears  -> emit ROOTCOPY, return True
      * never appears within the poll budget (signature failed -> dest deleted,
        or the copy never ran) -> emit ROOTCOPY-FAIL, return False. Nothing to
        delete; the next tick re-fires the applet.

    Default poll budget (180 * 5 s ≈ 895 s) tracks the applet's `maxrun 900` so
    a legitimately slow ~1.2 GB copy isn't abandoned a few minutes early."""
    emit_fn("ROOTCOPY-VERIFYING", "%s applet running copy /verify" % fname)
    for i in range(poll_attempts):
        try:
            dir_out = cli_execute_fn("dir %s%s" % (target_prefix, fname))
        except Exception:
            dir_out = ""
        if dir_out and "%Error" not in dir_out and "No such file" not in dir_out \
                and fname in dir_out:
            emit_fn("ROOTCOPY", "%s placed at flash root + verified" % fname)
            return True
        if i < poll_attempts - 1:
            sleep_fn(poll_interval_s)
    emit_fn("ROOTCOPY-FAIL",
            "%s verify timed out (no file appeared at flash root)" % fname)
    return False


def _copy_to_root_impl(fname, target_prefix, cli_configure_fn, cli_execute_fn,
                      emit_fn, reverify_fn=_agent_reverify_root,
                      copy_source=None):
    """Copy the staged image to the target filesystem root, then confirm it
    landed.

    The IRIS-COPYROOT EEM applet does the privileged work inside native IOS
    (operator requirement + `authorization bypass` for AAA nodes), because the
    device's guestshell can't run `copy`/`verify` directly:
      1. `delete /force <FS><fname>` — clear any stale same-named leftover so
         the presence check below is scoped to THIS attempt. Harmless if no
         such file exists (`file prompt quiet` suppresses the prompt).
      2. `copy /verify <FS>/guest-share/iris/<fname> <FS><fname>` — copy +
         Cisco signature in one IOS-enforced step; a bad signature fails the
         copy and leaves no destination file. Source and destination are both
         the chosen staging FS: flash: on the C9300, sdflash: on the IE3k (where
         IOx and the guest-share scratch live on the SD card).
    The applet logs a NEUTRAL `ROOTCOPY-ATTEMPTED` breadcrumb only — it makes no
    pass/fail claim. The agent (reverify_fn) owns the verdict: it polls for the
    file and emits the authoritative `ROOTCOPY ... + verified` log on presence.

    Module-level + injected callables so it's unit-testable. Returns bool.

    `copy_source` (optional) overrides the `copy /verify` SOURCE. Default (None)
    is the Guest Shell scratch on the staging FS (`<FS>/guest-share/iris/<fname>`)
    — the C9300 path, unchanged. The IOx path SCP-pushes its local scratch to
    that same IOS-visible location before using the direct SSH copy helper. The
    destination is always the target-FS root."""
    src = (copy_source(fname, target_prefix) if copy_source
           else "%s/guest-share/iris/%s" % (target_prefix, fname))
    cli_configure_fn([
        "no event manager applet IRIS-COPYROOT",
        "event manager applet IRIS-COPYROOT authorization bypass",
        "event none maxrun 900",
        'action 010 cli command "enable"',
        'action 020 cli command "delete /force %s%s"' % (target_prefix, fname),
        'action 030 cli command "copy /verify %s %s%s"'
        % (src, target_prefix, fname),
        'action 040 syslog msg "ROOTCOPY-ATTEMPTED %s"' % fname,
    ])
    try:
        cli_execute_fn("event manager run IRIS-COPYROOT")
    except Exception as e:
        emit_fn("ROOTCOPY-FAIL", "%s applet run raised: %s" % (fname, e))
        return False
    return reverify_fn(fname, target_prefix, cli_execute_fn, emit_fn)


def _copy_to_root_direct_impl(fname, target_prefix, cli_execute_fn, emit_fn,
                             reverify_fn=_agent_reverify_root, copy_source=None,
                             delete_source_on_success=False):
    """Copy the staged image to the target-FS root by running `copy /verify`
    DIRECTLY in the agent's IOS vty — no EEM applet. This is the container /
    SSH-to-self (IE-3x00) path.

    The IRIS-COPYROOT applet offload (see _copy_to_root_impl) exists ONLY because
    the C9300's Guest Shell `cli` module can't drive an interactive
    `copy`/`verify` (it hangs). The IE-3x00 agent reaches IOS over a real
    SSH-to-self vty (identical to `lab/device-run.sh`), which runs `copy /verify`
    to completion — and on that platform/IOS-XE the EEM `action cli command
    "copy …"` is a NO-OP (the applet completes in ~3 s reporting success but
    transfers nothing), so the applet path is both unnecessary and broken here.

    Same two privileged steps the applet did, now issued directly:
      1. `delete /force <FS><fname>` — clear any stale same-named leftover so the
         dir-presence verdict is scoped to THIS attempt (`file prompt quiet`
         suppresses the prompt; harmless if absent).
      2. `copy /verify <src> <FS><fname>` — copy + Cisco signature in one
         IOS-enforced step; a bad signature fails the copy and leaves no
         destination file. `copy /verify` is synchronous, so the file is present
         the moment it returns.
    Verdict is owned by reverify_fn's dir-presence poll, exactly as the applet
    path — keeping the success-log gating identical and unit-testable. Returns
    bool. `copy_source` overrides the SOURCE like _copy_to_root_impl."""
    src = (copy_source(fname, target_prefix) if copy_source
           else "%s/guest-share/iris/%s" % (target_prefix, fname))
    dst = "%s%s" % (target_prefix, fname)
    try:
        cli_execute_fn("delete /force %s" % dst)
        cli_execute_fn("copy /verify %s %s" % (src, dst))
    except Exception as e:
        emit_fn("ROOTCOPY-FAIL", "%s direct copy /verify raised: %s" % (fname, e))
        return False
    ok = reverify_fn(fname, target_prefix, cli_execute_fn, emit_fn)
    # In container mode the scp-pushed guest-share scratch is a transfer
    # intermediary (the swarm seeds from the CAF-persistent stage_dir), so a
    # verified placement deletes it — otherwise a duplicate image doubles
    # steady-state target-FS usage. Kept on failure: the next tick re-runs
    # copy /verify from it instead of re-pushing over the slow scp path.
    if ok and delete_source_on_success:
        try:
            cli_execute_fn("delete /force %s" % src)
        except Exception:
            pass
    return ok


def _share_settings(cfg):
    """(share_dir, share_ios_path) for the C9k SSD share mount. The app-hosting
    run-opts set the environment (the normal path); conf keys are the fallback
    so a hand-dropped config can steer it too. Empty strings = no share."""
    return (os.environ.get("IRIS_SHARE_DIR") or cfg.get("share_dir") or "",
            os.environ.get("IRIS_SHARE_IOS_PATH")
            or cfg.get("share_ios_path") or "")


_SHARE_SUBDIR = "iris"        # OUR subdir of the shared CAF dir: sweeps and
_SHARE_PROBE = ".iris-probe"  # undeploy cleanup can never touch operator files


def _stage_via_share_impl(fname, stage_dir, share_dir, share_ios_path,
                          copy_direct_fn, emit_fn, cli_execute_fn):
    """Land the downloaded scratch in the bind-mounted app-hosting share
    (C9k: usbflash1:iox_host_data_share, mounted into the container via
    run-opts -v), then have IOS place it with an INTERNAL disk-to-disk
    `copy /verify` — no scp, no control-plane punt path, no CoPP ceiling.

    Everything IRIS writes lives under the share's iris/ subdirectory, so the
    orphan sweep below and undeploy's share cleanup can never touch operator
    files in the shared CAF directory. Each attempt starts by sweeping that
    subdir — a tick killed mid-transfer (re-onboard's app teardown, CAF
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
    `copy /verify` failure AFTER a good probe is FINAL — scp would push the
    same bytes. The transient share copy is always removed (the swarm seeds
    from the scratch under stage_dir, not from the share)."""
    if not (share_dir and share_ios_path and os.path.isdir(share_dir)):
        return None
    sub = os.path.join(share_dir, _SHARE_SUBDIR)
    ios_sub = "%s/%s" % (share_ios_path, _SHARE_SUBDIR)

    def _sweep():
        try:
            for leftover in os.listdir(sub):
                try:
                    os.remove(os.path.join(sub, leftover))
                except OSError:
                    pass
        except OSError:
            pass

    try:
        os.makedirs(sub, exist_ok=True)
    except OSError as e:
        emit_fn("SHARE-FALLBACK",
                "%s share subdir failed (%s); falling back to scp" % (fname, e))
        return None
    _sweep()
    probe = os.path.join(sub, _SHARE_PROBE)
    try:
        with open(probe, "w") as stream:
            stream.write("iris")
        listing = cli_execute_fn("dir %s/%s" % (ios_sub, _SHARE_PROBE))
        if _SHARE_PROBE not in (listing or ""):
            raise OSError("IOS cannot read %s" % ios_sub)
    except Exception as e:
        emit_fn("SHARE-FALLBACK",
                "%s share probe failed (%s); falling back to scp" % (fname, e))
        _sweep()
        return None
    local = os.path.join(stage_dir, fname)
    staged = os.path.join(sub, fname)
    part = os.path.join(sub, ".%s.part" % fname)
    try:
        shutil.copyfile(local, part)
        os.replace(part, staged)
    except OSError as e:
        emit_fn("SHARE-FALLBACK",
                "%s share copy failed (%s); falling back to scp" % (fname, e))
        _sweep()
        return None
    try:
        return copy_direct_fn(
            lambda f, target_prefix: "%s/%s" % (ios_sub, f))
    finally:
        _sweep()


# ---- on-box wiring (not exercised by unit tests) ----

def build_deps(cfg, conf_path):  # pragma: no cover
    import base64
    import urllib.request
    import catalog_client

    ctx = make_catalog_context(cfg, lambda m: emit("TLS-WARN", m))
    catalog = catalog_client.CatalogClient(
        cfg["catalog_url"], cfg["catalog_token"], context=ctx)

    def refresh():
        # Thin wrapper — the POST + atomic conf rewrite + reload lives in the
        # module-level _refresh_impl so it's unit-testable. Returns the reloaded
        # cfg or None (best-effort).
        return _refresh_impl(cfg, conf_path, catalog.refresh_token, emit)

    # Runtime-mode seam: Guest Shell `cli` on the C9300 (default, unchanged) or
    # an SSH-to-self transport in a plain IOx Docker app on the IE-3400. Gated by
    # IRIS_RUNTIME_MODE / conf `runtime_mode`; see cli_ssh.select_cli.
    import cli_ssh
    cli_execute, cli_configure = cli_ssh.select_cli(cfg)

    # IE3x00 IOx app: IOx can't bind-mount sdflash: into the container, and inbound
    # to the container is blocked, so the agent can't write the IOS-visible SD
    # directly. Instead it scp-PUSHES the downloaded scratch to sdflash:guest-share/
    # iris via the device's SCP server (container -> device, the proven direction —
    # same as the SSH-to-self CLI), then the SSH vty runs
    # `copy /verify sdflash:guest-share/iris/<img> sdflash:<img>` — byte-identical
    # to the C9300 flash:guest-share -> flash: flow. Guest Shell (C9300) writes its
    # scratch via the in-VM mount, so it pushes nothing here.
    _mode = (os.environ.get("IRIS_RUNTIME_MODE")
             or cfg.get("runtime_mode") or "guestshell")
    _transport = getattr(cli_execute, "__self__", None)   # SSHCli in container mode

    def _push_scratch(fname, target_prefix):
        # create the IOS-side scratch dir (idempotent; file prompt quiet => no
        # prompt) then scp the downloaded file into it so `copy /verify` has a
        # source IOS can read.
        for d in ("%sguest-share" % target_prefix,
                  "%sguest-share/iris" % target_prefix):
            try:
                cli_execute("mkdir %s" % d)
            except Exception:
                pass
        local = os.path.join(cfg["stage_dir"], fname)
        _transport.put(local, "%sguest-share/iris/%s" % (target_prefix, fname))

    def copy_to_root(fname, target_prefix="flash:"):
        # Thin wrapper — the actual flow lives in module-level impls so
        # behavioural tests can inject all callables and prove the success log
        # is gated by _agent_reverify_root's pass.
        if _mode == "container" and _transport is not None:
            # C9k container: the SSD share (usbflash1:iox_host_data_share) is
            # bind-mounted at IRIS_SHARE_DIR, so the scratch lands there at
            # disk speed and IOS places it with an internal disk-to-disk
            # `copy /verify` — no scp, no CoPP-policed punt traffic. None =
            # share unusable -> fall through to the scp push below.
            share_dir, share_ios_path = _share_settings(cfg)
            if share_dir:
                shared = _stage_via_share_impl(
                    fname, cfg["stage_dir"], share_dir, share_ios_path,
                    lambda copy_source: _copy_to_root_direct_impl(
                        fname, target_prefix, cli_execute, emit,
                        copy_source=copy_source),
                    emit, cli_execute)
                if shared is not None:
                    return shared
            # IE-3x00 / container fallback: push the scratch onto the
            # IOS-visible SD, then `copy /verify` DIRECTLY over the SSH-to-self
            # vty. The EEM applet offload is only needed for the C9300 Guest
            # Shell cli module (can't drive interactive copy); a real vty runs
            # copy fine, and the EEM `cli command "copy"` action is a no-op on
            # this platform — so the direct path is both correct and necessary.
            try:
                _push_scratch(fname, target_prefix)
            except Exception as e:
                emit("ROOTCOPY-FAIL",
                     "%s scp push to %s failed: %s" % (fname, target_prefix, e))
                return False
            # NOTE: like the Guest Shell path, placement transiently needs
            # ~2x the image on the target FS (scratch + root copy); the
            # verified-delete below reclaims the scratch afterwards.
            return _copy_to_root_direct_impl(fname, target_prefix,
                                             cli_execute, emit,
                                             delete_source_on_success=True)
        return _copy_to_root_impl(fname, target_prefix,
                                  cli_configure, cli_execute, emit)

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
        try:
            summ = cli_execute("show install summary")
            if "operation" in summ.lower() and "progress" in summ.lower():
                emit("RECLAIM", "install op already in progress; skipping reclaim")
                return
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
        cli_execute("event manager run IRIS-RECLAIM")

    def emit(mnemonic, msg):
        _emit_impl(cli_execute, mnemonic, msg)

    def ios(cmd):
        return cli_execute(cmd)

    def aria_add(torrent_path, dest_dir):
        rpc = "http://127.0.0.1:%s/jsonrpc" % cfg["rpc_port"]
        with open(torrent_path, "rb") as f:
            tb = base64.b64encode(f.read()).decode()
        params = ["token:" + cfg["rpc_secret"], tb, [],
                  {"dir": dest_dir, "bt-seed-unverified": "true",
                   "bt-max-peers": cfg.get("max_peers", "10")}]
        payload = json.dumps({"jsonrpc": "2.0", "id": "a",
                              "method": "aria2.addTorrent",
                              "params": params}).encode()
        req = urllib.request.Request(rpc, data=payload,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()

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

    def purge_others(keep_filename, keep_id):
        # 1. drop every download except the current image from aria2c
        downloads = []
        for call, extra in (("aria2.tellActive", []),
                            ("aria2.tellWaiting", [0, 100]),
                            ("aria2.tellStopped", [0, 100])):
            try:
                downloads += _rpc(call, extra + [["gid", "files"]])
            except Exception:
                pass
        for d in downloads:
            names = [os.path.basename(f.get("path", "")) for f in d.get("files", [])]
            if keep_filename not in names:
                for m in ("aria2.forceRemove", "aria2.removeDownloadResult"):
                    try:
                        _rpc(m, [d["gid"]])
                    except Exception:
                        pass
        # 2. delete stale staged image artifacts (never the agent's own files)
        import glob
        keep = {keep_filename, keep_filename + ".aria2", keep_id + ".torrent"}
        for path in glob.glob(os.path.join(cfg["stage_dir"], "*")):
            base = os.path.basename(path)
            if base in keep:
                continue
            if base.endswith((".bin", ".torrent", ".aria2")):
                try:
                    os.remove(path)
                except OSError:
                    pass

    def root_present(fname, prefix="flash:"):
        # Cheap existence check of the staged root copy (no hashing).
        # IOS says it's gone -> False (re-copy). cli_execute itself raised
        # (transient glitch) -> True, so one flaky tick doesn't trigger a full
        # 1.2 GB re-copy; a real loss still shows as "No such file" next tick.
        try:
            out = cli_execute("dir %s%s" % (prefix, fname))
        except Exception:
            return True
        if "%Error" in out or "No such file" in out:
            return False
        return fname in out

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
        for call, extra in (("aria2.tellActive", []),
                            ("aria2.tellWaiting", [0, 100]),
                            ("aria2.tellStopped", [0, 100])):
            try:
                for d in _rpc(call, extra + [["gid", "files"]]):
                    names = [os.path.basename(f.get("path", ""))
                             for f in d.get("files", [])]
                    if filename in names:
                        for m in ("aria2.forceRemove",
                                  "aria2.removeDownloadResult"):
                            try:
                                _rpc(m, [d["gid"]])
                            except Exception:
                                pass
            except Exception:
                pass

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
            if f["type"] == "disk" and "rw" in f["flags"] \
                    and "crashinfo:" not in f["prefixes"]:
                prefix = f["prefixes"][0]
                if "Directory of" in _show("dir %sguest-share" % prefix):
                    found = prefix
                    break
        _gsf_cache.append(found)
        return found

    def target_fs():
        sb = _show("show boot")
        fss = flash_target.parse_file_systems(_show("show file systems"))
        gsf = _guest_share_fs(fss)
        mdl = flash_target.device_model(_show("show version"))
        preferred = cfg.get("target_fs", "").strip()
        prefix = (flash_target.choose_stage_fs(
                      fss, model=mdl, guest_share_fs=gsf,
                      preferred_fs=preferred)
                  or flash_target.choose_target_fs(fss, flash_target.boot_path(sb))
                  or "flash:")
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
        # Delete UNUSED image artifacts via a one-shot authorization-bypass
        # applet (AAA nodes silently no-op a raw delete). Stage-only: never the
        # running/staging/seeding image (the caller's `protect` set guarantees
        # `names` excludes them).
        if not names:
            return
        actions = ['action 010 cli command "enable"']
        for i, n in enumerate(names, start=2):
            actions.append('action %03d cli command "delete /force %s%s"'
                            % (i * 10, target_prefix, n))
        cli_configure([
            "no event manager applet IRIS-RECLAIM-BUNDLE",
            "event manager applet IRIS-RECLAIM-BUNDLE authorization bypass",
            "event none maxrun 120",
        ] + actions)
        cli_execute("event manager run IRIS-RECLAIM-BUNDLE")

    def version():
        try:
            out = cli_execute("show version | include Cisco IOS XE Software")
            return out.strip().split(",")[-1].strip() or "unknown"
        except Exception:
            return "unknown"

    def model():
        # Hardware model (e.g. C9300-48UXM / IE-3400-8T2S) for the swarm map.
        return flash_target.device_model(_show("show version"))

    return Deps(catalog=catalog, emit=emit, ios=ios, aria_add=aria_add,
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
                io_transfer=(_mode == "container"))


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
    try:
        with open(state_path) as f:
            state = json.load(f)
    except Exception:
        state = {}
    deps = build_deps(cfg, conf_path)
    result = run_once(cfg, deps, state)
    try:
        with open(state_path, "w") as f:
            json.dump(state, f)
    except Exception:
        pass
    print(result)


if __name__ == "__main__":
    if "--once" in sys.argv or len(sys.argv) == 1:
        main()
