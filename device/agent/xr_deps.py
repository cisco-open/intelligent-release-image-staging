# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Deps wiring for the IRIS agent running as an IOS-XR appmgr Docker app.

`run_once()` is platform-neutral and fully injected, so a new platform is a
second `build_deps()` — never a fork of the control loop. This is that second
builder, for a Cisco 8000-series router (IOS-XR 25.x) where the agent runs in
an appmgr container activated with `-td --net=host -v /misc/disk1:/hostmount`.

What makes XR simpler than every IOS-XE platform: `/misc/disk1` IS `harddisk:`
and a write inside the container appears there immediately (hardware-proven,
`agentinfo/xr-support/LAB-RESULTS-2026-08-27.md` and its 2026-08-28 addendum).
aria2c therefore downloads each image STRAIGHT to its final location, so:

  * there is no placement step. `copy_to_root` degenerates to attesting the
    bytes already at the target — a `stat` for presence and the catalog's
    exact size. Nothing is copied, so nothing can be half-copied, and no
    running image can be overwritten by it.
  * `io_transfer` is False: one image needs one image's worth of room, not
    two, at the pre-download staging gate.
  * `copy_in_place` is True: the flash-root copy gate must not charge a
    SECOND image's worth of headroom either — attest_in_place writes no new
    bytes, so a device with room for exactly one image must not sit in
    flash_full_seeding_only forever waiting for room that was never needed.
  * every device fact is a filesystem call. There is NO CLI transport on this
    platform — no Guest Shell `cli`, no SSH-to-self, no EEM applets. The
    facts a CLI used to supply (model, version, running image) are recorded
    by the onboard into the agent conf, and an unrecorded fact stays
    honestly unknown rather than being guessed.

Deliberate parity deviations, each with its reason:

  * `emit` writes the `%IRIS-6-<MNEMONIC>` line to the container log appmgr
    captures instead of device syslog: reaching `show logging` from an
    appmgr container is unproven, and inventing a CLI transport just to log
    would undo the simplicity above.
  * `reclaim` does nothing and `reclaimable` offers only files the agent's
    own state proves IRIS placed. The mount is the operator's `harddisk:`
    root, shared with the XR install manager, so no filename pattern there
    is provably IRIS's. v1 reclaims nothing automatically.

Stdlib only, like every other agent module.
"""

import base64
import glob
import json
import os
import sys
import urllib.request

import iris_agent
import telemetry_report
import verify_image

# The bind mount, and the IOS-visible name of the same filesystem. Both are
# fixed by the activation line device/xr-install.sh commits; the conf carries
# them so a lab run can point the agent somewhere else without editing code.
STAGE_DEFAULT = "/hostmount"
TARGET_FS = "harddisk:"
# detect_mode()'s answer. _reclaim_for_mode understands "install" and
# "bundle" and skips anything else, which is exactly the reclaim-none
# behaviour v1 wants (see the module docstring).
MODE = "xr"
# telemetry_report reads runtime_mode straight from cfg and defaults it to
# "guestshell"; an XR container must not report that.
RUNTIME_MODE = "xr-container"

# Sidecars whose NAME proves IRIS (or its aria2) wrote them. Everything else
# at the mount is presumed to be the operator's.
_OWNED_SUFFIXES = (".torrent", ".aria2", telemetry_report.RECEIPT_SIDECAR_SUFFIX)


def attest_in_place(stage_dir, fname, expected_size, emit,
                    stat_fn=os.stat):
    """The XR `copy_to_root`: confirm the download already sitting at its
    final location is whole.

    Returns True when the file is present and — when the catalog declared a
    size — exactly that size. Returns plain False otherwise, which is the
    honest verdict here: run_once burns one of its four attempts and the
    normal machinery re-downloads. The two running-image sentinels do NOT
    apply on this platform: no attempt of ours deletes or overwrites
    anything, so there is no partial-of-unknown-ownership to reason about
    and no destructive command to refuse.

    A short file is LEFT ALONE. aria2 resumes it on the next tick; throwing
    away bytes the swarm already delivered would be pure loss."""
    path = os.path.join(stage_dir, fname)
    try:
        observed = stat_fn(path).st_size
    except OSError as exc:
        emit("ROOTCOPY-FAIL",
             "%s is not at %s (%s): nothing to attest" % (fname, TARGET_FS, exc))
        return False
    if expected_size is not None and observed != expected_size:
        emit("ROOTCOPY-FAIL",
             "%s at %s is %d bytes, catalog says %d - partial download, not "
             "placed" % (fname, TARGET_FS, observed, expected_size))
        return False
    if expected_size is None:
        emit("ROOTCOPY", "%s present at %s" % (fname, TARGET_FS))
    else:
        emit("ROOTCOPY", "%s written straight to %s, size verified (%d bytes)"
             % (fname, TARGET_FS, expected_size))
    return True


def root_present(stage_dir, fname, expected_size=None, stat_fn=os.stat):
    """Steady-state presence check, with the IOS-XE tri-state semantics kept:
    absent or the wrong size -> False (re-acquire); present -> True; and a
    stat that fails for any OTHER reason -> True, because one flaky tick must
    not trigger a multi-gigabyte re-download."""
    try:
        observed = stat_fn(os.path.join(stage_dir, fname)).st_size
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if expected_size is None:
        return True
    return observed == expected_size


def free_bytes(stage_dir, statvfs_fn=os.statvfs):
    """Free bytes on the mount. f_bavail (not f_bfree) so a reserved-block
    filesystem never promises room the agent cannot actually use. 0 on any
    failure, mirroring the XE reader's parse-failure answer — the space gates
    re-measure through target_fs() before they act."""
    try:
        st = statvfs_fn(stage_dir)
    except OSError:
        return 0
    return int(st.f_bavail) * int(st.f_frsize)


def reclaim_bundle(stage_dir, names, emit, remove_fn=os.remove):
    """Delete named files from the mount. Best-effort per name so one failure
    cannot strand the rest; callers re-verify with root_present.

    Only ever called with names the agent can prove it placed — run_once's
    state-tracked pending_root_deletes and its failed-placement reclaim. The
    mount is the operator's `harddisk:` root, so anything that is not a plain
    basename is refused rather than resolved: a delete primitive here must
    not be able to address a path outside the directory it was given."""
    for name in names:
        if not name or name != os.path.basename(name) or name in (".", ".."):
            emit("RECLAIM-FAIL",
                 "refusing to delete %r: not a plain filename on %s"
                 % (name, TARGET_FS))
            continue
        try:
            remove_fn(os.path.join(stage_dir, name))
        except FileNotFoundError:
            pass
        except OSError as exc:
            emit("RECLAIM-FAIL",
                 "%s%s delete failed: %s" % (TARGET_FS, name, exc))


def reclaimable(stage_dir, protect, state):
    """Files on the mount that IRIS may delete to free room.

    The XE allowlist (`cat9k*.bin` and friends) matches nothing here and
    could not be trusted if it did: `harddisk:` is the operator's directory
    and the XR install manager may reference files in it. The agent's own
    state is the only proof of ownership, so a file qualifies only when
    state records IRIS as having placed it, it is really on the mount, and
    the caller's protect set does not spare it. A PARKED image's copy is
    offered on purpose — that is the parked-aware `_protect_set` contract:
    an unchecked image's file is kept until another image needs the room.

    NOTE: run_once's `_reclaim_for_mode` acts on modes "install" and
    "bundle" only, and detect_mode() answers "xr", so nothing calls this
    today (v1 ships reclaim-none; a full mount degrades to `flash_full`
    heartbeats and an operator reclaims by hand). It is written to the
    contract rather than stubbed so the behaviour is right if the mode
    vocabulary ever grows."""
    placed = set()
    for value in (state or {}).values():
        if isinstance(value, dict) and value.get("root_file"):
            placed.add(value["root_file"])
    root_file = (state or {}).get("root_file")
    if root_file:
        placed.add(root_file)
    return sorted(name for name in placed
                  if name not in protect
                  and os.path.isfile(os.path.join(stage_dir, name)))


def purge_others(stage_dir, keep_filenames, keep_ids, rpc=None):
    """Reassignment hygiene: drop every aria2 download outside the assigned
    SET, then delete the stale IRIS sidecars left behind.

    Divergence from the IOS-XE sweep, and the reason for it: there the stage
    dir is IRIS's own directory, so dropping stale `*.bin` files is safe.
    Here the stage dir IS `harddisk:` — full of operator files — and only the
    torrent/aria2/receipt sidecars carry proof of IRIS ownership. Image files
    are therefore never swept by name; the one IRIS itself placed is removed
    through run_once's state-tracked pending_root_deletes, which knows it was
    ours."""
    keep_filenames = list(keep_filenames)
    if rpc is not None:
        for gid, names in iris_agent._aria_downloads(rpc):
            if not any(k in names for k in keep_filenames):
                iris_agent._aria_drop(rpc, gid)
    keep = set()
    for keep_filename in keep_filenames:
        keep.update((keep_filename, keep_filename + ".aria2",
                     keep_filename + telemetry_report.RECEIPT_SIDECAR_SUFFIX))
    keep.update(keep_id + ".torrent" for keep_id in keep_ids)
    for path in glob.glob(os.path.join(stage_dir, "*")):
        base = os.path.basename(path)
        if base in keep or not base.endswith(_OWNED_SUFFIXES):
            continue
        try:
            os.remove(path)
        except OSError:
            pass


def emit_impl(mnemonic, msg, stream=None):
    """The operator log line. Same `%IRIS-6-<MNEMONIC>` vocabulary the IOS-XE
    agent sends to device syslog, written to the container's stdout — what
    appmgr captures for this app. NEVER raises: a failed emit must not abort
    the tick or mask the fault it was reporting. ASCII-forced so the text is
    byte-identical to the IOS-XE line for the same event."""
    try:
        line = "%%IRIS-6-%s: %s" % (mnemonic, msg)
        (stream or sys.stdout).write(
            line.encode("ascii", "replace").decode() + "\n")
        (stream or sys.stdout).flush()
    except Exception:
        pass


def build_deps(cfg, conf_path, state_path=None):
    """Assemble the 27-field Deps for the XR container.

    Catalog, aria2, telemetry and checkpoint wiring is the same work the
    IOS-XE builder does — the module-level impls it already factored out are
    reused here, and the few remaining closures (the JSON-RPC caller and its
    aria2 wrappers) are the same handful of lines because the contract is
    identical. What differs is entirely in the device-facing fields above."""
    stage_dir = cfg.get("stage_dir") or STAGE_DEFAULT
    target_prefix = (cfg.get("target_fs") or "").strip() or TARGET_FS
    # Stamp the platform's telemetry label unless an operator set one.
    if not (cfg.get("runtime_mode") or "").strip():
        cfg["runtime_mode"] = RUNTIME_MODE

    def emit(mnemonic, msg):
        emit_impl(mnemonic, msg)

    # Defined before the catalog context, whose fail-closed path (#12) calls
    # straight back into emit -- synchronously, if catalog_ca is unset -- so
    # emit must already exist in this scope (see iris_agent.build_deps' own
    # fix for the NameError this ordering avoids).
    import catalog_client
    ctx = iris_agent.make_catalog_context(cfg, lambda m: emit("TLS-ERROR", m))
    catalog = catalog_client.CatalogClient(
        cfg["catalog_url"], cfg["catalog_token"], context=ctx)

    def refresh():
        return iris_agent._refresh_impl(cfg, conf_path, catalog.refresh_token,
                                        emit)

    def _rpc(method, params):
        payload = json.dumps({"jsonrpc": "2.0", "id": "p", "method": method,
                              "params": ["token:" + cfg["rpc_secret"]] + params}
                             ).encode()
        req = urllib.request.Request(
            "http://127.0.0.1:%s/jsonrpc" % cfg["rpc_port"], data=payload,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode()).get("result", [])

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

    def aria_remove(filename):
        for gid, names in iris_agent._aria_downloads(_rpc):
            if filename in names:
                iris_agent._aria_drop(_rpc, gid)

    def ios(cmd):
        raise RuntimeError(
            "no CLI transport exists in the IOS-XR appmgr container "
            "(asked for %r)" % cmd)

    def target_fs():
        # Fixed prefix, free space measured NOW: XR free space varies by
        # platform and deployment, and both space gates act on this reading.
        return target_prefix, free_bytes(stage_dir)

    def _conf_fact(key, env_key):
        # Recorded by the onboard; never probed, never guessed.
        return (os.environ.get(env_key) or cfg.get(key) or "").strip()

    return iris_agent.Deps(
        catalog=catalog, emit=emit, ios=ios, aria_add=aria_add,
        file_size=lambda p: os.path.getsize(p) if os.path.exists(p) else None,
        verify=lambda p, sha: verify_image.sha256_matches(p, sha),
        free_bytes=lambda prefix=TARGET_FS: free_bytes(stage_dir),
        version=lambda: _conf_fact("device_version", "IRIS_DEVICE_VERSION")
                        or "unknown",
        copy_to_root=lambda fname, target=TARGET_FS, expected_size=None:
            attest_in_place(stage_dir, fname, expected_size, emit),
        purge_others=lambda keep_filenames, keep_ids:
            purge_others(stage_dir, keep_filenames, keep_ids, rpc=_rpc),
        reclaim=lambda: None,
        root_present=lambda fname, prefix=TARGET_FS, expected_size=None:
            root_present(stage_dir, fname, expected_size),
        remove_stage=_remove_stage,
        aria_remove=aria_remove,
        detect_mode=lambda: MODE,
        target_fs=target_fs,
        running_image=lambda: _conf_fact("running_image",
                                         "IRIS_RUNNING_IMAGE") or None,
        reclaimable=lambda target, protect: reclaimable(
            stage_dir, protect, _load_state(state_path)),
        reclaim_bundle=lambda target, names: reclaim_bundle(stage_dir, names,
                                                            emit),
        model=lambda: _conf_fact("device_model", "IRIS_DEVICE_MODEL") or None,
        refresh=refresh,
        aria_stats=lambda stage_path: iris_agent._aria_stats_impl(_rpc,
                                                                  stage_path),
        aria_peers=lambda stage_path: iris_agent._aria_peers_impl(_rpc,
                                                                  stage_path),
        io_transfer=False,
        checkpoint=lambda state: iris_agent._atomic_write_state(state_path,
                                                                state),
        aria_session=lambda: iris_agent._aria_session_impl(_rpc),
        # attest_in_place stats the bytes already at stage_dir -- the copy
        # gate must not charge headroom for a root copy this platform never
        # writes (see the gate's comment in iris_agent.py for the incident
        # this closes: a device that fit exactly one image sat in
        # flash_full_seeding_only forever).
        copy_in_place=True)


def _remove_stage(path):
    try:
        os.remove(path)
    except OSError:
        pass


def _load_state(state_path):
    """The persisted state, for reclaimable()'s ownership proof. Never
    raises: an unreadable state file means nothing is provably IRIS's, which
    is the safe answer."""
    try:
        with open(state_path) as f:
            return json.load(f)
    except Exception:
        return {}
