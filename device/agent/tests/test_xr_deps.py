# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The IOS-XR appmgr-container Deps builder.

The XR agent runs `run_once` byte-identically; everything platform-specific
lives behind the same 26-field Deps contract the IOS-XE builder fills. What
makes XR different is that its stage dir IS its final dir: the container
bind-mounts /misc/disk1 (== `harddisk:`) at /hostmount and aria2c downloads
straight to the file's final location, so placement degenerates to an
attest-in-place stat and every device fact is a plain filesystem call. There
is no CLI transport on this platform at all.

These tests drive the real module against a real temporary directory — the
mount is the only thing to fake, and faking a filesystem would prove less
than using one.
"""

import json
import os
import subprocess
import tempfile
import time as _time

import iris_agent
import telemetry_report
import xr_deps


def _emitter():
    lines = []
    return lines, (lambda mnemonic, msg: lines.append((mnemonic, msg)))


def _mnemonics(lines):
    return [m for m, _ in lines]


# A real (throwaway, self-signed) CA file so _cfg()'s default catalog_ca takes
# make_catalog_context's VERIFYING branch instead of its fail-closed one (#12):
# these tests exercise xr_deps' own wiring, not catalog TLS itself (that's
# test_catalog_tls.py's job). Generated once, outside any tmp_path a test
# might assert exact directory contents against (_cfg's `mount` doubles as
# stage_dir for several tests).
_CA_DIR = tempfile.mkdtemp(prefix="iris-xr-deps-test-ca-")
_CA_FILE = os.path.join(_CA_DIR, "iris-catalog.pem")
subprocess.run(
    ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
     "-keyout", os.path.join(_CA_DIR, "key.pem"), "-out", _CA_FILE,
     "-subj", "/CN=iris-xr-deps-tests"],
    check=True, capture_output=True)


def _cfg(mount, **extra):
    cfg = {"device_id": "8010-R1", "catalog_url": "https://10.0.0.1:8443",
           "catalog_token": "t", "stage_dir": str(mount),
           "target_fs": "harddisk:", "mode": "xr", "rpc_port": "6800",
           "rpc_secret": "s", "max_peers": "10", "catalog_ca": _CA_FILE,
           "token_expires_at": str(int(_time.time()) + 604_800)}
    cfg.update(extra)
    return cfg


def _write(path, size, byte=b"x"):
    with open(path, "wb") as f:
        f.write(byte * size)
    return str(path)


# --- copy_to_root: attest in place ---------------------------------------

def test_copy_to_root_attests_the_file_already_at_its_final_location(tmp_path):
    """Write-through is hardware-proven: aria2c downloaded the image THROUGH
    the bind mount, so the bytes are already at harddisk:. Placement is
    therefore a stat that confirms presence and the catalog's exact byte
    size — nothing is copied, and the success emit says so honestly."""
    _write(tmp_path / "8000-x64.iso", 2048)
    lines, emit = _emitter()
    assert xr_deps.attest_in_place(str(tmp_path), "8000-x64.iso", 2048,
                                   emit) is True
    assert "ROOTCOPY" in _mnemonics(lines)
    message = dict(lines)["ROOTCOPY"]
    assert "2048" in message and "harddisk:" in message


def test_copy_to_root_is_false_when_the_file_is_missing(tmp_path):
    """No file at the mount means nothing was placed. False (not the
    running-image sentinel): the normal retry machinery re-downloads."""
    lines, emit = _emitter()
    assert xr_deps.attest_in_place(str(tmp_path), "gone.iso", 10, emit) is False
    assert "ROOTCOPY-FAIL" in _mnemonics(lines)


def test_copy_to_root_is_false_on_a_short_file_and_leaves_it_alone(tmp_path):
    """A truncated file must never pass as placed. The partial is LEFT on
    disk: aria2 resumes it on the next tick, and deleting bytes the swarm
    already fetched would be pure loss."""
    staged = _write(tmp_path / "part.iso", 5)
    lines, emit = _emitter()
    assert xr_deps.attest_in_place(str(tmp_path), "part.iso", 4096,
                                   emit) is False
    message = dict(lines)["ROOTCOPY-FAIL"]
    assert "5" in message and "4096" in message
    assert os.path.exists(staged)


def test_copy_to_root_without_a_catalog_size_falls_back_to_presence(tmp_path):
    """expected_size=None keeps the presence-only contract _agent_reverify_root
    offers callers that have no catalog size to check against."""
    _write(tmp_path / "img.iso", 3)
    lines, emit = _emitter()
    assert xr_deps.attest_in_place(str(tmp_path), "img.iso", None, emit) is True
    assert "ROOTCOPY" in _mnemonics(lines)


def test_copy_to_root_returns_a_plain_bool_never_a_sentinel(tmp_path):
    """The running-image sentinels exist for a destructive IOS `copy` that
    could overwrite the running image. XR places nothing and deletes nothing,
    so both verdicts are plain booleans and no attempt is ever refused
    pre-transport."""
    _write(tmp_path / "img.iso", 8)
    _, emit = _emitter()
    ok = xr_deps.attest_in_place(str(tmp_path), "img.iso", 8, emit)
    missing = xr_deps.attest_in_place(str(tmp_path), "no.iso", 8, emit)
    for verdict in (ok, missing):
        assert verdict is not iris_agent.ROOT_COPY_RUNNING_IMAGE_UNKNOWN
        assert verdict is not iris_agent.ROOT_COPY_NOT_ATTEMPTED
        assert isinstance(verdict, bool)


# --- root_present: a stat, with the XE tri-state semantics ---------------

def test_root_present_confirms_presence_and_exact_size(tmp_path):
    _write(tmp_path / "img.iso", 100)
    assert xr_deps.root_present(str(tmp_path), "img.iso", 100) is True
    assert xr_deps.root_present(str(tmp_path), "img.iso", None) is True


def test_root_present_is_false_when_absent_or_short(tmp_path):
    _write(tmp_path / "img.iso", 99)
    assert xr_deps.root_present(str(tmp_path), "img.iso", 100) is False
    assert xr_deps.root_present(str(tmp_path), "other.iso", 100) is False


def test_root_present_assumes_present_when_the_mount_cannot_answer(tmp_path):
    """XE returns True when the `dir` read itself raises, so one flaky tick
    cannot trigger a multi-GB re-download. A stat that fails for any reason
    other than "not there" gets the same benefit of the doubt."""
    def boom(_path):
        raise OSError("EIO")

    assert xr_deps.root_present(str(tmp_path), "img.iso", 100,
                                stat_fn=boom) is True


# --- free space: statvfs on the mount ------------------------------------

def test_free_bytes_reads_the_mount_with_statvfs(tmp_path):
    class Result:
        f_bavail = 7
        f_frsize = 4096

    assert xr_deps.free_bytes(str(tmp_path),
                              statvfs_fn=lambda p: Result()) == 7 * 4096


def test_free_bytes_is_zero_when_the_mount_cannot_be_read(tmp_path):
    """Heartbeat display value: 0 rather than a raise, exactly like the XE
    reader's parse failure. The gates re-measure through target_fs()."""
    def boom(_path):
        raise OSError("ENOENT")

    assert xr_deps.free_bytes(str(tmp_path), statvfs_fn=boom) == 0


def test_free_bytes_is_a_real_reading_on_a_real_directory(tmp_path):
    assert xr_deps.free_bytes(str(tmp_path)) > 0


# --- reclaim: only what IRIS can prove it placed -------------------------

def test_reclaim_bundle_deletes_named_files_and_tolerates_the_missing(tmp_path):
    doomed = _write(tmp_path / "old.iso", 10)
    _, emit = _emitter()
    xr_deps.reclaim_bundle(str(tmp_path), ["old.iso", "never-there.iso"], emit)
    assert not os.path.exists(doomed)


def test_reclaim_bundle_refuses_a_name_that_leaves_the_mount(tmp_path):
    """The mount is the operator's harddisk: root. A delete primitive that
    accepted a path fragment could reach anywhere on the router, so anything
    that is not a plain basename is refused, loudly, and deleted by nobody."""
    outside = _write(tmp_path / "outside.iso", 10)
    lines, emit = _emitter()
    xr_deps.reclaim_bundle(str(tmp_path), ["../outside.iso", "sub/x.iso"], emit)
    assert os.path.exists(outside)
    assert _mnemonics(lines) == ["RECLAIM-FAIL", "RECLAIM-FAIL"]


def test_reclaim_bundle_reports_a_delete_that_failed(tmp_path):
    lines, emit = _emitter()

    def boom(_path):
        raise OSError("EPERM")

    xr_deps.reclaim_bundle(str(tmp_path), ["x.iso"], emit, remove_fn=boom)
    assert _mnemonics(lines) == ["RECLAIM-FAIL"]


def test_reclaimable_offers_only_files_state_records_iris_as_having_placed(tmp_path):
    """The XR mount is shared with the operator: no filename pattern there is
    provably IRIS's. The agent's own state is the only proof of ownership, so
    a file is reclaimable only when state says IRIS placed it, it is really on
    the mount, and the caller's protect set does not spare it. A PARKED
    image's copy is offered — that is the parked-aware _protect_set contract:
    kept until another image needs the room."""
    _write(tmp_path / "parked.iso", 10)
    _write(tmp_path / "current.iso", 10)
    _write(tmp_path / "operator-owned.iso", 10)
    _write(tmp_path / "8000-x64-26.2.1.iso", 10)
    state = {"img-parked": {"root_file": "parked.iso", "parked": True},
             "img-current": {"root_file": "current.iso"},
             "img-gone": {"root_file": "already-deleted.iso"}}
    protect = {"current.iso"}
    assert xr_deps.reclaimable(str(tmp_path), protect, state) == ["parked.iso"]


def test_reclaimable_is_empty_without_state(tmp_path):
    _write(tmp_path / "anything.iso", 10)
    assert xr_deps.reclaimable(str(tmp_path), set(), {}) == []


# --- purge_others: never sweeps a bare file off the operator's root ------

def test_purge_others_deletes_only_iris_sidecars_outside_the_assigned_set(tmp_path):
    """On IOS-XE the stage dir is IRIS's own directory, so the sweep may drop
    stale `.bin` files. Here the stage dir IS `harddisk:` — the operator's
    root — and only the aria2/torrent/receipt sidecars carry proof of IRIS
    ownership. A bare image file is never swept: the one IRIS placed is
    removed through run_once's state-tracked pending_root_deletes instead."""
    keep = "keep.iso"
    _write(tmp_path / keep, 10)
    _write(tmp_path / (keep + ".aria2"), 1)
    _write(tmp_path / "keep-id.torrent", 1)
    _write(tmp_path / ("stale.iso" + telemetry_report.RECEIPT_SIDECAR_SUFFIX), 1)
    _write(tmp_path / "stale.iso.aria2", 1)
    _write(tmp_path / "stale-id.torrent", 1)
    operator = _write(tmp_path / "operator-8000-x64.iso", 10)
    operator_bin = _write(tmp_path / "operator.bin", 10)
    stale_image = _write(tmp_path / "stale.iso", 10)

    calls = []

    def rpc(method, params):
        calls.append((method, params))
        if method == "aria2.tellActive":
            return [{"gid": "keep-gid", "files": [{"path": "/hostmount/" + keep}]},
                    {"gid": "stale-gid",
                     "files": [{"path": "/hostmount/stale.iso"}]}]
        return []

    xr_deps.purge_others(str(tmp_path), [keep], ["keep-id"], rpc=rpc)

    remaining = sorted(os.listdir(tmp_path))
    assert remaining == sorted([keep, keep + ".aria2", "keep-id.torrent",
                                "operator-8000-x64.iso", "operator.bin",
                                "stale.iso"])
    assert os.path.exists(operator) and os.path.exists(operator_bin)
    assert os.path.exists(stale_image)
    # the download outside the assigned set is dropped from aria2; the kept
    # one is left running
    removed = [params[0] for method, params in calls
               if method == "aria2.forceRemove"]
    assert removed == ["stale-gid"]


# --- the assembled Deps ---------------------------------------------------

def _build(tmp_path, **extra):
    cfg = _cfg(tmp_path, **extra)
    return cfg, xr_deps.build_deps(cfg, str(tmp_path / "iris-agent.conf"),
                                   str(tmp_path / "iris-agent.state"))


def test_build_deps_fills_every_field_of_the_deps_contract(tmp_path):
    """All 27 fields, or run_once dies mid-tick on an attribute nobody
    noticed was missing."""
    _cfg_out, deps = _build(tmp_path)
    assert len(iris_agent.Deps._fields) == 27
    for field in iris_agent.Deps._fields:
        assert getattr(deps, field) is not None, field


def test_build_deps_reports_the_xr_platform_facts(tmp_path):
    """target_fs is fixed (`harddisk:` is the only writable target an appmgr
    container has) but its free reading is measured NOW, per tick, because XR
    free space varies per platform and deployment."""
    _cfg_out, deps = _build(tmp_path)
    prefix, free = deps.target_fs()
    assert prefix == "harddisk:"
    assert free > 0
    assert deps.detect_mode() == "xr"
    assert deps.free_bytes("harddisk:") > 0


def test_build_deps_never_doubles_the_space_requirement(tmp_path):
    """io_transfer doubles both space gates for platforms whose placement
    transits an intermediate copy. XR's stage dir IS its final dir, so one
    image needs one image's worth of room."""
    _cfg_out, deps = _build(tmp_path)
    assert deps.io_transfer is False


def test_build_deps_charges_nothing_for_the_root_copy_gate(tmp_path):
    """copy_in_place=True: attest_in_place writes no new bytes, so the
    flash-root copy gate (iris_agent.py) must not charge XR a second
    image's worth of headroom it never needs (F2 -- a device with room for
    exactly one image must not sit in flash_full_seeding_only forever)."""
    _cfg_out, deps = _build(tmp_path)
    assert deps.copy_in_place is True


def test_build_deps_reads_identity_from_conf_and_never_guesses(tmp_path):
    """model/version/running_image are recorded by the onboard. There is no
    CLI on this platform to ask, and a guessed running image would authorise
    destructive work — so an unrecorded value stays honestly unknown."""
    _cfg_out, deps = _build(tmp_path, device_model="8201",
                            device_version="25.4.2 LNT",
                            running_image="8000-x64-25.4.2.iso")
    assert deps.model() == "8201"
    assert deps.version() == "25.4.2 LNT"
    assert deps.running_image() == "8000-x64-25.4.2.iso"

    _cfg_out, blank = _build(tmp_path)
    assert blank.model() is None
    assert blank.version() == "unknown"
    assert blank.running_image() is None


def test_build_deps_labels_its_telemetry_runtime_mode(tmp_path):
    """telemetry_report reads runtime_mode straight from cfg and defaults to
    'guestshell'. An XR container reporting 'guestshell' would be a lie in
    every report, so the builder stamps its own label."""
    cfg, _deps = _build(tmp_path)
    assert cfg["runtime_mode"] == "xr-container"


def test_build_deps_keeps_an_operator_configured_runtime_mode(tmp_path):
    cfg, _deps = _build(tmp_path, runtime_mode="xr-lab")
    assert cfg["runtime_mode"] == "xr-lab"


def test_build_deps_emit_writes_an_iris_syslog_line_and_never_raises(tmp_path, capsys):
    """There is no IOS vty to `send log` through from an appmgr container, so
    the mnemonic vocabulary operators grep for goes to the container log
    appmgr captures. Never raises: a failed emit must not abort the tick."""
    _cfg_out, deps = _build(tmp_path)
    deps.emit("ROOTCOPY", "8000-x64.iso placed — done")
    out = capsys.readouterr().out
    assert "%IRIS-6-ROOTCOPY" in out
    assert "8000-x64.iso" in out


def test_build_deps_checkpoint_persists_state_durably(tmp_path):
    _cfg_out, deps = _build(tmp_path)
    deps.checkpoint({"seq": 7})
    with open(str(tmp_path / "iris-agent.state")) as f:
        assert json.load(f) == {"seq": 7}


def test_build_deps_file_size_verify_and_remove_stage_are_the_shared_ones(tmp_path):
    _cfg_out, deps = _build(tmp_path)
    staged = _write(tmp_path / "img.iso", 12)
    assert deps.file_size(staged) == 12
    assert deps.file_size(str(tmp_path / "nope.iso")) is None
    import hashlib
    assert deps.verify(staged, hashlib.sha256(b"x" * 12).hexdigest()) is True
    deps.remove_stage(staged)
    assert not os.path.exists(staged)
    deps.remove_stage(staged)          # best-effort: a second call is a no-op


def test_build_deps_reclaim_is_a_documented_no_op(tmp_path):
    """`install remove inactive` is an IOS-XE package-manager action. XR's
    install manager owns boot state on this box, so v1 reclaims nothing
    automatically — run_once's mode='xr' never asks it to."""
    _cfg_out, deps = _build(tmp_path)
    assert deps.reclaim() is None


def test_build_deps_ios_escape_hatch_refuses_instead_of_pretending(tmp_path):
    """deps.ios is dead in run_once and there is no CLI here. Raising beats
    returning "" — a caller that grew a dependency on it must find out."""
    _cfg_out, deps = _build(tmp_path)
    try:
        deps.ios("show version")
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "IOS-XR" in str(exc)


# --- the dispatch in iris_agent.build_deps -------------------------------

def test_iris_agent_build_deps_dispatches_xr_mode_to_this_module(tmp_path, monkeypatch):
    """The one hook in iris_agent: conf `mode = xr` (written by
    device/xr/entrypoint.sh) selects this builder. Every other mode keeps the
    IOS-XE wiring untouched."""
    seen = {}

    def fake(cfg, conf_path, state_path=None):
        seen["cfg"] = cfg
        return "xr-deps"

    monkeypatch.setattr(xr_deps, "build_deps", fake)
    cfg = _cfg(tmp_path)
    assert iris_agent.build_deps(cfg, "/conf", "/state") == "xr-deps"
    assert seen["cfg"] is cfg


def test_iris_agent_build_deps_leaves_other_modes_alone(monkeypatch):
    """A conf without `mode = xr` must never reach the XR builder."""
    def fake(*_a, **_k):
        raise AssertionError("XR builder called for a non-XR mode")

    monkeypatch.setattr(xr_deps, "build_deps", fake)
    for mode in ("", "container", "guestshell", None):
        cfg = {"mode": mode} if mode is not None else {}
        try:
            iris_agent.build_deps(cfg, "/conf", "/state")
        except Exception as exc:            # the IOS-XE wiring needs a device
            assert "XR builder" not in str(exc)


# --- run_once over the real XR deps --------------------------------------

class _Catalog:
    """Just enough catalog for one tick; the seam under test is the deps."""

    def __init__(self, image):
        self.image = image
        self.heartbeats = []

    def get_policy(self, _sid):
        return {"approved_image_id": self.image["id"], "telemetry": "off"}

    def get_image(self, image_id):
        return self.image if image_id == self.image["id"] else None

    def heartbeat(self, _sid, payload):
        self.heartbeats.append(payload)
        return {}


def test_run_once_completes_a_tick_against_the_real_xr_deps(tmp_path):
    """End to end over the actual module: a fully downloaded image sitting on
    the mount is hashed, attested in place, and reported ready — with no copy
    step, no CLI, and harddisk: as the target filesystem."""
    import hashlib
    body = b"y" * 256
    _write(tmp_path / "8000-x64-26.2.1.iso", 256, b"y")
    image = {"id": "img-1", "filename": "8000-x64-26.2.1.iso", "size": 256,
             "sha256": hashlib.sha256(body).hexdigest()}
    catalog = _Catalog(image)
    cfg, deps = _build(tmp_path)
    deps = deps._replace(catalog=catalog, aria_stats=lambda p: None,
                         aria_peers=lambda p: [], aria_session=lambda: None)
    state = {}
    assert iris_agent.run_once(cfg, deps, state) == "complete"
    assert state["img-1"]["copied"] is True
    assert state["stage_fs"] == "harddisk:"
    hb = catalog.heartbeats[-1]
    assert hb["stage_state"] == "ready"
    assert hb["target_fs"] == "harddisk:"
    assert hb["free_flash_bytes"] > 0
