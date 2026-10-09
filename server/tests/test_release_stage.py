# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Authentication/export is separate from exact-byte manual publication."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location("release_stage", ROOT / "tools/release-stage.py")
STAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGE)
TAG, COMMIT = "v2026.10.09", "a" * 40


def sha(data):
    return hashlib.sha256(data).hexdigest()


def packed(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return output.getvalue()


def inventory(files):
    return {name: {"sha256": sha(data), "size": len(data)} for name, data in files.items()}


@pytest.fixture
def stage(tmp_path, monkeypatch):
    files = {name: ("fixture bytes for " + name).encode() for name in STAGE._source_assets(TAG)}
    files["release-stage.json"] = STAGE._canonical(STAGE._stage_record(TAG, COMMIT, 31, 2))
    manifest = {"schema": 1, "repository": STAGE.REPOSITORY, "workflow": STAGE.WORKFLOW,
                "tag": TAG, "commit": COMMIT, "assets": inventory(files)}
    files["release.json"] = STAGE._canonical(manifest)
    files["SHA256SUMS"] = "".join(sha(files[name]) + "  " + name + "\n" for name in sorted(files)).encode()
    files["attestations.jsonl"] = b"fixture bundle; signatures are mocked, never real authentication\n"
    archive = packed(files)
    selected = STAGE.selection(TAG, COMMIT, 31, 2, 47, sha(archive))
    repo = {"full_name": STAGE.REPOSITORY, "id": 91}
    run = {"id": 31, "run_attempt": 2, "path": ".github/workflows/release.yml", "head_sha": COMMIT,
           "event": "push", "status": "completed", "conclusion": "success", "repository": repo,
           "head_repository": dict(repo)}
    artifact = {"id": 47, "name": "iris-authenticated-31-2", "expired": False,
                "digest": "sha256:" + sha(archive), "size_in_bytes": len(archive),
                "workflow_run": {"id": 31, "repository_id": 91, "head_repository_id": 91, "head_sha": COMMIT}}
    value = {"selected": selected, "files": files, "archive": archive, "run": run, "artifact": artifact,
             "output": tmp_path / "verified", "calls": []}
    def api(endpoint, token):
        value["calls"].append((endpoint, token))
        if endpoint == "/git/ref/tags/" + TAG:
            return {"ref": "refs/tags/" + TAG, "object": {"type": "commit", "sha": COMMIT}}
        return value["run"] if "/attempts/" in endpoint else value["artifact"]
    def download(selected, path, size, token):
        path.write_bytes(value["archive"])
        assert size == len(value["archive"])
        assert selected["artifact_sha256"] == sha(value["archive"])
    monkeypatch.setattr(STAGE, "_api", api)
    monkeypatch.setattr(STAGE, "_download", download)
    monkeypatch.setattr(STAGE, "_verify_signature", lambda *args: value["calls"].append(Path(args[0]).name))
    return value


def qualification(stage):
    selected, files = stage["selected"], inventory(stage["files"])
    return {"schema": "iris-release-qualification-v1", "repository": STAGE.REPOSITORY,
            "tag": TAG, "commit": COMMIT, "profile": "source-only",
            "stage": {key: selected[key] for key in ("run_id", "run_attempt", "artifact_id", "artifact_sha256")},
            "release_json_sha256": files["release.json"]["sha256"],
            "sha256sums_sha256": files["SHA256SUMS"]["sha256"],
            "attestations_sha256": files["attestations.jsonl"]["sha256"], "assets": files,
            "release_kit_sha256": None, "candidate_evidence_sha256": None, "image_identities": None,
            "reviewed_by": "reviewer", "checks": {key: {"result": "passed", "evidence_sha256": "b" * 64}
                                                     for key in STAGE.CHECKS}}


def publish(stage, value=None, **kwargs):
    data = STAGE._canonical(value if value is not None else qualification(stage))
    options = {"qualification": data, "qualification_sha256": sha(data), "actor": "dispatcher",
               "actor_id": 17, "triggering_actor": "reviewer",
               "confirmation": "publish " + TAG + " " + sha(stage["files"]["release.json"])}
    options.update(kwargs)
    return STAGE.prepare_publication(stage["selected"], stage["output"], **options)


def replace_files(stage, files):
    stage["files"] = files
    stage["archive"] = packed(files)
    stage["selected"]["artifact_sha256"] = sha(stage["archive"])
    stage["artifact"]["digest"] = "sha256:" + sha(stage["archive"])
    stage["artifact"]["size_in_bytes"] = len(stage["archive"])


def test_acquisition_preserves_exact_flat_files_and_never_executes_them(stage):
    record = STAGE.acquire_stage(stage["selected"], stage["output"], token="test-token")
    assert record["files"] == inventory(stage["files"])
    assert record["selection"] == stage["selected"]
    assert set(path.name for path in stage["output"].iterdir()) == {"assets", "stage-verification.json"}
    for name, data in stage["files"].items():
        path = stage["output"] / "assets" / name
        assert path.read_bytes() == data
        assert stat.S_IMODE(path.stat().st_mode) == 0o400
    assert stat.S_IMODE((stage["output"] / "assets").stat().st_mode) == 0o500
    signatures = [value for value in stage["calls"] if isinstance(value, str)]
    assert signatures[0] == "release.json"
    assert set(signatures) == set(stage["files"]) - {"attestations.jsonl"}
    assert stage["calls"][:2] == [("/actions/runs/31/attempts/2", "test-token"),
                                  ("/actions/artifacts/47", "test-token")]


def test_publication_snapshot_keeps_qualification_outside_signed_asset_set(stage):
    value = qualification(stage)
    record = publish(stage, value)
    assert record["qualification_is_reviewer_statement"] is True
    assert record["dispatch"] == {"actor": "dispatcher", "actor_id": 17, "triggering_actor": "reviewer"}
    assert set(path.name for path in stage["output"].iterdir()) == {"assets", "qualification.json", "publication.json"}
    assert (stage["output"] / "qualification.json").read_bytes() == STAGE._canonical(value)
    assert inventory({name: (stage["output"] / "assets" / name).read_bytes() for name in stage["files"]}) == record["files"]


@pytest.mark.parametrize("field,value", [("id", True), ("id", 32), ("run_attempt", 3),
    ("path", ".github/workflows/other.yml"), ("head_sha", "b" * 40), ("event", "workflow_dispatch"),
    ("status", "in_progress"), ("conclusion", "failure"), ("head_repository", {"id": 92, "full_name": STAGE.REPOSITORY})])
def test_run_identity_mismatch_refuses_before_download(stage, field, value, monkeypatch):
    stage["run"][field] = value
    monkeypatch.setattr(STAGE, "_download", lambda *args: pytest.fail("must not download"))
    with pytest.raises(STAGE.InstallError):
        STAGE.acquire_stage(stage["selected"], stage["output"])
    assert not stage["output"].exists()


@pytest.mark.parametrize("suffix", ["", "@" + TAG, "@refs/tags/" + TAG])
def test_run_path_supports_only_exact_selected_tag_forms(stage, suffix):
    stage["run"]["path"] = ".github/workflows/release.yml" + suffix
    STAGE.acquire_stage(stage["selected"], stage["output"])


@pytest.mark.parametrize("suffix", ["@main", "@refs/heads/main", "@refs/tags/v2026.10.08", "@v2026.10.08", "/../release.yml"])
def test_run_path_rejects_other_refs_and_aliases(stage, suffix):
    stage["run"]["path"] = ".github/workflows/release.yml" + suffix
    with pytest.raises(STAGE.InstallError, match="workflow"):
        STAGE.acquire_stage(stage["selected"], stage["output"])


@pytest.mark.parametrize("field,value", [("id", True), ("id", 48), ("name", "iris-authenticated-31-1"),
    ("expired", True), ("expired", 0), ("digest", "sha256:" + "b" * 64), ("size_in_bytes", True),
    ("workflow_run", {"id": 32, "repository_id": 91, "head_repository_id": 91, "head_sha": COMMIT})])
def test_artifact_identity_mismatch_refuses_before_download(stage, field, value, monkeypatch):
    stage["artifact"][field] = value
    monkeypatch.setattr(STAGE, "_download", lambda *args: pytest.fail("must not download"))
    with pytest.raises(STAGE.InstallError):
        STAGE.acquire_stage(stage["selected"], stage["output"])


@pytest.mark.parametrize("field,value", [("schema", "other"), ("tag", "v2026.10.08"),
    ("commit", "b" * 40), ("profile", "prepared-host"), ("reviewed_by", "other"),
    ("release_kit_sha256", "b" * 64), ("candidate_evidence_sha256", "b" * 64),
    ("image_identities", {}), ("attestations_sha256", "b" * 64)])
def test_qualification_identity_or_scope_mismatch(stage, field, value):
    record = qualification(stage)
    record[field] = value
    with pytest.raises(STAGE.InstallError, match="qualification"):
        publish(stage, record)
    assert not stage["output"].exists()


@pytest.mark.parametrize("change", ["missing", "unknown", "failed", "pending", "bad-evidence", "type", "stage", "asset", "extra"])
def test_qualification_requires_all_exact_checks_and_asset_bytes(stage, change):
    record = qualification(stage)
    check = record["checks"]["lifecycle"]
    if change == "missing":
        del record["checks"]["lifecycle"]
    elif change == "unknown":
        record["checks"]["invented"] = check
    elif change in ("failed", "pending"):
        check["result"] = change
    elif change == "bad-evidence":
        check["evidence_sha256"] = "https://example.invalid/evidence"
    elif change == "type":
        record["stage"]["run_attempt"] = 2.0
    elif change == "stage":
        record["stage"]["artifact_id"] = 48
    elif change == "asset":
        record["assets"]["iris.tgz"]["sha256"] = "b" * 64
    else:
        record["approved"] = True
    with pytest.raises(STAGE.InstallError):
        publish(stage, record)


@pytest.mark.parametrize("kwargs", [{"qualification_sha256": "0" * 64}, {"confirmation": "publish"},
    {"confirmation": "publish " + TAG + " " + "b" * 64}, {"actor_id": True},
    {"qualification": b"x" * (STAGE.MAX_QUALIFICATION + 1)}, {"triggering_actor": "bad\nactor"}])
def test_manual_boundary_rejects_changed_hash_confirmation_and_actor(stage, kwargs):
    with pytest.raises(STAGE.InstallError):
        publish(stage, **kwargs)
    assert not stage["output"].exists()


@pytest.mark.parametrize("kind", ["lightweight", "annotated", "nested"])
def test_current_tag_must_resolve_to_exact_qualified_commit(stage, monkeypatch, kind):
    original = STAGE._api
    tag1, tag2 = "c" * 40, "d" * 40
    def api(endpoint, token):
        if endpoint == "/git/ref/tags/" + TAG:
            obj = {"type": "commit", "sha": COMMIT} if kind == "lightweight" else {"type": "tag", "sha": tag1}
            return {"ref": "refs/tags/" + TAG, "object": obj}
        if endpoint == "/git/tags/" + tag1:
            obj = {"type": "tag", "sha": tag2} if kind == "nested" else {"type": "commit", "sha": COMMIT}
            return {"sha": tag1, "object": obj}
        if endpoint == "/git/tags/" + tag2:
            return {"sha": tag2, "object": {"type": "commit", "sha": COMMIT}}
        return original(endpoint, token)
    monkeypatch.setattr(STAGE, "_api", api)
    publish(stage)
    assert stage["output"].is_dir()


@pytest.mark.parametrize("change", ["moved", "wrong-ref", "tree", "cycle", "wrong-object", "too-deep", "missing"])
def test_changed_or_unresolvable_current_tag_cannot_publish(stage, monkeypatch, change):
    original = STAGE._api
    calls = []
    def api(endpoint, token):
        if not endpoint.startswith("/git/"):
            return original(endpoint, token)
        calls.append(endpoint)
        if change == "missing":
            raise STAGE.InstallError("tag unavailable")
        if endpoint.startswith("/git/ref/"):
            obj = {"type": "commit", "sha": "b" * 40 if change == "moved" else COMMIT}
            if change in ("cycle", "wrong-object", "too-deep"):
                obj = {"type": "tag", "sha": "c" * 40}
            if change == "tree":
                obj["type"] = "tree"
            return {"ref": "refs/tags/" + ("v2026.10.08" if change == "wrong-ref" else TAG), "object": obj}
        current = endpoint.rsplit("/", 1)[-1]
        return {"sha": "b" * 40 if change == "wrong-object" else current,
                "object": {"type": "tag", "sha": format(len(calls), "040x") if change == "too-deep" else current}}
    monkeypatch.setattr(STAGE, "_api", api)
    with pytest.raises(STAGE.InstallError):
        publish(stage)
    assert not stage["output"].exists()
    assert len(calls) <= 9


def test_invalid_signature_precedes_parsing_release_and_qualification(stage, monkeypatch):
    files = dict(stage["files"], **{"release.json": b"not json"})
    replace_files(stage, files)
    def reject(*args):
        raise subprocess.CalledProcessError(1, ["gh", "attestation", "verify"])
    monkeypatch.setattr(STAGE, "_verify_signature", reject)
    monkeypatch.setattr(STAGE, "_json", lambda *args: pytest.fail("must not parse claims"))
    with pytest.raises(subprocess.CalledProcessError):
        publish(stage, qualification=b"not JSON")
    assert not stage["output"].exists()


@pytest.mark.parametrize("change", ["bytes", "schema-bool", "size-float", "stage-attempt", "checksums", "unknown", "prebuilt", "missing"])
def test_closed_signed_asset_set_is_exact_and_source_only(stage, change):
    files = dict(stage["files"])
    if change == "bytes":
        files["iris.tgz"] = b"tampered"
    elif change in ("schema-bool", "size-float"):
        manifest = json.loads(files["release.json"])
        if change == "schema-bool":
            manifest["schema"] = True
        else:
            manifest["assets"]["iris.tgz"]["size"] = float(manifest["assets"]["iris.tgz"]["size"])
        files["release.json"] = STAGE._canonical(manifest)
    elif change == "stage-attempt":
        files["release-stage.json"] = STAGE._canonical(STAGE._stage_record(TAG, COMMIT, 31, 1))
        manifest = json.loads(files["release.json"])
        manifest["assets"]["release-stage.json"] = inventory(files)["release-stage.json"]
        files["release.json"] = STAGE._canonical(manifest)
        files["SHA256SUMS"] = "".join(sha(files[name]) + "  " + name + "\n"
            for name in sorted(set(files) - {"SHA256SUMS", "attestations.jsonl"})).encode()
    elif change == "checksums":
        files["SHA256SUMS"] += b"0" * 64 + b"  unknown\n"
    elif change in ("unknown", "prebuilt"):
        files["release-kit.json" if change == "prebuilt" else "unexpected.txt"] = b"{}"
    else:
        del files["iris.tgz"]
    replace_files(stage, files)
    with pytest.raises(STAGE.InstallError):
        STAGE.acquire_stage(stage["selected"], stage["output"])
    assert not stage["output"].exists()


@pytest.mark.parametrize("name", ["../escape", "/absolute", "a/b", ".hidden", "-option", "has space", "new\nline"])
def test_zip_paths_are_flat_safe_data(tmp_path, name):
    archive = tmp_path / "bad.zip"
    archive.write_bytes(packed({name: b"data"}))
    with pytest.raises(STAGE.InstallError):
        STAGE._unpack(archive, tmp_path)


@pytest.mark.parametrize("kind", [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFDIR])
def test_zip_special_files_refused(tmp_path, kind):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as output:
        row = zipfile.ZipInfo("file")
        row.external_attr = (kind | 0o777) << 16
        output.writestr(row, b"data")
    with pytest.raises(STAGE.InstallError):
        STAGE._unpack(archive, tmp_path)


def test_zip_duplicate_and_oversized_central_index_refused(tmp_path, monkeypatch):
    archive = tmp_path / "bad.zip"
    with pytest.warns(UserWarning), zipfile.ZipFile(archive, "w") as output:
        output.writestr("file", b"one")
        output.writestr("file", b"two")
    with pytest.raises(STAGE.InstallError):
        STAGE._unpack(archive, tmp_path)
    data = bytearray(packed({"file": b"data"}))
    struct.pack_into("<I", data, len(data) - 22 + 12, STAGE.MAX_JSON + 1)
    archive.write_bytes(data)
    monkeypatch.setattr(STAGE.zipfile, "ZipFile", lambda *args: pytest.fail("must bound index before opening"))
    with pytest.raises(STAGE.InstallError):
        STAGE._unpack(archive, tmp_path)


def test_fixed_zip64_index_form_is_supported(tmp_path):
    data = packed({"file": b"data"})
    _, _, _, _, count, size, offset, _ = struct.unpack("<4s4H2IH", data[-22:])
    end64 = struct.pack("<4sQ2H2I4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, size, offset)
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, len(data) - 22, 1)
    end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 65535, 65535, 2**32-1, 2**32-1, 0)
    archive = tmp_path / "zip64.zip"
    archive.write_bytes(data[:-22] + end64 + locator + end)
    assert STAGE._unpack(archive, tmp_path) == inventory({"file": b"data"})


@pytest.mark.parametrize("change", ["bytes", "alias", "new-file"])
def test_snapshot_changed_during_signature_checks_is_not_handed_off(stage, monkeypatch, change):
    original = STAGE._verify_assets
    def alter(directory, *args):
        original(directory, *args)
        if change == "new-file":
            (directory / "extra").write_bytes(b"foreign")
        elif change == "alias":
            os.link(directory / "iris.tgz", directory.parent / "alias")
        else:
            target = directory / "iris.tgz"
            target.chmod(0o600)
            target.write_bytes(b"wrong".ljust(target.stat().st_size, b"x"))
            target.chmod(0o400)
    monkeypatch.setattr(STAGE, "_verify_assets", alter)
    with pytest.raises(STAGE.InstallError, match="changed"):
        publish(stage)
    assert not stage["output"].exists()


def test_no_overwrite_even_when_destination_appears_at_last_step(stage, monkeypatch):
    original = STAGE.finalizer._publish
    def race(parent, source, destination):
        stage["output"].mkdir()
        (stage["output"] / "owner").write_bytes(b"keep")
        return original(parent, source, destination)
    monkeypatch.setattr(STAGE.finalizer, "_publish", race)
    with pytest.raises((STAGE.InstallError, OSError)):
        publish(stage)
    assert (stage["output"] / "owner").read_bytes() == b"keep"


@pytest.mark.parametrize("change", ["suffix", "prefix", "truncated", "members", "file", "total"])
def test_zip_size_and_termination_bounds(tmp_path, monkeypatch, change):
    data = packed({"file": b"data", "second": b"more"})
    if change == "suffix":
        data += b"trailer"
    elif change == "prefix":
        data = b"prefix" + data
    elif change == "truncated":
        data = data[:-1]
    elif change == "members":
        monkeypatch.setattr(STAGE, "MAX_FILES", 1)
    elif change == "file":
        monkeypatch.setattr(STAGE, "MAX_FILE", 3)
    else:
        monkeypatch.setattr(STAGE, "MAX_TOTAL", len(data) - 1)
    archive = tmp_path / "bad.zip"
    archive.write_bytes(data)
    with pytest.raises(STAGE.InstallError):
        STAGE._unpack(archive, tmp_path)


def test_verifier_uses_fixed_existing_identity_and_bounded_sanitized_process(tmp_path, monkeypatch):
    selected = STAGE.selection(TAG, COMMIT, 31, 2, 47, "a" * 64)
    calls = []
    monkeypatch.setenv("GH_HOST", "untrusted.invalid")
    monkeypatch.setenv("GH_TOKEN", "fixture-token")
    monkeypatch.setenv("SSL_CERT_FILE", "/untrusted")
    monkeypatch.setattr(STAGE.subprocess, "run", lambda command, **kwargs: calls.append((command, kwargs)))
    STAGE._verify_signature(tmp_path / "release.json", tmp_path / "bundle", selected, 57,
                            STAGE.time.monotonic() + 120, tmp_path / "config")
    command, kwargs = calls[0]
    assert command == STAGE._auth().verify_command(tmp_path / "release.json", TAG, COMMIT, tmp_path / "bundle")
    assert kwargs["timeout"] == 60 and kwargs["pass_fds"] == (57,)
    assert kwargs["env"]["GH_HOST"] == "github.com" and "SSL_CERT_FILE" not in kwargs["env"]
    assert kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
    with pytest.raises(STAGE.InstallError, match="deadline"):
        STAGE._verify_signature(tmp_path / "release.json", tmp_path / "bundle", selected, 57, 0, tmp_path)


class Response(io.BytesIO):
    def __init__(self, data=b"", status=200, headers=None):
        super().__init__(data)
        self.status, self.headers = status, headers or {}


def test_download_checks_raw_zip_hash_and_never_forwards_token(tmp_path, monkeypatch):
    data, calls = b"raw ZIP fixture", []
    selected = STAGE.selection(TAG, COMMIT, 31, 2, 47, sha(data))
    def request(url, token=None):
        calls.append((url, token))
        return Response(status=302, headers={"Location": "https://storage.example.invalid/signed?secret=opaque"}) if token else Response(data)
    monkeypatch.setattr(STAGE, "_request", request)
    STAGE._download(selected, tmp_path / "raw.zip", len(data), "fixture-token")
    assert calls == [("https://api.github.com/repos/" + STAGE.REPOSITORY + "/actions/artifacts/47/zip", "fixture-token"),
                     ("https://storage.example.invalid/signed?secret=opaque", None)]
    selected["artifact_sha256"] = "b" * 64
    with pytest.raises(STAGE.InstallError, match="raw artifact ZIP"):
        STAGE._download(selected, tmp_path / "other.zip", len(data), "fixture-token")


@pytest.mark.parametrize("location", ["http://example.invalid/a", "file:///tmp/data", "https://user:pass@host/a", "https://host:444/a", "https://host/a#fragment"])
def test_download_location_only_comes_from_https_redirect(tmp_path, monkeypatch, location):
    selected = STAGE.selection(TAG, COMMIT, 31, 2, 47, "a" * 64)
    calls = []
    def request(*args):
        calls.append(args)
        return Response(status=302, headers={"Location": location})
    monkeypatch.setattr(STAGE, "_request", request)
    with pytest.raises(STAGE.InstallError):
        STAGE._download(selected, tmp_path / "raw.zip", 10, "token")
    assert len(calls) == 1


def test_stream_stops_at_size_or_total_deadline(monkeypatch):
    with pytest.raises(STAGE.InstallError, match="size bound"):
        STAGE._stream(Response(b"too much"), io.BytesIO(), 3, STAGE.time.monotonic() + 10)
    ticks = iter([0, 20])
    monkeypatch.setattr(STAGE.time, "monotonic", lambda: next(ticks))
    with pytest.raises(STAGE.InstallError, match="deadline"):
        STAGE._stream(Response(b"data"), io.BytesIO(), 100, 10)


def test_existing_output_and_parent_substitution_preserve_owner_bytes(stage, monkeypatch):
    stage["output"].mkdir()
    sentinel = stage["output"] / "owner"
    sentinel.write_bytes(b"keep")
    with pytest.raises(STAGE.InstallError, match="already exists"):
        publish(stage)
    assert sentinel.read_bytes() == b"keep"
    stage["output"] = stage["output"].parent / "new-output"
    original = STAGE._verify_assets
    parent, moved = stage["output"].parent, stage["output"].parent.with_name("held-parent")
    foreign = []
    def swap(directory, *args):
        original(directory, *args)
        stage_name = directory.parent.resolve().name
        parent.rename(moved)
        parent.mkdir()
        replacement = parent / stage_name / "assets"
        replacement.mkdir(parents=True)
        (replacement / "foreign").write_bytes(b"preserve replacement")
        foreign.append(replacement / "foreign")
    monkeypatch.setattr(STAGE, "_verify_assets", swap)
    with pytest.raises(STAGE.InstallError, match="parent changed"):
        publish(stage)
    assert foreign[0].read_bytes() == b"preserve replacement"
    assert not list(moved.glob(".iris-release-stage-*"))


def test_staging_name_substitution_never_deletes_foreign_replacement(stage, monkeypatch):
    original = STAGE._verify_assets
    paths = []
    def swap(directory, *args):
        original(directory, *args)
        named = directory.parent.resolve()
        moved = named.with_name("original-private-stage")
        named.rename(moved)
        named.mkdir()
        (named / "foreign").write_bytes(b"preserve replacement")
        paths.extend((named, moved))
    monkeypatch.setattr(STAGE, "_verify_assets", swap)
    with pytest.raises(STAGE.InstallError, match="staging directory changed"):
        publish(stage)
    assert (paths[0] / "foreign").read_bytes() == b"preserve replacement"
    assert not list(paths[1].iterdir())
    assert not stage["output"].exists()


def test_replaced_stage_before_fd_acquisition_is_not_adopted_or_cleaned(stage, monkeypatch):
    original = STAGE.os.open
    replacement = []
    def race(path, flags, *args, **kwargs):
        if isinstance(path, str) and path.startswith(".iris-release-stage-") and "dir_fd" in kwargs:
            named = Path(f"/proc/self/fd/{kwargs['dir_fd']}") / path
            physical = named.resolve()
            physical.rename(physical.with_name("initial-stage"))
            physical.mkdir()
            (physical / "owner").write_bytes(b"preserve foreign directory")
            replacement.append(physical)
        return original(path, flags, *args, **kwargs)
    monkeypatch.setattr(STAGE.os, "open", race)
    with pytest.raises(STAGE.InstallError, match="before acquisition"):
        publish(stage)
    assert (replacement[0] / "owner").read_bytes() == b"preserve foreign directory"
    assert not stage["output"].exists()


def test_stage_record_is_exclusive_and_binds_attempt(tmp_path):
    output = tmp_path / "release-stage.json"
    record = STAGE.create_stage_record(output, TAG, COMMIT, 31, 2)
    assert json.loads(output.read_bytes()) == record
    assert record["run_id"] == 31 and record["run_attempt"] == 2
    with pytest.raises(FileExistsError):
        STAGE.create_stage_record(output, TAG, COMMIT, 31, 3)


def test_cli_reads_literal_environment_without_shell_or_url_processing(stage, monkeypatch):
    value = qualification(stage)
    data = STAGE._canonical(value)
    monkeypatch.setenv("IRIS_QUALIFICATION_JSON", data.decode())
    args = ["prepare-publication", "--tag", TAG, "--commit", COMMIT, "--run-id", "31", "--run-attempt", "2",
            "--artifact-id", "47", "--artifact-sha256", stage["selected"]["artifact_sha256"],
            "--output-dir", str(stage["output"]), "--qualification-env", "--qualification-sha256", sha(data),
            "--actor", "dispatcher", "--actor-id", "17", "--triggering-actor", "reviewer", "--confirmation",
            "publish " + TAG + " " + sha(stage["files"]["release.json"])]
    assert STAGE.main(args) == 0
    assert (stage["output"] / "qualification.json").read_bytes() == data


def test_duplicate_json_and_metadata_symlinks_refused(tmp_path):
    with pytest.raises(STAGE.InstallError):
        STAGE._json(b'{"field":1,"field":2}')
    source, alias = tmp_path / "source", tmp_path / "alias"
    source.write_bytes(b"literal")
    alias.symlink_to(source)
    with pytest.raises(OSError):
        STAGE._read(alias)


def test_manual_workflow_never_interpolates_dispatch_data_in_shell():
    text = (ROOT / ".github/workflows/publish-release.yml").read_text()
    run = text.split("        run: |", 1)[1].split("      - name:", 1)[0]
    assert "${{" not in run
    assert "IRIS_QUALIFICATION_JSON: ${{ inputs.qualification_json }}" in text
    assert '"$snapshot"/assets/*' in run
    assert "--qualification-env" in run and "--confirmation" in run
    assert "--clobber" not in run and "docker" not in run and "make-release" not in run
