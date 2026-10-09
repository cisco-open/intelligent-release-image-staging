# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Prebuilt package acquisition preserves topology checks and resumable bytes."""

import hashlib
import json
from pathlib import Path

import pytest

from test_device_finalize import roots, run
from test_installer_prebuilt_adapters import adapter, CLASSES
from iris_installer import cli, deploy, packaging_inputs, prebuilt_device
from iris_installer.state import InstallError


@pytest.fixture
def packaging(adapter, roots, tmp_path, monkeypatch):
    receipt = run(tmp_path, roots)
    runtime = tmp_path / "result"
    final_sha = hashlib.sha256((runtime / "iris-device.oci.tar.finalization.json").read_bytes()).hexdigest()
    local_tool = tmp_path / "licensed-ioxclient"
    local_tool.write_bytes(b"#!/bin/sh\nexit 93\n")
    local_tool.chmod(0o700)
    tool_sha = hashlib.sha256(local_tool.read_bytes()).hexdigest()
    active = {}
    def prepare_inputs(kit, output):
        assert not output.exists()
        output.mkdir(mode=0o700)
        archive = output / "xr-appmgr-build.tar.gz"
        archive.write_bytes(b"authenticated synthetic appmgr source")
        return packaging_inputs.PackagingInputs(archive, "c" * 64, "d" * 40, tool_sha, kit.receipt())
    monkeypatch.setattr(packaging_inputs, "prepare_packaging_inputs", prepare_inputs)
    monkeypatch.setattr(prebuilt_device, "prepare_runtime", lambda _: (runtime, final_sha))
    monkeypatch.setattr(cli, "diagnose", lambda *args, **kwargs: {"state": "checks-passed"})
    def make(target="docker"):
        obj = adapter(target)
        (obj.base / "artifacts").mkdir()
        obj.journal.document["prebuilt_ioxclient"] = str(local_tool)
        obj.env = {"PATH": "/usr/bin:/bin", "IRIS_INSTRUCTION_ROOTS_DIR": "/source-only-roots",
                   "IOXCLIENT": "/source-only-default", "IOXCLIENT_HOME": "/operator-home",
                   "APPMGR_BUILD_CMD": "unverified-command"}
        obj.wrapper_calls = []
        obj.runtime_calls = []
        obj.generation_failure = None
        def runner(command, **kwargs):
            assert command[0] == "bash"
            name = Path(command[1]).name
            assert name in ("stage-iox-package.sh", "build-xr-package.sh")
            assert "get-ioxclient.sh" not in " ".join(command)
            args = dict(zip(command[2::2], command[3::2]))
            assert args["--finalized-dir"] == str(runtime)
            assert args["--finalization-sha256"] == final_sha
            env = kwargs["env"]
            assert not {"IRIS_INSTRUCTION_ROOTS_DIR", "IOXCLIENT_HOME", "APPMGR_BUILD_CMD"} & env.keys()
            tool = Path(env["IOXCLIENT"])
            assert tool != local_tool and tool.name == "ioxclient"
            assert tool.read_bytes() == local_tool.read_bytes()
            assert tool.stat().st_mode & 0o777 == 0o500
            assert obj.journal.document["completed"]["prebuilt-package-intent"]["kit"] == obj._verified_kit.receipt()
            obj.wrapper_calls.append((command, env))
            if obj.generation_failure == len(obj.wrapper_calls):
                raise InstallError("synthetic packaging failure")
            if name == "stage-iox-package.sh":
                assert args["--ioxclient-sha256"] == tool_sha
                filename = "iris-" + args["--arch"] + ".tar"
                output = Path(args["--artifacts-dir"])
            else:
                assert Path(args["--appmgr-archive"]).is_file()
                assert args["--appmgr-sha256"] == "c" * 64
                assert args["--appmgr-revision"] == "d" * 40
                filename = "iris-xr.rpm"
                output = Path(args["--out"])
            payload = ("wrapper " + filename).encode()
            (output / filename).write_bytes(payload)
            values = dict(format="iris-device-wrapper-v2", wrapper_kind="xr-appmgr" if filename.endswith(".rpm") else "iox",
                          wrapper_file=filename, wrapper_sha256=hashlib.sha256(payload).hexdigest(),
                          platform="linux/arm64" if filename == "iris-arm64.tar" else "linux/amd64",
                          canonical_index_digest=receipt["index_digest"], canonical_archive_sha256=receipt["archive_sha256"],
                          canonical_neutral_source_sha256=receipt["neutral_source_sha256"], canonical_finalization_sha256=final_sha)
            (output / (filename + ".manifest")).write_text("".join(key + "=" + value + "\n" for key, value in values.items()))
            return b""
        obj.runner = runner
        def execute(*args, **kwargs):
            obj.runtime_calls.append(args)
            if args == ("python3", "-I", "-B", "-"):
                return json.dumps({"state": "checks-passed"}).encode()
            return b""
        obj.execute = execute
        obj.python = lambda code: json.dumps({"state": "ok"}).encode()
        active.update(obj=obj, tool=local_tool, receipt=receipt, final_sha=final_sha)
        return obj
    make.active = active
    monkeypatch.setattr(cli, "validate_report", lambda *args, **kwargs: None)
    return make


@pytest.mark.parametrize("target", CLASSES)
def test_all_topologies_wrap_only_finalized_inputs_then_run_existing_runtime_gates(packaging, target):
    obj = packaging(target)
    original_env = dict(obj.env)
    obj.packages()
    assert [Path(call[0][1]).name for call in obj.wrapper_calls] == [
        "stage-iox-package.sh", "stage-iox-package.sh", "build-xr-package.sh"]
    saved = obj.journal.document["completed"]
    assert set(saved["packages"]) == deploy.NATIVE_FILES
    assert saved["packages"] == saved["prebuilt-package-generated"]["hashes"]
    assert saved["guestshell"]["state"] == "ok"
    assert ("/opt/iris/server/provision-served.sh",) in obj.runtime_calls
    assert obj.env == original_env
    for filename, expected in saved["packages"].items():
        public = obj.base / "artifacts" / filename
        assert hashlib.sha256(public.read_bytes()).hexdigest() == expected
        assert public.stat().st_mode & 0o777 == 0o444
    assert (obj.base / saved["prebuilt-package-generated"]["directory"]).stat().st_mode & 0o777 == 0o700
    if target == "kubernetes":
        assert "kube-package-proof" in saved
        uploads = [call for call in obj.runtime_calls if call[:4] == ("python3", "-I", "-B", "-c")]
        assert len(uploads) == 6


def test_completed_resume_preserves_exact_wrappers_without_executing_or_requiring_original_tool(packaging):
    obj = packaging()
    obj.packages()
    before = dict(obj.journal.document["completed"]["packages"])
    packaging.active["tool"].unlink()
    obj.wrapper_calls.clear()
    obj.packages()
    assert obj.wrapper_calls == []
    assert obj.journal.document["completed"]["packages"] == before


@pytest.mark.parametrize("record", [None, {}, False, {"schema": 1}])
def test_present_malformed_generation_record_cannot_trigger_regeneration(packaging, record):
    obj = packaging()
    obj.packages()
    obj.journal.document["completed"].pop("packages")
    obj.journal.document["completed"]["prebuilt-package-generated"] = record
    packaging.active["tool"].unlink()
    obj.wrapper_calls.clear()
    with pytest.raises(InstallError, match="generation is invalid"):
        obj.packages()
    assert obj.wrapper_calls == []


def test_generation_failure_publishes_no_partial_artifacts_and_can_resume(packaging):
    obj = packaging()
    obj.generation_failure = 2
    with pytest.raises(InstallError, match="synthetic packaging failure"):
        obj.packages()
    assert not list(obj.base.glob("prebuilt-native-packages-*"))
    assert list((obj.base / "artifacts").iterdir()) == []
    assert set(obj.journal.document["completed"]) == {"prebuilt-package-intent"}
    obj.generation_failure = None
    obj.wrapper_calls.clear()
    obj.packages()
    assert len(obj.wrapper_calls) == 3


def test_partial_publication_recovers_cached_wrappers_without_rebuilding(packaging, monkeypatch):
    obj = packaging()
    publish = deploy._publish_prebuilt_packages
    def interrupted(source, destination, hashes):
        name = "iris-amd64.tar"
        (destination / name).write_bytes((source / name).read_bytes())
        raise InstallError("synthetic publication interruption")
    monkeypatch.setattr(deploy, "_publish_prebuilt_packages", interrupted)
    with pytest.raises(InstallError, match="publication interruption"):
        obj.packages()
    assert "packages" not in obj.journal.document["completed"]
    assert "prebuilt-package-generated" in obj.journal.document["completed"]
    obj.wrapper_calls.clear()
    monkeypatch.setattr(deploy, "_publish_prebuilt_packages", publish)
    obj.packages()
    assert obj.wrapper_calls == []
    assert set(obj.journal.document["completed"]["packages"]) == deploy.NATIVE_FILES


@pytest.mark.parametrize("kind", ["missing", "relative", "wrong-hash", "symlink"])
def test_local_licensed_tool_is_explicit_and_verified_before_execution(packaging, kind):
    obj = packaging()
    tool = packaging.active["tool"]
    if kind == "missing": del obj.journal.document["prebuilt_ioxclient"]
    elif kind == "relative": obj.journal.document["prebuilt_ioxclient"] = "ioxclient"
    elif kind == "wrong-hash": tool.write_bytes(b"different executable")
    else:
        original = tool.with_name("actual-tool")
        tool.rename(original)
        tool.symlink_to(original)
    with pytest.raises(InstallError):
        obj.packages()
    assert obj.wrapper_calls == [] and obj.runtime_calls == []
    assert "packages" not in obj.journal.document["completed"]


def test_unrecorded_existing_native_outputs_are_preserved(packaging):
    obj = packaging()
    path = obj.base / "artifacts/iris-amd64.tar"
    path.write_bytes(b"owner data")
    with pytest.raises(InstallError, match="Unrecorded native artifacts"):
        obj.packages()
    assert path.read_bytes() == b"owner data"
    assert obj.wrapper_calls == [] and obj.runtime_calls == []


@pytest.mark.parametrize("kind", ["public-bytes", "cache-bytes", "cache-extra", "cache-symlink", "intent",
                                  "empty-packages", "extra-packages", "missing-cache"])
def test_resume_rejects_changed_outputs_or_journal_without_rebuilding(packaging, kind):
    obj = packaging()
    obj.packages()
    saved = obj.journal.document["completed"]
    cache = obj.base / saved["prebuilt-package-generated"]["directory"]
    if kind == "public-bytes":
        path = obj.base / "artifacts/iris-amd64.tar"
        path.chmod(0o600); path.write_bytes(b"changed")
    elif kind == "cache-bytes":
        path = cache / "iris-xr.rpm"
        path.chmod(0o600); path.write_bytes(b"changed")
    elif kind == "cache-extra": (cache / "extra").write_text("unexpected")
    elif kind == "cache-symlink":
        cache.rename(obj.base / "renamed-cache")
        cache.symlink_to(obj.base / "renamed-cache", target_is_directory=True)
    elif kind == "intent": saved["prebuilt-package-intent"]["ioxclient_sha256"] = "0" * 64
    elif kind == "empty-packages": saved["packages"] = {}
    elif kind == "extra-packages": saved["packages"]["../extra"] = "0" * 64
    elif kind == "missing-cache": cache.rename(obj.base / "preserved-cache")
    obj.wrapper_calls.clear(); obj.runtime_calls.clear()
    with pytest.raises(InstallError):
        obj.packages()
    assert obj.wrapper_calls == [] and obj.runtime_calls == []


@pytest.mark.parametrize("after_save", [False, True])
def test_interrupted_generation_checkpoint_never_adopts_consistently_tampered_sidecars(packaging, monkeypatch, after_save):
    obj = packaging()
    checkpoint = obj.journal.checkpoint
    def interrupted(stage, evidence):
        if stage == "prebuilt-package-generated":
            if after_save:
                checkpoint(stage, evidence)
            raise InstallError("synthetic checkpoint interruption")
        return checkpoint(stage, evidence)
    monkeypatch.setattr(obj.journal, "checkpoint", interrupted)
    with pytest.raises(InstallError, match="checkpoint interruption"):
        obj.packages()
    cache, = obj.base.glob("prebuilt-native-packages-*")
    path = cache / "iris-xr.rpm"
    path.chmod(0o600); path.write_bytes(b"tampered bytes with matching sidecar")
    manifest = cache / "iris-xr.rpm.manifest"
    values = dict(line.split("=", 1) for line in manifest.read_text().splitlines())
    values["wrapper_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest.chmod(0o600)
    manifest.write_text("".join(key + "=" + value + "\n" for key, value in values.items()))
    monkeypatch.setattr(obj.journal, "checkpoint", checkpoint)
    # Resume from persisted authority, as a separate installer invocation does.
    obj.journal.document = json.loads(obj.journal.path.read_bytes())
    obj.wrapper_calls.clear(); obj.runtime_calls.clear()
    if after_save:
        with pytest.raises(InstallError, match="cache changed"):
            obj.packages()
        assert obj.wrapper_calls == [] and obj.runtime_calls == []
    else:
        obj.packages()
        assert len(obj.wrapper_calls) == 3
        assert obj.journal.document["completed"]["prebuilt-package-generated"]["directory"] != cache.name
        assert (obj.base / "artifacts/iris-xr.rpm").read_bytes() == b"wrapper iris-xr.rpm"
    assert path.read_bytes() == b"tampered bytes with matching sidecar"


def test_publication_parent_substitution_cannot_delete_replacement_temp_directory(packaging, monkeypatch):
    from iris_installer import device_finalize as f
    obj = packaging()
    snapshot = f._snapshot
    parent = obj.base / "artifacts"
    replacement = None
    def substitute(source, destination, limit):
        nonlocal replacement
        result = snapshot(source, destination, limit)
        if Path(destination).parent.name.startswith(".iris-native-"):
            relative = Path(destination).parent.name
            parent.rename(obj.base / "held-artifacts")
            parent.mkdir()
            replacement = parent / relative
            replacement.mkdir()
            (replacement / "owner-marker").write_text("keep")
        return result
    monkeypatch.setattr(f, "_snapshot", substitute)
    with pytest.raises(InstallError, match="directory changed"):
        obj.packages()
    assert replacement is not None
    assert (replacement / "owner-marker").read_text() == "keep"
    assert list((obj.base / "held-artifacts").iterdir()) == []
    assert "packages" not in obj.journal.document["completed"]


def test_generation_parent_substitution_cannot_redirect_failed_runner_cleanup(packaging):
    obj = packaging()
    original = obj.base.with_name("held-installation")
    replacement = None
    def moved(command, **kwargs):
        nonlocal replacement
        output = Path(command[command.index("--artifacts-dir") + 1])
        inputs_name = Path(kwargs["env"]["IOXCLIENT"]).parents[1].name
        obj.base.rename(original)
        obj.base.mkdir(mode=0o700)
        replacement = obj.base / output.name
        replacement.mkdir()
        (replacement / "owner-marker").write_text("keep")
        (obj.base / inputs_name).mkdir()
        (obj.base / inputs_name / "owner-marker").write_text("keep inputs")
        raise InstallError("synthetic runner failure after parent move")
    obj.runner = moved
    with pytest.raises(InstallError, match="runner failure after parent move"):
        obj.packages()
    assert replacement is not None
    assert (replacement / "owner-marker").read_text() == "keep"
    assert not list(original.glob("prebuilt-native-packages-*"))
    assert not list(original.glob("prebuilt-package-inputs-*"))
    inputs, = obj.base.glob("prebuilt-package-inputs-*")
    assert (inputs / "owner-marker").read_text() == "keep inputs"


def test_invalid_generated_provenance_is_not_published(packaging):
    obj = packaging()
    runner = obj.runner
    def invalid(command, **kwargs):
        result = runner(command, **kwargs)
        if "--out" in command:
            output = Path(command[command.index("--out") + 1])
            with (output / "iris-xr.rpm.manifest").open("a") as stream:
                stream.write("canonical_source_sha256=" + "f" * 64 + "\n")
        return result
    obj.runner = invalid
    with pytest.raises(InstallError, match="provenance differs"):
        obj.packages()
    assert list((obj.base / "artifacts").iterdir()) == []
    assert "packages" not in obj.journal.document["completed"]


def test_public_collision_during_resume_preserves_owner_file(packaging, monkeypatch):
    obj = packaging()
    publish = deploy._publish_prebuilt_packages
    def conflicting(source, destination, hashes):
        (destination / "iris-xr.rpm").write_bytes(b"owner replacement")
        return publish(source, destination, hashes)
    monkeypatch.setattr(deploy, "_publish_prebuilt_packages", conflicting)
    with pytest.raises(InstallError, match="existing native artifact differs"):
        obj.packages()
    assert (obj.base / "artifacts/iris-xr.rpm").read_bytes() == b"owner replacement"
    assert "packages" not in obj.journal.document["completed"]


def test_source_acquisition_retains_original_download_and_wrapper_commands(adapter):
    obj = adapter()
    obj.journal.document.pop("input_selection")
    (obj.base / "artifacts").mkdir()
    calls = []
    def command(argv, **kwargs):
        calls.append([str(item) for item in argv])
        for name in deploy.NATIVE_FILES:
            (obj.base / "artifacts" / name).write_bytes(b"source output")
    obj.command = command
    obj.acquire_packages()
    assert [Path(argv[1]).name for argv in calls] == ["get-ioxclient.sh", "stage-iox-package.sh",
                                                     "stage-iox-package.sh", "build-xr-package.sh"]
    assert all("--finalized-dir" not in argv for argv in calls)
    assert set(obj.journal.document["completed"]["packages"]) == deploy.NATIVE_FILES
