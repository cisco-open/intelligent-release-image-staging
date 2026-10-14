#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Acquire a tag-authenticated stage, or bind it to manual publication approval.

Only GET requests and attestation verification are performed externally. This
helper never publishes, rebuilds, or executes downloaded files. Qualification
is an identified reviewer's statement, not proof this helper ran lab checks.
"""

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from iris_installer import device_finalize as finalizer
from iris_installer import release_kit as kit
from iris_installer.state import InstallError

REPOSITORY = "cisco-open/intelligent-release-image-staging"
WORKFLOW = REPOSITORY + "/.github/workflows/release.yml"
MAX_JSON = 1024 * 1024
MAX_QUALIFICATION = 65535
MAX_FILE = 2 * 1024**3
MAX_TOTAL = 8 * 1024**3
MAX_FILES = 64
PROFILES = ("source-only", "prepared-host", "ubuntu-dependencies")
CHUNK = 1024 * 1024
CHECKS = frozenset(("installer-source-parity", "source-notices-review", "single-docker",
                    "split-docker", "single-node-kubernetes", "multi-node-kubernetes",
                    "device-amd64", "device-arm64", "native-admission", "lifecycle"))


def fail(message):
    raise InstallError("Release stage: " + message)


def _auth():
    # This is the checked-out helper, never the copy inside the received ZIP.
    spec = importlib.util.spec_from_file_location("iris_stage_auth", Path(__file__).with_name("release-auth.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _json(data):
    return kit._json(data)


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _keys(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        fail("unsupported or missing fields")


def _positive(value):
    if type(value) is not int or not 0 < value < 2**63:
        fail("expected a positive numeric GitHub identity")
    return value


def _actor(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?", value):
        fail("invalid GitHub actor identity")
    return value


def selection(tag, commit, run_id, run_attempt, artifact_id, artifact_sha256):
    _auth().validate_tag(tag)
    if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
        fail("a full source commit is required")
    return {"tag": tag, "commit": commit, "run_id": _positive(run_id),
            "run_attempt": _positive(run_attempt), "artifact_id": _positive(artifact_id),
            "artifact_sha256": kit._sha(artifact_sha256)}


def _selection(value):
    _keys(value, ("tag", "commit", "run_id", "run_attempt", "artifact_id", "artifact_sha256"))
    return selection(**value)


def _stage_record(tag, commit, run_id, run_attempt):
    # Validate the same fields without inventing an artifact identity before upload.
    selected = selection(tag, commit, run_id, run_attempt, 1, "0" * 64)
    return {"schema": "iris-release-stage-v1", "repository": REPOSITORY, "workflow": WORKFLOW,
            **{key: selected[key] for key in ("tag", "commit", "run_id", "run_attempt")}}


def create_stage_record(path, tag, commit, run_id, run_attempt):
    value = _stage_record(tag, commit, run_id, run_attempt)
    with Path(path).open("xb") as output:
        output.write(_canonical(value))
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _request(url, token=None):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10",
               "User-Agent": "iris-release-stage"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        return urllib.request.build_opener(_NoRedirect).open(request, timeout=30)
    except urllib.error.HTTPError as error:
        if error.code == 302:
            return error
        error.close()
        fail("GitHub GET failed")
    except (urllib.error.URLError, TimeoutError, OSError):
        fail("GitHub GET failed")


def _stream(response, output, maximum, deadline):
    digest, size = hashlib.sha256(), 0
    while True:
        if time.monotonic() >= deadline:
            fail("download deadline exceeded")
        # read1 returns available bytes, so a slow stream cannot reset the whole deadline.
        data = response.read1(min(CHUNK, maximum + 1 - size))
        if not data:
            break
        size += len(data)
        if size > maximum:
            fail("download exceeds its size bound")
        digest.update(data)
        output.write(data)
    if time.monotonic() >= deadline or not size:
        fail("empty download or expired deadline")
    return {"sha256": digest.hexdigest(), "size": size}


def _api(endpoint, token):
    import io
    with _request("https://api.github.com/repos/" + REPOSITORY + endpoint, token) as response:
        if response.status != 200:
            fail("unexpected GitHub API response")
        output = io.BytesIO()
        _stream(response, output, MAX_JSON, time.monotonic() + 60)
    return _json(output.getvalue())


def _hosted_identity(selected, token, profile="source-only"):
    _profile(profile)
    run = _api(f"/actions/runs/{selected['run_id']}/attempts/{selected['run_attempt']}", token)
    workflow_path = ".github/workflows/release.yml"
    paths = (workflow_path, workflow_path + "@" + selected["tag"],
             workflow_path + "@refs/tags/" + selected["tag"])
    if (not isinstance(run, dict) or type(run.get("id")) is not int
            or run["id"] != selected["run_id"] or type(run.get("run_attempt")) is not int
            or run["run_attempt"] != selected["run_attempt"]
            or run.get("path") not in paths
            or run.get("head_sha") != selected["commit"]
            or run.get("event") != ("push" if profile == "source-only" else "workflow_dispatch")
            or run.get("status") != "completed" or run.get("conclusion") != "success"):
        fail("selected run attempt is not the successful profile-specific tag authentication workflow")
    if profile != "source-only":
        # API head_branch is only an additional consistency check, not proof
        # of a tag rather than a same-named branch. Current peeled-tag checks
        # and every asset's attestation source-ref still establish that boundary.
        if run.get("head_branch") not in (selected["tag"], "refs/tags/" + selected["tag"]):
            fail("prebuilt authentication run does not name the selected tag")
        _current_tag(selected, token)
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    if (not isinstance(repository, dict) or not isinstance(head_repository, dict)
            or repository.get("full_name") != REPOSITORY or head_repository.get("full_name") != REPOSITORY
            or _positive(repository.get("id")) != _positive(head_repository.get("id"))):
        fail("selected run is not from the fixed repository")
    artifact = _api(f"/actions/artifacts/{selected['artifact_id']}", token)
    if (not isinstance(artifact, dict) or type(artifact.get("id")) is not int
            or artifact["id"] != selected["artifact_id"]
            or artifact.get("name") != f"iris-authenticated-{selected['run_id']}-{selected['run_attempt']}"
            or artifact.get("expired") is not False
            or artifact.get("digest") != "sha256:" + selected["artifact_sha256"]
            or type(artifact.get("size_in_bytes")) is not int
            or not 0 < artifact["size_in_bytes"] <= MAX_TOTAL):
        fail("selected artifact identity, digest, or lifetime differs")
    origin = artifact.get("workflow_run")
    if (not isinstance(origin, dict) or type(origin.get("id")) is not int
            or origin["id"] != selected["run_id"] or origin.get("head_sha") != selected["commit"]
            or type(origin.get("repository_id")) is not int
            or origin["repository_id"] != repository["id"]
            or type(origin.get("head_repository_id")) is not int
            or origin["head_repository_id"] != repository["id"]):
        fail("artifact belongs to a different hosted run or repository")
    return artifact["size_in_bytes"]


def _download(selected, path, expected_size, token):
    endpoint = f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{selected['artifact_id']}/zip"
    with _request(endpoint, token) as response:
        if response.status != 302:
            fail("artifact endpoint did not return a download location")
        location = response.headers.get("Location", "")
    parsed = urllib.parse.urlsplit(location)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.port not in (None, 443) or parsed.fragment):
        fail("artifact download location is not HTTPS")
    # Only the fixed GitHub API supplies this location. Never forward its token.
    with _request(location) as response, path.open("xb") as output:
        if response.status != 200:
            fail("unexpected artifact download response")
        actual = _stream(response, output, min(expected_size, MAX_TOTAL), time.monotonic() + 900)
    if actual != {"sha256": selected["artifact_sha256"], "size": expected_size}:
        fail("raw artifact ZIP differs from the selected hash or size")


def _current_tag(selected, token):
    """--verify-tag checks existence only; require its current peeled commit too."""
    value = _api("/git/ref/tags/" + selected["tag"], token)
    if not isinstance(value, dict) or value.get("ref") != "refs/tags/" + selected["tag"]:
        fail("current release tag identity differs")
    seen = set()
    for _ in range(8):
        obj = value.get("object")
        if (not isinstance(obj, dict) or not isinstance(obj.get("sha"), str)
                or not re.fullmatch(r"[a-f0-9]{40}", obj["sha"]) or obj["sha"] in seen):
            fail("invalid or cyclic current tag object")
        seen.add(obj["sha"])
        if obj.get("type") == "commit":
            if obj["sha"] != selected["commit"]:
                fail("current release tag no longer identifies the qualified source commit")
            return
        if obj.get("type") != "tag":
            fail("current release tag does not identify a commit")
        value = _api("/git/tags/" + obj["sha"], token)
        if not isinstance(value, dict) or value.get("sha") != obj["sha"]:
            fail("current annotated tag object differs")
    fail("current annotated tag chain exceeds its bound")


def _zip_index(archive):
    """Bound central-directory allocation before ZipFile reads it into memory."""
    with archive.open("rb") as stream:
        size = stream.seek(0, 2)
        if not 22 <= size <= MAX_TOTAL:
            fail("invalid ZIP size")
        stream.seek(-22, 2)
        signature, disk, index_disk, count_disk, count, length, offset, comment = struct.unpack("<4s4H2IH", stream.read(22))
        end = size - 22
        if signature != b"PK\x05\x06" or comment or disk or index_disk:
            fail("unsupported ZIP termination or multi-disk archive")
        if end >= 20:
            stream.seek(end - 20)
            locator = stream.read(20)
            if locator[:4] == b"PK\x06\x07":
                _, disk64, position, disks = struct.unpack("<4sIQI", locator)
                if disk64 or disks != 1 or position != end - 76:
                    fail("unsupported ZIP64 locator")
                stream.seek(position)
                record = stream.read(56)
                signature64, record_size, _, _, disk64, index64, count_disk, count, length, offset = struct.unpack("<4sQ2H2I4Q", record)
                if signature64 != b"PK\x06\x06" or record_size != 44 or disk64 or index64:
                    fail("unsupported ZIP64 index")
                end = position
        if count_disk != count or not 0 < count <= MAX_FILES or not 0 < length <= MAX_JSON or offset + length != end:
            fail("ZIP index exceeds its bounds or is not closed")
        stream.seek(0)
        if stream.read(4) != b"PK\x03\x04":
            fail("ZIP has an unsupported prefix")
    return count


def _unpack(archive, directory):
    files, total = {}, 0
    count = _zip_index(archive)
    with zipfile.ZipFile(archive) as incoming:
        members = incoming.infolist()
        if len(members) != count:
            fail("artifact member count exceeds its bound")
        for row in members:
            name = kit._name(row.filename)
            kind = stat.S_IFMT(row.external_attr >> 16)
            if (name != row.orig_filename or name in files or row.is_dir() or row.flag_bits & 1
                    or kind not in (0, stat.S_IFREG) or not 0 < row.file_size <= MAX_FILE
                    or row.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                fail("artifact must contain unique bounded flat regular files")
            total += row.file_size
            if total > MAX_TOTAL:
                fail("expanded artifact exceeds its aggregate bound")
            digest, size = hashlib.sha256(), 0
            with incoming.open(row) as source, (directory / name).open("xb") as output:
                while data := source.read(CHUNK):
                    size += len(data)
                    if size > row.file_size:
                        fail("artifact member grew while expanding")
                    digest.update(data)
                    output.write(data)
                os.fchmod(output.fileno(), 0o400)
            if size != row.file_size:
                fail("truncated artifact member")
            files[name] = {"sha256": digest.hexdigest(), "size": size}
    return files


def _read(path, maximum=MAX_JSON):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            fail("metadata must be a bounded regular file without aliases")
        data = stream.read(maximum + 1)
        if kit._identity(before) != kit._identity(os.fstat(stream.fileno())):
            fail("metadata changed during inspection")
    if len(data) != before.st_size:
        fail("metadata exceeds its bound")
    return data


def _verify_signature(path, bundle, selected, parent_fd, deadline, config):
    command = _auth().verify_command(path, selected["tag"], selected["commit"], bundle)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        fail("signature verification deadline exceeded")
    environment = {"PATH": os.defpath, "GH_PROMPT_DISABLED": "1", "GH_HOST": "github.com",
                   "GH_CONFIG_DIR": str(config), "HOME": str(config)}
    if os.environ.get("GH_TOKEN"):
        environment["GH_TOKEN"] = os.environ["GH_TOKEN"]
    subprocess.run(command, check=True, timeout=min(60, remaining), pass_fds=(parent_fd,),
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=environment)


def _source_assets(tag, commit):
    package = "iris-installer_" + tag[1:] + "+installer.0.g" + commit[:12] + "_amd64.deb"
    return {"iris.tgz", "iris.tgz.sha256", "MANIFEST.txt", "release-auth.py", "release-stage.json",
            "aria2c-x86_64", "aria2c-aarch64", "aria2c.sha256", "aria2c-2.5.6-p12-source.tar.gz",
            "aria2c-2.5.6-p12-source.tar.gz.sha256", package, package + ".sha256", package + ".source.json"}


def _profile(value):
    if not isinstance(value, str) or value not in PROFILES:
        fail("select an explicitly supported stage profile")
    return value


def _same(actual, expected, message):
    # JSON types matter: Python equality alone equates false/0 and 1/1.0.
    if _canonical(actual) != _canonical(expected):
        fail(message)


def _prebuilt_metadata(directory, files, selected, profile, *, require_incoming=True, unsigned=False):
    """Join exporter records, without replacing complete source validation.

    Acquisition uses this only after the fixed tag-workflow signature boundary.
    The trusted hosted producer also uses the explicitly unsigned form before
    repeating the existing complete candidate validator. Neither use infers trust
    from an unsigned record. These checks bind the externally supplied statement;
    neither a signature nor this join authenticates the original reviewer or
    proves source sufficiency, lab results, or binary reproduction.
    """
    from iris_installer import prebuilt_release as gate
    from iris_installer import candidate_evidence as completion
    from iris_installer import image_components

    def metadata(name, maximum=kit.MAX_METADATA):
        if name not in files:
            fail("prebuilt stage omits required metadata")
        return _json(_read(directory / name, maximum))

    def subset(records, names):
        gate._asset_map(records)
        _same(records, {name: files[name] for name in names if name in files},
              "prebuilt byte inventory differs from the authenticated files")
        if set(records) != set(names):
            fail("prebuilt inventory is not the required closed set")

    identity = {key: selected[key] for key in ("tag", "commit")}
    evidence = metadata(completion.MANIFEST)
    _keys(evidence, gate.EVIDENCE_FIELDS)
    if (evidence["format"] != completion.SCHEMA or evidence["profile"] != profile
            or any(evidence[key] is not False for key in ("authenticated", "source_coverage_complete", "rebuild_verified"))
            or any(evidence[key] != value for key, value in identity.items())):
        fail("prebuilt evidence identity or scope differs")
    gate._asset_map(evidence["files"])
    _keys(evidence["external_pins"], {"debian_keyring_sha256", "pip_sdist_sha256"})
    for digest in evidence["external_pins"].values():
        kit._sha(digest)
    refs = gate._companions(evidence)
    for role, record in refs.items():
        expected_name = ("aria2c-2.5.6-p12-source.tar.gz" if role == "aria2" else completion.COMPANIONS[role])
        if record["asset"] != expected_name:
            fail("prebuilt companion role has an unsupported filename")
        if role != "aria2":
            _keys(evidence["companions"][role], {"asset", "archive_sha256", "validated_manifest_canonical_sha256", "scope"})
            kit._sha(evidence["companions"][role]["validated_manifest_canonical_sha256"])
    original = metadata(completion.ORIGINAL)
    required = {"format", "authenticated", "scope", "commit", "tag", "version", "profile", "source_match", "files"}
    if (not isinstance(original, dict) or not required <= original.keys()
            or original.keys() - required - {"ubuntu_source_coverage", "aria2_source_binding"}
            or original["format"] != "iris-local-release-candidate-v1" or original["authenticated"] is not False
            or (original["tag"], original["commit"], original["version"], original["profile"])
            != (selected["tag"], selected["commit"], selected["tag"][1:], profile)):
        fail("original candidate identity or profile differs")
    if evidence["original_candidate_sha256"] != files[completion.ORIGINAL]["sha256"]:
        fail("original candidate seal differs from the authenticated evidence")
    role_names = {"server-image": "iris-server-amd64.docker.tar", "console-image": "iris-console-amd64.docker.tar",
                  "device-runtime": "iris-device-neutral.oci.tar", "guest-inputs": "iris-guest-inputs.tar.gz",
                  "packaging-tools": "iris-packaging-tools.tar.gz", "source": "iris.tgz"}
    if profile == "ubuntu-dependencies":
        role_names["ubuntu-dependencies"] = "iris-ubuntu-dependencies.tar.gz"
    package = "iris-installer_" + selected["tag"][1:] + "+installer.0.g" + selected["commit"][:12] + "_amd64.deb"
    original_names = {*role_names.values(), "release-kit.json", "iris-device-neutral.oci.tar.manifest",
                      package, package + ".sha256", package + ".source.json"}
    # Newer candidates may already carry these exact companions; completion
    # preserves them. No arbitrary original-candidate extra files are admitted.
    optional = {refs["aria2"]["asset"]}
    if profile == "ubuntu-dependencies":
        optional.add(refs["ubuntu"]["asset"])
    if not isinstance(original["files"], dict) or set(original["files"]) - original_names - optional:
        fail("original candidate contains unsupported assets")
    subset(original["files"], original_names | (set(original["files"]) & optional))
    completed_names = {*original["files"], completion.ORIGINAL, "image-components.json",
                       "iris-server-image-config.json", "iris-console-image-config.json",
                       *(row["asset"] for row in refs.values())}
    subset(evidence["files"], completed_names)
    delivery_names = {"release-auth.py", "aria2c-x86_64", "aria2c-aarch64", "MANIFEST.txt", "aria2c.sha256",
                      "iris.tgz.sha256", refs["aria2"]["asset"] + ".sha256"}
    payload_names = completed_names | {completion.MANIFEST} | delivery_names
    metadata_names = {gate.REVIEW_NAME, gate.PREPARATION_NAME, gate.STAGE_NAME, "release.json", "SHA256SUMS"}
    if not unsigned:
        metadata_names.add("attestations.jsonl")
    if require_incoming:
        metadata_names.add("prebuilt-incoming.json")
    if set(files) != payload_names | metadata_names:
        fail("prebuilt stage contains missing or unsupported assets")
    payload = {name: files[name] for name in payload_names}
    preparation = metadata(gate.PREPARATION_NAME)
    _keys(preparation, {"format", "authenticated", "source_coverage_complete", "rebuild_verified",
        "review_statement_authenticated", "tag", "commit", "profile", "candidate_evidence_sha256",
        "payload_assets", "payload_asset_map_sha256", "image_inventory_sha256", "companions",
        "git_source_parity", "delivery_assets", "source_review_sha256", "stage_record_sha256",
        "staged_run", "review_attribution", "remaining_gates"})
    fixed = {"format": gate.PREPARATION_SCHEMA, **identity, "profile": profile,
             "authenticated": False, "source_coverage_complete": False, "rebuild_verified": False,
             "review_statement_authenticated": False, "candidate_evidence_sha256": files[completion.MANIFEST]["sha256"],
             "payload_assets": payload, "payload_asset_map_sha256": hashlib.sha256(_canonical(payload)).hexdigest(),
             "image_inventory_sha256": files["image-components.json"]["sha256"], "companions": refs,
             "delivery_assets": {name: files[name] for name in delivery_names},
             "source_review_sha256": files[gate.REVIEW_NAME]["sha256"],
             "stage_record_sha256": files[gate.STAGE_NAME]["sha256"],
             "staged_run": {key: selected[key] for key in ("run_id", "run_attempt")},
             "remaining_gates": ["external owner-review authority", "release authentication",
                                 "topology qualification", "owner publication approval"]}
    _same({key: preparation[key] for key in fixed}, fixed, "prebuilt preparation binding differs")
    if evidence["image_inventory_sha256"] != fixed["image_inventory_sha256"]:
        fail("prebuilt image inventory digest differs")
    checked = gate.CheckedCandidate(directory, evidence, files[completion.MANIFEST]["sha256"], payload,
                                    refs, preparation["git_source_parity"], preparation["delivery_assets"])
    review = gate._review(_read(directory / gate.REVIEW_NAME, kit.MAX_METADATA), checked, **identity)
    _same(preparation["review_attribution"], {"reviewer": review["reviewer"], "reference": review["reference"],
          "authority": "Externally supplied statement; this helper checks binding, not reviewer identity or approval authority."},
          "prebuilt review attribution differs")
    if require_incoming:
        incoming = metadata("prebuilt-incoming.json")
        _keys(incoming, {"schema", "repository", "tag", "commit", "profile", "incoming", "hosted_run",
                         "candidate_evidence_sha256", "source_review_sha256", "external_pins",
                         "review_authority_verified", "payloads_rebuilt"})
        expected = {"schema": "iris-hosted-prebuilt-input-v1", "repository": REPOSITORY,
                    **identity, "profile": profile,
                    "hosted_run": {key: selected[key] for key in ("run_id", "run_attempt")},
                    "candidate_evidence_sha256": files[completion.MANIFEST]["sha256"],
                    "source_review_sha256": files[gate.REVIEW_NAME]["sha256"],
                    "external_pins": evidence["external_pins"],
                    "review_authority_verified": False, "payloads_rebuilt": False}
        _same({key: incoming[key] for key in expected}, expected, "hosted prebuilt input binding differs")
        origin = incoming["incoming"]
        _keys(origin, {"run_id", "run_attempt", "workflow", "event", "repository_id", "artifact_id",
                       "artifact_name", "artifact_sha256", "artifact_size"})
        for key in ("run_id", "run_attempt", "repository_id", "artifact_id"):
            _positive(origin[key])
        kit._sha(origin["artifact_sha256"])
        if (not isinstance(origin["workflow"], str)
                or not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml(?:@[^\s]+)?", origin["workflow"])
                or origin["event"] not in ("push", "workflow_dispatch")
                or not isinstance(origin["artifact_name"], str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", origin["artifact_name"])
                or type(origin["artifact_size"]) is not int or not 0 < origin["artifact_size"] <= MAX_TOTAL):
            fail("hosted prebuilt origin receipt differs")
    sidecar = metadata(package + ".source.json")
    _keys(sidecar, {"schema", "commit", "files"})
    if type(sidecar["schema"]) is not int or sidecar["schema"] != 1 or sidecar["commit"] != selected["commit"]:
        fail("installer source identity differs")
    source_map = sidecar["files"]
    if not isinstance(source_map, dict) or not 1 <= len(source_map) <= 100000:
        fail("installer source inventory is unbounded")
    for path, digest in source_map.items():
        if not isinstance(path, str) or path.startswith("/") or any(part in ("", ".", "..") for part in path.split("/")):
            fail("installer source inventory has an unsafe path")
        kit._sha(digest)
    _same(preparation["git_source_parity"], {"commit": selected["commit"], "canonical_file_count": len(source_map),
          "canonical_source_map_sha256": hashlib.sha256(_canonical(source_map)).hexdigest(),
          "scope": "all retained canonical source bytes and modes match the selected local Git shipping set",
          "binary_rebuild_verified": False}, "authenticated Git source parity report differs")
    agreement = evidence["source_agreement"]
    _keys(agreement, {"scope", "git_provenance_verified", "commit_label", "source_inventory_sha256",
                      "canonical_file_count", "additional_tar_files"})
    if (agreement["git_provenance_verified"] is not False or agreement["commit_label"] != selected["commit"]
            or type(agreement["canonical_file_count"]) is not int or agreement["canonical_file_count"] != len(source_map)):
        fail("retained source agreement differs")
    kit._sha(agreement["source_inventory_sha256"])
    extras = agreement["additional_tar_files"]
    if not isinstance(extras, dict) or "MANIFEST.txt" not in extras or set(extras) - {"MANIFEST.txt", "artifacts/.gitkeep"}:
        fail("retained source manifest evidence is missing")
    _same(extras["MANIFEST.txt"], {**files["MANIFEST.txt"], "mode": 0o644}, "delivered source manifest differs")
    if "artifacts/.gitkeep" in extras:
        _same(extras["artifacts/.gitkeep"], {"sha256": hashlib.sha256(b"").hexdigest(), "size": 0, "mode": 0o644},
              "unsupported generated source file")
    binaries = evidence["companions"]["aria2"].get("binary_sha256")
    _keys(binaries, {"x86_64", "aarch64"})
    for name, path in (("release-auth.py", "tools/release-auth.py"),
                       ("aria2c-x86_64", "deliverables/aria2c-x86_64"), ("aria2c-aarch64", "deliverables/aria2c-aarch64")):
        if source_map.get(path) != files[name]["sha256"]:
            fail("delivery helper or client differs from canonical source inventory")
    for arch, digest in binaries.items():
        if kit._sha(digest) != files["aria2c-" + arch]["sha256"]:
            fail("delivered client differs from the source companion binding")
    for name in ("iris.tgz", refs["aria2"]["asset"], package):
        if _read(directory / (name + ".sha256")) != (files[name]["sha256"] + "  " + name + "\n").encode():
            fail("delivery checksum sidecar differs")
    if _read(directory / "aria2c.sha256") != "".join(
            binaries[arch] + "  aria2c-" + arch + "\n" for arch in ("x86_64", "aarch64")).encode():
        fail("delivery client checksums differ")
    descriptor = metadata("release-kit.json")
    # The general kit reader predates strict JSON numeric type comparisons.
    if not isinstance(descriptor, dict) or descriptor.get("profile") != profile:
        fail("release kit profile differs from the explicit selection")
    if not isinstance(descriptor.get("assets"), dict):
        fail("release kit roles must be a mapping")
    for row in descriptor["assets"].values():
        if not isinstance(row, dict) or type(row.get("size")) is not int:
            fail("release kit asset size must be an integer")
    assets = {asset.role: asset for asset in kit._kit_manifest(descriptor, _auth(), **identity, inventory=files)}
    _same({role: asset.name for role, asset in assets.items()}, role_names, "release kit role filenames differ")
    image_inventory = metadata("image-components.json", image_components.MAX_RECEIPT)
    _keys(image_inventory, {"format", "scope", "authenticated", "source_coverage_complete", "commit",
                           "commit_scope", "images", "attribution_policy"})
    if (image_inventory["format"] != "iris-image-component-inventory-v1" or image_inventory["scope"] != "inventory-only"
            or image_inventory["authenticated"] is not False or image_inventory["source_coverage_complete"] is not False
            or image_inventory["commit"] != selected["commit"] or image_inventory["commit_scope"] != "core-revision-labels-only"):
        fail("image inventory scope or source identity differs")
    _keys(image_inventory["images"], kit.IMAGES)
    images = {}
    for role in sorted(kit.IMAGES):
        image, asset = image_inventory["images"][role], assets[role]
        if not isinstance(image, dict):
            fail("invalid image identity metadata")
        fields = {"archive_sha256": asset.sha256, "archive_size": asset.size}
        if role == "device-runtime":
            fields.update(index_digest=asset.image_digest, source_commit_binding="not-assessed")
            platforms = image.get("platforms")
            if not isinstance(platforms, list) or len(platforms) != 2:
                fail("neutral inventory requires both platforms")
            if [row.get("platform") for row in platforms if isinstance(row, dict)] != list(asset.platforms):
                fail("neutral inventory platform selection differs")
            for row in platforms:
                kit._sha(row.get("config_digest"), "sha256:")
                kit._sha(row.get("manifest_digest"), "sha256:")
            images[role] = {"archive_sha256": asset.sha256, "index_digest": asset.image_digest,
                            "neutral_source_sha256": asset.neutral_source_sha256, "platforms": list(asset.platforms)}
        else:
            fields.update(config_digest=asset.image_digest, platform="linux/amd64", revision_label=selected["commit"])
            if files["iris-" + role + "-config.json"]["sha256"] != asset.image_digest.removeprefix("sha256:"):
                fail("retained core configuration bytes differ from kit image identity")
            images[role] = {"archive_sha256": asset.sha256, "config_digest": asset.image_digest, "platform": "linux/amd64"}
        _same({key: image.get(key) for key in fields}, fields, "image inventory differs from release kit")
    neutral = assets["device-runtime"]
    if evidence["neutral_source_sha256"] != neutral.neutral_source_sha256:
        fail("neutral source context identity differs")
    try:
        lines = [line.split("=", 1) for line in _read(directory / "iris-device-neutral.oci.tar.manifest").decode("ascii").splitlines()]
        neutral_record = dict(lines)
    except (UnicodeError, ValueError):
        fail("invalid neutral builder record")
    _same(neutral_record, {"format": "iris-device-neutral-oci-v1", "trust_mode": "neutral",
          "source_sha256": neutral.neutral_source_sha256, "index_digest": neutral.image_digest,
          "archive_sha256": neutral.sha256, "platforms": "linux/amd64,linux/arm64"}, "neutral builder identity differs")
    if len(lines) != len(neutral_record):
        fail("duplicate neutral builder fields")
    return {"release_kit_sha256": files["release-kit.json"]["sha256"],
            "candidate_evidence_sha256": files[completion.MANIFEST]["sha256"], "image_identities": images,
            "prebuilt_inputs": {"original_candidate_sha256": files[completion.ORIGINAL]["sha256"],
                "source_review_sha256": files[gate.REVIEW_NAME]["sha256"],
                "preparation_sha256": files[gate.PREPARATION_NAME]["sha256"],
                "payload_asset_map_sha256": preparation["payload_asset_map_sha256"],
                "image_inventory_sha256": files["image-components.json"]["sha256"]}}


def _verify_assets(directory, files, selected, parent_fd, config, profile="source-only"):
    _profile(profile)
    expected_names = _source_assets(selected["tag"], selected["commit"]) | {"release.json", "SHA256SUMS", "attestations.jsonl"}
    if profile == "source-only" and set(files) != expected_names:
        fail("source-only stage has missing or unsupported assets; prebuilt publication remains disabled")
    if not {"release.json", "release-stage.json", "SHA256SUMS", "attestations.jsonl"} <= files.keys():
        fail("stage omits authentication metadata")
    for name, maximum in (("release.json", MAX_JSON), ("release-stage.json", MAX_JSON),
                          ("SHA256SUMS", MAX_JSON), ("attestations.jsonl", kit.MAX_BUNDLE)):
        if files[name]["size"] > maximum:
            fail("authentication metadata exceeds its bound")
    bundle, deadline = directory / "attestations.jsonl", time.monotonic() + 600
    _verify_signature(directory / "release.json", bundle, selected, parent_fd, deadline, config)
    manifest = _json(_read(directory / "release.json"))
    _keys(manifest, ("schema", "repository", "workflow", "tag", "commit", "assets"))
    if (type(manifest["schema"]) is not int or manifest["schema"] != 1
            or manifest["repository"] != REPOSITORY or manifest["workflow"] != WORKFLOW
            or manifest["tag"] != selected["tag"] or manifest["commit"] != selected["commit"]):
        fail("authenticated release inventory does not match the selected identity")
    expected = {name: row for name, row in files.items() if name not in {"release.json", "SHA256SUMS", "attestations.jsonl"}}
    if _canonical(manifest["assets"]) != _canonical(expected):
        fail("authenticated inventory differs from the exact extracted files")
    for name in sorted(expected):
        _verify_signature(directory / name, bundle, selected, parent_fd, deadline, config)
    _verify_signature(directory / "SHA256SUMS", bundle, selected, parent_fd, deadline, config)
    expected_checksums = "".join(files[name]["sha256"] + "  " + name + "\n"
                                 for name in sorted(set(files) - {"SHA256SUMS", "attestations.jsonl"})).encode()
    if _read(directory / "SHA256SUMS") != expected_checksums:
        fail("signed checksum list differs from the exact asset set")
    record = _json(_read(directory / "release-stage.json"))
    if _canonical(record) != _canonical(_stage_record(selected["tag"], selected["commit"],
                                                     selected["run_id"], selected["run_attempt"])):
        fail("signed stage record belongs to a different run attempt")
    if profile != "source-only":
        return _prebuilt_metadata(directory, files, selected, profile)
    return None


def _recheck_files(directory, files):
    """Ensure the exact read-only signature-checked snapshot is handed off."""
    if set(os.listdir(directory)) != set(files):
        fail("verified asset set changed before handoff")
    for name, expected in files.items():
        path = directory / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o400
                    or before.st_size != expected["size"]):
                fail("verified file custody changed before handoff")
            digest, size = kit._hash(fd, MAX_FILE)
            if ({"sha256": digest, "size": size} != expected
                    or kit._identity(before) != kit._identity(os.fstat(fd))
                    or kit._identity(before) != kit._identity(path.lstat())):
                fail("verified file bytes changed before handoff")
        finally:
            os.close(fd)


@contextmanager
def _publication(destination):
    output = kit._path(Path(destination))
    parent = kit._protected_directory(output.parent)
    stage, staging_fd, published = None, None, False
    try:
        held = os.fstat(parent)
        if held.st_uid != os.geteuid() or held.st_mode & 0o022:
            fail("output parent must be caller-owned and protected")
        if output.exists() or output.is_symlink():
            fail("output already exists")
        named_stage = Path(tempfile.mkdtemp(prefix=".iris-release-stage-", dir=f"/proc/self/fd/{parent}"))
        before = named_stage.lstat()
        staging_fd = os.open(named_stage.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        held_stage = os.fstat(staging_fd)
        if (held_stage.st_dev, held_stage.st_ino) != (before.st_dev, before.st_ino):
            os.close(staging_fd)
            staging_fd = None
            fail("staging directory changed before acquisition")
        stage = Path(f"/proc/self/fd/{staging_fd}")
        yield stage, staging_fd
        for path in stage.rglob("*"):
            if path.is_file():
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
        current = output.parent.lstat()
        if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
            fail("output parent changed during preparation")
        current_stage = os.stat(named_stage.name, dir_fd=parent, follow_symlinks=False)
        if (current_stage.st_dev, current_stage.st_ino) != (held_stage.st_dev, held_stage.st_ino):
            fail("staging directory changed during preparation")
        assets_fd = os.open("assets", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=staging_fd)
        try:
            os.fchmod(assets_fd, 0o500)
            os.fsync(assets_fd)
        finally:
            os.close(assets_fd)
        os.fchmod(staging_fd, 0o500)
        os.fsync(staging_fd)
        finalizer._publish(parent, named_stage.name, output.name)
        published = True
    finally:
        try:
            if staging_fd is not None and not published:
                os.fchmod(staging_fd, 0o700)
                for name in os.listdir(staging_fd):
                    info = os.stat(name, dir_fd=staging_fd, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=staging_fd)
                        try:
                            os.fchmod(child, 0o700)
                        finally:
                            os.close(child)
                        shutil.rmtree(name, dir_fd=staging_fd)
                    else:
                        os.unlink(name, dir_fd=staging_fd)
                try:
                    named = os.stat(named_stage.name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    if (named.st_dev, named.st_ino) == (held_stage.st_dev, held_stage.st_ino):
                        os.rmdir(named_stage.name, dir_fd=parent)
        finally:
            if staging_fd is not None:
                os.close(staging_fd)
            os.close(parent)


def _acquire(selected, stage, parent_fd, token, profile="source-only"):
    expected_size = _hosted_identity(selected, token, profile)
    archive, assets, config = stage / "stage.zip", stage / "assets", stage / "verifier-config"
    assets.mkdir(mode=0o700)
    config.mkdir(mode=0o700)
    _download(selected, archive, expected_size, token)
    files = _unpack(archive, assets)
    binding = _verify_assets(assets, files, selected, parent_fd, config, profile)
    archive.unlink()
    shutil.rmtree(config)
    return files, binding


def _qualification(data, expected_sha256, selected, files, actor, confirmation, profile="source-only", binding=None):
    _profile(profile)
    kit._sha(expected_sha256)
    if not 0 < len(data) <= MAX_QUALIFICATION or hashlib.sha256(data).hexdigest() != expected_sha256:
        fail("qualification bytes differ from the explicit hash or size bound")
    value = _json(data)
    fields = ("schema", "repository", "tag", "commit", "profile", "stage", "release_json_sha256",
              "sha256sums_sha256", "attestations_sha256", "assets", "release_kit_sha256",
              "candidate_evidence_sha256", "image_identities", "reviewed_by", "checks")
    if profile != "source-only":
        fields += ("prebuilt_inputs",)
        if not isinstance(binding, dict):
            fail("prebuilt qualification requires verified metadata bindings")
    _keys(value, fields)
    expected = {"schema": "iris-release-qualification-v1", "repository": REPOSITORY,
                "tag": selected["tag"], "commit": selected["commit"], "profile": "source-only",
                "stage": {key: selected[key] for key in ("run_id", "run_attempt", "artifact_id", "artifact_sha256")},
                "release_json_sha256": files["release.json"]["sha256"],
                "sha256sums_sha256": files["SHA256SUMS"]["sha256"],
                "attestations_sha256": files["attestations.jsonl"]["sha256"], "assets": files,
                "release_kit_sha256": None, "candidate_evidence_sha256": None, "image_identities": None,
                "reviewed_by": actor}
    if profile != "source-only":
        expected.update(schema="iris-release-qualification-v2", profile=profile, **binding)
    if _canonical({key: value[key] for key in fields if key != "checks"}) != _canonical(expected):
        fail("qualification does not bind the exact selected stage, profile and reviewer")
    _keys(value["checks"], CHECKS)
    for record in value["checks"].values():
        _keys(record, ("result", "evidence_sha256"))
        if record["result"] != "passed":
            fail("qualification includes an incomplete or failed check")
        kit._sha(record["evidence_sha256"])
    if (profile != "source-only" and value["checks"]["source-notices-review"]["evidence_sha256"]
            != binding["prebuilt_inputs"]["source_review_sha256"]):
        fail("qualification source review does not name the exact staged statement")
    if confirmation != "publish " + selected["tag"] + " " + files["release.json"]["sha256"]:
        fail("explicit publication confirmation differs from the selected release")
    return value


def acquire_stage(selected, output_dir, *, token=None, profile="source-only"):
    """Read-only hosted acquisition for qualification; no approval or publication."""
    selected = _selection(selected)
    profile = _profile(profile)
    with _publication(output_dir) as (stage, parent_fd):
        files, binding = _acquire(selected, stage, parent_fd, token, profile)
        record = {"schema": "iris-verified-release-stage-v1", "selection": selected, "files": files}
        if binding is not None:
            record.update(schema="iris-verified-release-stage-v2", profile=profile, prebuilt_binding=binding,
                          verification_scope="authenticated exporter metadata bindings; source validators were not rerun")
        (stage / "stage-verification.json").write_bytes(_canonical(record))
        (stage / "stage-verification.json").chmod(0o400)
        _recheck_files(stage / "assets", files)
    return record


def prepare_publication(selected, output_dir, *, qualification, qualification_sha256,
                        confirmation, actor, actor_id, triggering_actor, token=None, profile="source-only"):
    """Return a new sealed snapshot, with manual approval outside its assets/."""
    selected = _selection(selected)
    profile = _profile(profile)
    actor, triggering_actor, actor_id = _actor(actor), _actor(triggering_actor), _positive(actor_id)
    if not isinstance(qualification, bytes) or not 0 < len(qualification) <= MAX_QUALIFICATION:
        fail("qualification must be bounded literal JSON bytes")
    with _publication(output_dir) as (stage, parent_fd):
        files, binding = _acquire(selected, stage, parent_fd, token, profile)
        _qualification(qualification, qualification_sha256, selected, files, triggering_actor, confirmation, profile, binding)
        record = {"schema": "iris-release-publication-v1", "selection": selected, "files": files,
                  "qualification_sha256": qualification_sha256,
                  "dispatch": {"actor": actor, "actor_id": actor_id, "triggering_actor": triggering_actor},
                  "qualification_is_reviewer_statement": True}
        if binding is not None:
            record.update(schema="iris-release-publication-v2", profile=profile, prebuilt_binding=binding,
                          verification_scope="authenticated exporter metadata bindings; source validators were not rerun")
        for name, data in (("qualification.json", qualification), ("publication.json", _canonical(record))):
            (stage / name).write_bytes(data)
            (stage / name).chmod(0o400)
        _recheck_files(stage / "assets", files)
        _current_tag(selected, token)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("record", "acquire", "prepare-publication"):
        command = commands.add_parser(name)
        command.add_argument("--tag", required=True)
        command.add_argument("--commit", required=True)
        command.add_argument("--run-id", type=int, required=True)
        command.add_argument("--run-attempt", type=int, required=True)
        if name == "record":
            command.add_argument("--output", type=Path, required=True)
        else:
            command.add_argument("--artifact-id", type=int, required=True)
            command.add_argument("--artifact-sha256", required=True)
            command.add_argument("--output-dir", type=Path, required=True)
            command.add_argument("--profile", choices=PROFILES, default="source-only")
        if name == "prepare-publication":
            source = command.add_mutually_exclusive_group(required=True)
            source.add_argument("--qualification-file", type=Path)
            source.add_argument("--qualification-env", action="store_true")
            for field in ("qualification-sha256", "confirmation", "actor", "triggering-actor"):
                command.add_argument("--" + field, required=True)
            command.add_argument("--actor-id", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "record":
            create_stage_record(args.output, args.tag, args.commit, args.run_id, args.run_attempt)
        else:
            selected = selection(args.tag, args.commit, args.run_id, args.run_attempt,
                                 args.artifact_id, args.artifact_sha256)
            if args.command == "acquire":
                acquire_stage(selected, args.output_dir, token=os.environ.get("GH_TOKEN"), profile=args.profile)
            else:
                data = (_read(args.qualification_file, MAX_QUALIFICATION) if args.qualification_file
                        else os.environ.get("IRIS_QUALIFICATION_JSON", "").encode())
                prepare_publication(selected, args.output_dir, qualification=data,
                    qualification_sha256=args.qualification_sha256, confirmation=args.confirmation,
                    actor=args.actor, actor_id=args.actor_id, triggering_actor=args.triggering_actor,
                    token=os.environ.get("GH_TOKEN"), profile=args.profile)
    except (InstallError, ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile, RuntimeError):
        # Avoid printing redirected signed URLs, credentials, or untrusted JSON.
        print("Release stage verification failed; no publication snapshot was produced", file=sys.stderr)
        return 1
    print("Release stage operation completed; nothing was published")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
