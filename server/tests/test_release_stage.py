# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Authentication/export is separate from exact-byte manual publication."""

import hashlib
from contextlib import contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import zipfile

import pytest
import yaml

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
    files = {name: ("fixture bytes for " + name).encode() for name in STAGE._source_assets(TAG, COMMIT)}
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


def seal_prebuilt(stage, files):
    """Refresh only the signed outer seal; inner joins remain independently checked."""
    files = {name: raw for name, raw in files.items() if name not in {"release.json", "SHA256SUMS", "attestations.jsonl"}}
    files["release.json"] = STAGE._canonical({"schema": 1, "repository": STAGE.REPOSITORY,
        "workflow": STAGE.WORKFLOW, "tag": TAG, "commit": COMMIT, "assets": inventory(files)})
    files["SHA256SUMS"] = "".join(sha(files[name]) + "  " + name + "\n" for name in sorted(files)).encode()
    files["attestations.jsonl"] = b"Fixture signatures mocked; not hosted authentication\n"
    replace_files(stage, files)


def rebind_prebuilt(stage, files):
    """Rebind surrounding inventories to test malformed inner signed metadata."""
    original = json.loads(files["local-candidate.json"])
    original["files"] = {name: inventory(files)[name] for name in original["files"]}
    files["local-candidate.json"] = STAGE._canonical(original)
    evidence = json.loads(files["candidate-evidence.json"])
    evidence["files"] = {name: inventory(files)[name] for name in evidence["files"]}
    evidence["original_candidate_sha256"] = sha(files["local-candidate.json"])
    evidence["image_inventory_sha256"] = sha(files["image-components.json"])
    files["candidate-evidence.json"] = STAGE._canonical(evidence)
    prep = json.loads(files["prebuilt-preparation.json"])
    prep["payload_assets"] = {name: inventory(files)[name] for name in prep["payload_assets"]}
    prep["payload_asset_map_sha256"] = sha(STAGE._canonical(prep["payload_assets"]))
    prep["candidate_evidence_sha256"] = sha(files["candidate-evidence.json"])
    prep["image_inventory_sha256"] = sha(files["image-components.json"])
    prep["delivery_assets"] = {name: inventory(files)[name] for name in prep["delivery_assets"]}
    review = json.loads(files["source-review.json"])
    for key in ("candidate_evidence_sha256", "image_inventory_sha256", "payload_assets", "payload_asset_map_sha256"):
        review[key] = prep[key]
    files["source-review.json"] = STAGE._canonical(review)
    prep["source_review_sha256"] = sha(files["source-review.json"])
    files["prebuilt-preparation.json"] = STAGE._canonical(prep)
    seal_prebuilt(stage, files)


@pytest.fixture(params=["prepared-host", "ubuntu-dependencies"])
def prebuilt(stage, request, tmp_path, monkeypatch):
    """Use the real gate writer; expensive source reconstruction is a labelled stub."""
    from iris_installer import prebuilt_release as gate
    from iris_installer import candidate_evidence as completion
    profile = request.param
    package = "iris-installer_" + TAG[1:] + "+installer.0.g" + COMMIT[:12] + "_amd64.deb"
    roles = {"server-image": "iris-server-amd64.docker.tar", "console-image": "iris-console-amd64.docker.tar",
             "device-runtime": "iris-device-neutral.oci.tar", "guest-inputs": "iris-guest-inputs.tar.gz",
             "packaging-tools": "iris-packaging-tools.tar.gz", "source": "iris.tgz"}
    if profile == "ubuntu-dependencies":
        roles["ubuntu-dependencies"] = "iris-ubuntu-dependencies.tar.gz"
    files = {name: ("inert fixture " + name).encode() for name in roles.values()}
    configs = {role: STAGE._canonical({"architecture": "amd64", "os": "linux",
               "config": {"Labels": {"org.opencontainers.image.revision": COMMIT}}, "role": role})
               for role in ("server-image", "console-image")}
    digest = {role: "sha256:" + sha(raw) for role, raw in configs.items()}
    digest["device-runtime"] = "sha256:" + "c" * 64
    source_sha = "d" * 64
    descriptor = {"schema": STAGE.kit.SCHEMA, "repository": STAGE.REPOSITORY, "workflow": STAGE.WORKFLOW,
                  "tag": TAG, "commit": COMMIT, "host": STAGE.kit.HOST, "profile": profile, "assets": {}}
    for role, name in roles.items():
        row = {"name": name, **inventory(files)[name], "format": "tar.gz"}
        if role in STAGE.kit.IMAGES:
            row.update(format="oci-archive" if role == "device-runtime" else "docker-archive",
                       platforms=["linux/amd64", "linux/arm64"] if role == "device-runtime" else ["linux/amd64"],
                       image_digest=digest[role])
        if role == "device-runtime":
            row["neutral_source_sha256"] = source_sha
        if role == "ubuntu-dependencies":
            row["dependency_manifest_sha256"] = "e" * 64
        descriptor["assets"][role] = row
    files["release-kit.json"] = STAGE._canonical(descriptor)
    neutral = {"format": "iris-device-neutral-oci-v1", "trust_mode": "neutral", "source_sha256": source_sha,
               "index_digest": digest["device-runtime"], "archive_sha256": sha(files[roles["device-runtime"]]),
               "platforms": "linux/amd64,linux/arm64"}
    files["iris-device-neutral.oci.tar.manifest"] = "".join(key + "=" + value + "\n" for key, value in neutral.items()).encode()
    delivery = {"release-auth.py": b"# Never execute received helper\n", "aria2c-x86_64": b"inert amd64 client",
                "aria2c-aarch64": b"inert arm64 client", "MANIFEST.txt": b"fixture canonical source manifest\n"}
    source_map = {"tools/release-auth.py": sha(delivery["release-auth.py"]),
                  **{"deliverables/aria2c-" + arch: sha(delivery["aria2c-" + arch]) for arch in ("x86_64", "aarch64")}}
    files[package] = b"inert installer fixture"
    files[package + ".source.json"] = STAGE._canonical({"schema": 1, "commit": COMMIT, "files": source_map})
    files[package + ".sha256"] = (sha(files[package]) + "  " + package + "\n").encode()
    original = {"format": "iris-local-release-candidate-v1", "authenticated": False, "scope": "local candidate only",
                "tag": TAG, "commit": COMMIT, "version": TAG[1:], "profile": profile,
                "source_match": {"canonical_source_matches": True}, "files": inventory(files)}
    files[completion.ORIGINAL] = STAGE._canonical(original)
    images = {}
    for role in sorted(STAGE.kit.IMAGES):
        image = {"archive_sha256": sha(files[roles[role]]), "archive_size": len(files[roles[role]])}
        if role == "device-runtime":
            image.update(index_digest=digest[role], source_commit_binding="not-assessed",
                         platforms=[{"platform": platform, "config_digest": "sha256:" + "e" * 64,
                                     "manifest_digest": "sha256:" + "f" * 64}
                                    for platform in ("linux/amd64", "linux/arm64")])
        else:
            image.update(config_digest=digest[role], platform="linux/amd64", revision_label=COMMIT)
            files["iris-" + role + "-config.json"] = configs[role]
        images[role] = image
    files["image-components.json"] = STAGE._canonical({"format": "iris-image-component-inventory-v1",
        "scope": "inventory-only", "authenticated": False, "source_coverage_complete": False, "commit": COMMIT,
        "commit_scope": "core-revision-labels-only", "images": images, "attribution_policy": "Fixture evidence only"})
    companions = {}
    for role, name in {"aria2": "aria2c-2.5.6-p10-source.tar.gz", **completion.COMPANIONS}.items():
        if role == "ubuntu" and profile != "ubuntu-dependencies":
            continue
        files[name] = ("inert source companion " + role).encode()
        companions[role] = {"asset": name, "archive_sha256": sha(files[name]), "scope": "fixture source binding"}
        if role == "aria2":
            companions[role]["binary_sha256"] = {arch: sha(delivery["aria2c-" + arch]) for arch in ("x86_64", "aarch64")}
        else:
            companions[role]["validated_manifest_canonical_sha256"] = "f" * 64
    agreement = {"scope": "fixture retained source parity", "git_provenance_verified": False, "commit_label": COMMIT,
                 "source_inventory_sha256": "b" * 64, "canonical_file_count": len(source_map),
                 "additional_tar_files": {"MANIFEST.txt": {**inventory(delivery)["MANIFEST.txt"], "mode": 0o644}}}
    evidence = {"format": completion.SCHEMA, "authenticated": False, "source_coverage_complete": False,
                "rebuild_verified": False, "original_candidate_sha256": sha(files[completion.ORIGINAL]),
                "tag": TAG, "commit": COMMIT, "profile": profile, "image_inventory_sha256": sha(files["image-components.json"]),
                "source_agreement": agreement, "neutral_source_sha256": source_sha,
                "external_pins": {"debian_keyring_sha256": "b" * 64, "pip_sdist_sha256": "c" * 64},
                "companions": companions, "files": inventory(files), "mechanical_evidence": "fixture only", "remaining_gates": []}
    files[completion.MANIFEST] = STAGE._canonical(evidence)
    delivery["aria2c.sha256"] = "".join(sha(delivery["aria2c-" + arch]) + "  aria2c-" + arch + "\n"
                                        for arch in ("x86_64", "aarch64")).encode()
    for name in ("iris.tgz", companions["aria2"]["asset"]):
        delivery[name + ".sha256"] = (sha(files[name]) + "  " + name + "\n").encode()
    files.update(delivery)
    private = tmp_path / "gate-checked-fixture"
    private.mkdir(mode=0o700)
    for name, raw in files.items():
        (private / name).write_bytes(raw)
    parity = {"commit": COMMIT, "canonical_file_count": len(source_map),
              "canonical_source_map_sha256": sha(STAGE._canonical(source_map)),
              "scope": "all retained canonical source bytes and modes match the selected local Git shipping set",
              "binary_rebuild_verified": False}
    refs = gate._companions(evidence)
    checked = gate.CheckedCandidate(private, evidence, sha(files[completion.MANIFEST]), inventory(files), refs, parity, inventory(delivery))
    @contextmanager
    def checked_fixture(*args, **kwargs):
        yield checked
    monkeypatch.setattr(gate, "check_completed_candidate", checked_fixture)
    review = {"format": gate.REVIEW_SCHEMA, "scope": "source-sufficiency-and-redistribution",
              "decision": "approve-exact-artifacts", "tag": TAG, "commit": COMMIT,
              "candidate_evidence_sha256": checked.evidence_sha256, "payload_assets": checked.assets,
              "payload_asset_map_sha256": sha(STAGE._canonical(checked.assets)),
              "image_inventory_sha256": evidence["image_inventory_sha256"], "companions": refs,
              "reviewer": "Fixture only", "reference": "No owner approval", "statement": "Test statement only"}
    review_raw = json.dumps(review, indent=2).encode() + b"\n"
    record_raw = json.dumps(STAGE._stage_record(TAG, COMMIT, 31, 2), indent=2).encode() + b"\n"
    review_path, record_path = tmp_path / "review-input.json", tmp_path / "stage-input.json"
    review_path.write_bytes(review_raw)
    record_path.write_bytes(record_raw)
    output = gate.prepare_prebuilt(private, checked.evidence_sha256, tmp_path / "gate-output",
        repository=tmp_path / "unused-repository", tag=TAG, commit=COMMIT,
        debian_keyring=tmp_path / "unused-keyring", pip_sdist_sha256="c" * 64,
        source_review=review_path, expected_review_sha256=sha(review_raw),
        stage_record=record_path, expected_stage_sha256=sha(record_raw))
    files = {path.name: path.read_bytes() for path in output.parent.iterdir()}
    files["attestations.jsonl"] = b"Fixture signatures mocked; not hosted authentication\n"
    replace_files(stage, files)
    stage["profile"] = profile
    stage["package"] = package
    # Acquisition must never invoke these expensive source-validation seams.
    def forbidden(*args, **kwargs):
        raise AssertionError("stage verifier must not rerun source validators or execute candidate code")
    monkeypatch.setattr(gate, "check_completed_candidate", forbidden)
    monkeypatch.setattr(completion, "assemble", forbidden)
    return stage


def prebuilt_qualification(stage):
    value = qualification(stage)
    prep = json.loads(stage["files"]["prebuilt-preparation.json"])
    descriptor = json.loads(stage["files"]["release-kit.json"])
    images = {}
    for role in STAGE.kit.IMAGES:
        row = descriptor["assets"][role]
        images[role] = ({"archive_sha256": row["sha256"], "index_digest": row["image_digest"],
                         "neutral_source_sha256": row["neutral_source_sha256"], "platforms": row["platforms"]}
                        if role == "device-runtime" else {"archive_sha256": row["sha256"],
                            "config_digest": row["image_digest"], "platform": "linux/amd64"})
    value.update(schema="iris-release-qualification-v2", profile=stage["profile"],
        release_kit_sha256=sha(stage["files"]["release-kit.json"]),
        candidate_evidence_sha256=sha(stage["files"]["candidate-evidence.json"]), image_identities=images,
        prebuilt_inputs={"original_candidate_sha256": sha(stage["files"]["local-candidate.json"]),
            "source_review_sha256": sha(stage["files"]["source-review.json"]),
            "preparation_sha256": sha(stage["files"]["prebuilt-preparation.json"]),
            "payload_asset_map_sha256": prep["payload_asset_map_sha256"],
            "image_inventory_sha256": sha(stage["files"]["image-components.json"])})
    value["checks"]["source-notices-review"]["evidence_sha256"] = sha(stage["files"]["source-review.json"])
    return value


def test_actual_prebuilt_gate_writer_acquires_both_profiles(prebuilt):
    record = STAGE.acquire_stage(prebuilt["selected"], prebuilt["output"], profile=prebuilt["profile"])
    assert record["schema"] == "iris-verified-release-stage-v2"
    assert record["profile"] == prebuilt["profile"]
    assert record["files"] == inventory(prebuilt["files"])
    assert "source validators were not rerun" in record["verification_scope"]
    signatures = [value for value in prebuilt["calls"] if isinstance(value, str)]
    assert signatures[0] == "release.json"
    assert set(signatures) == set(prebuilt["files"]) - {"attestations.jsonl"}


def test_prebuilt_qualification_binds_exact_writer_output_without_publishing(prebuilt):
    record = publish(prebuilt, prebuilt_qualification(prebuilt), profile=prebuilt["profile"])
    assert record["schema"] == "iris-release-publication-v2"
    assert record["qualification_is_reviewer_statement"] is True
    assert record["profile"] == prebuilt["profile"]
    assert json.loads((prebuilt["output"] / "assets/prebuilt-preparation.json").read_bytes())["review_statement_authenticated"] is False
    assert prebuilt["calls"][-1][0] == "/git/ref/tags/" + TAG


@pytest.mark.parametrize("profile", [None, "source-only", "other", False])
def test_prebuilt_never_infers_profile_or_bypasses_default(prebuilt, profile):
    options = {} if profile is None else {"profile": profile}
    with pytest.raises(STAGE.InstallError):
        STAGE.acquire_stage(prebuilt["selected"], prebuilt["output"], **options)
    assert not prebuilt["output"].exists()


def test_prebuilt_explicit_other_profile_refuses(prebuilt):
    other = "prepared-host" if prebuilt["profile"] == "ubuntu-dependencies" else "ubuntu-dependencies"
    with pytest.raises(STAGE.InstallError):
        STAGE.acquire_stage(prebuilt["selected"], prebuilt["output"], profile=other)


@pytest.mark.parametrize("field", ["profile", "schema", "release_kit_sha256", "candidate_evidence_sha256",
                                    "image_identities", "prebuilt_inputs", "assets", "reviewed_by"])
def test_prebuilt_qualification_selection_is_exact(prebuilt, field):
    value = prebuilt_qualification(prebuilt)
    value[field] = None
    with pytest.raises(STAGE.InstallError):
        publish(prebuilt, value, profile=prebuilt["profile"])
    assert not prebuilt["output"].exists()


def test_prebuilt_qualification_review_evidence_names_actual_statement(prebuilt):
    value = prebuilt_qualification(prebuilt)
    value["checks"]["source-notices-review"]["evidence_sha256"] = "0" * 64
    with pytest.raises(STAGE.InstallError, match="exact staged statement"):
        publish(prebuilt, value, profile=prebuilt["profile"])


@pytest.mark.parametrize("field,value", [("authenticated", True), ("review_statement_authenticated", 0),
    ("profile", "source-only"), ("staged_run", {"run_id": 31, "run_attempt": 2.0}),
    ("stage_record_sha256", "0" * 64), ("source_review_sha256", "0" * 64),
    ("payload_asset_map_sha256", "0" * 64), ("candidate_evidence_sha256", "0" * 64),
    ("delivery_assets", {}), ("companions", {}), ("git_source_parity", {}),
    ("review_attribution", {}), ("remaining_gates", []), ("unknown", True)])
def test_authenticated_but_inconsistent_preparation_refuses(prebuilt, field, value):
    files = dict(prebuilt["files"])
    record = json.loads(files["prebuilt-preparation.json"])
    record[field] = value
    files["prebuilt-preparation.json"] = STAGE._canonical(record)
    seal_prebuilt(prebuilt, files)
    with pytest.raises(STAGE.InstallError):
        STAGE.acquire_stage(prebuilt["selected"], prebuilt["output"], profile=prebuilt["profile"])
    assert not prebuilt["output"].exists()


@pytest.mark.parametrize("fault", ["extra", "missing-review", "missing-helper", "missing-source", "renamed-source",
                                    "wrong-stage", "unsigned-metadata", "bad-size-type", "null-files"])
def test_prebuilt_closed_set_and_authentication_boundary(prebuilt, fault, monkeypatch):
    files = dict(prebuilt["files"])
    if fault == "extra":
        files["extra.bin"] = b"unsupported"
    elif fault.startswith("missing-"):
        del files[{"missing-review": "source-review.json", "missing-helper": "release-auth.py",
                   "missing-source": "iris-runtime-sources.tar.gz"}[fault]]
    elif fault == "renamed-source":
        files["another-source.tar.gz"] = files.pop("iris-runtime-sources.tar.gz")
    elif fault == "wrong-stage":
        files["release-stage.json"] = STAGE._canonical(STAGE._stage_record(TAG, COMMIT, 31, 3))
    elif fault in ("bad-size-type", "null-files"):
        evidence = json.loads(files["candidate-evidence.json"])
        if fault == "bad-size-type":
            evidence["files"]["iris.tgz"]["size"] = True
        else:
            evidence["files"] = None
        files["candidate-evidence.json"] = STAGE._canonical(evidence)
    else:
        def refuse(path, *args):
            if path.name == "source-review.json":
                raise STAGE.InstallError("unsigned fixture review")
        monkeypatch.setattr(STAGE, "_verify_signature", refuse)
        monkeypatch.setattr(STAGE, "_prebuilt_metadata", lambda *args: pytest.fail("claims read before signatures"))
    seal_prebuilt(prebuilt, files)
    with pytest.raises(STAGE.InstallError):
        STAGE.acquire_stage(prebuilt["selected"], prebuilt["output"], profile=prebuilt["profile"])
    assert not prebuilt["output"].exists()


@pytest.mark.parametrize("filename,keys,value", [
    ("release-kit.json", ("assets",), []),
    ("release-kit.json", ("assets", "server-image", "size"), True),
    ("release-kit.json", ("assets", "server-image", "image_digest"), "sha256:" + "0" * 64),
    ("release-kit.json", ("profile",), "source-only"),
    ("release-kit.json", ("host", "version"), 24.04),
    ("image-components.json", ("authenticated",), 0),
    ("image-components.json", ("commit_scope",), "all-images"),
    ("image-components.json", ("images", "server-image"), []),
    ("image-components.json", ("images", "console-image", "revision_label"), "0" * 40),
    ("image-components.json", ("images", "device-runtime", "platforms"), None),
    ("image-components.json", ("images", "device-runtime", "source_commit_binding"), "verified"),
    ("candidate-evidence.json", ("authenticated",), 0),
    ("candidate-evidence.json", ("external_pins", "pip_sdist_sha256"), "untrusted"),
    ("candidate-evidence.json", ("neutral_source_sha256",), "0" * 64),
    ("candidate-evidence.json", ("source_agreement", "canonical_file_count"), 3.0),
    ("candidate-evidence.json", ("source_agreement", "git_provenance_verified"), 0),
    ("candidate-evidence.json", ("source_agreement", "additional_tar_files", "MANIFEST.txt", "mode"), 0o600),
    ("candidate-evidence.json", ("companions", "aria2", "binary_sha256", "aarch64"), "0" * 64),
    ("local-candidate.json", ("authenticated",), 0),
    ("local-candidate.json", ("version",), "2020.01.01"),
    ("local-candidate.json", ("unknown",), True),
])
def test_resealed_inner_metadata_joins_are_strict(prebuilt, filename, keys, value):
    files = dict(prebuilt["files"])
    record = json.loads(files[filename])
    target = record
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = value
    files[filename] = STAGE._canonical(record)
    rebind_prebuilt(prebuilt, files)
    with pytest.raises(STAGE.InstallError):
        STAGE.acquire_stage(prebuilt["selected"], prebuilt["output"], profile=prebuilt["profile"])
    assert not prebuilt["output"].exists()


@pytest.mark.parametrize("name", ["release-auth.py", "aria2c-aarch64", "MANIFEST.txt", "iris.tgz.sha256",
                                   "aria2c.sha256", "iris-device-neutral.oci.tar.manifest",
                                   "iris-server-image-config.json"])
def test_resealed_delivery_and_image_evidence_cannot_alias_other_bytes(prebuilt, name):
    files = dict(prebuilt["files"])
    files[name] += b"changed fixture\n"
    rebind_prebuilt(prebuilt, files)
    with pytest.raises(STAGE.InstallError):
        STAGE.acquire_stage(prebuilt["selected"], prebuilt["output"], profile=prebuilt["profile"])
    assert not prebuilt["output"].exists()


def test_source_only_cannot_be_selected_as_prebuilt(stage):
    with pytest.raises(STAGE.InstallError):
        STAGE.acquire_stage(stage["selected"], stage["output"], profile="prepared-host")
    assert not stage["output"].exists()


def test_cli_explicit_profile_preserves_source_only_default(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(STAGE, "acquire_stage", lambda *args, **kwargs: calls.append(kwargs["profile"]))
    args = ["acquire", "--tag", TAG, "--commit", COMMIT, "--run-id", "31", "--run-attempt", "2",
            "--artifact-id", "47", "--artifact-sha256", "a" * 64, "--output-dir", str(tmp_path / "unused")]
    assert STAGE.main(args) == 0
    assert STAGE.main(args + ["--profile", "ubuntu-dependencies"]) == 0
    assert calls == ["source-only", "ubuntu-dependencies"]


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


def test_source_stage_matches_actual_installer_builder_and_release_prepare(stage, tmp_path):
    if shutil.which("dpkg-deb") is None:
        pytest.skip("actual lightweight installer writer needs dpkg-deb")
    repo, output = tmp_path / "writer-repo", tmp_path / "writer-assets"
    repo.mkdir()
    output.mkdir()
    sources = {"VERSION": TAG[1:] + "\n", "LICENSE": "Fixture license\n",
               "docs/dev/installer.md": "Fixture installer documentation\n",
               "tools/iris_installer/__init__.py": "# Fixture package\n",
               "tools/irisctl": "#!/usr/bin/env python3\n",
               "tools/iris-key-setup": "#!/usr/bin/env python3\n",
               "tools/release-auth.py": "# Fixture shipped helper, never executed\n",
               "release/iris.tgz": "fixture source archive",
               "release/iris.tgz.sha256": "fixture source sidecar",
               "release/MANIFEST.txt": "fixture source manifest"}
    aria_source = b"fixture pinned corresponding aria source"
    sources["tools/aria2c-source/source.sha256"] = sha(aria_source) + "  aria2c-2.5.6-p10-source.tar.gz\n"
    sources["tools/aria2c.sha256"] = "".join(sha(arch.encode()) + "  " + arch + "\n" for arch in ("x86_64", "aarch64"))
    for arch in ("x86_64", "aarch64"):
        sources["deliverables/aria2c-" + arch] = arch
    for name, text in sources.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for command in (["init", "-q"], ["add", "."],
                    ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Writer fixture"],
                    ["tag", TAG]):
        subprocess.run(["git", "-C", str(repo), *command], check=True)
    commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    spec = importlib.util.spec_from_file_location("actual_installer_writer", ROOT / "tools/build-installer-package.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    builder.build(repo, output)
    packages = list(output.glob("*.deb"))
    assert [path.name for path in packages] == ["iris-installer_" + TAG[1:] + "+installer.0.g" + commit[:12] + "_amd64.deb"]
    (output / "aria2c-2.5.6-p10-source.tar.gz").write_bytes(aria_source)
    STAGE.create_stage_record(output / "release-stage.json", TAG, commit, 31, 2)
    STAGE._auth().prepare(repo, output, TAG)
    (output / "attestations.jsonl").write_bytes(stage["files"]["attestations.jsonl"])
    files = {path.name: path.read_bytes() for path in output.iterdir()}
    replace_files(stage, files)
    stage["selected"]["commit"] = commit
    stage["run"]["head_sha"] = commit
    stage["artifact"]["workflow_run"]["head_sha"] = commit
    record = STAGE.acquire_stage(stage["selected"], stage["output"])
    assert record["files"] == inventory(files)


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


@pytest.mark.parametrize("change", ["bytes", "schema-bool", "size-float", "stage-attempt", "checksums", "unknown", "prebuilt", "missing", "plain-package", "other-commit-package"])
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
    elif change in ("plain-package", "other-commit-package"):
        suffix = "+installer.0.g" + COMMIT[:12]
        replacement = "" if change == "plain-package" else "+installer.0.g" + "b" * 12
        for name in list(files):
            if suffix in name:
                files[name.replace(suffix, replacement)] = files.pop(name)
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
    workflow = yaml.load(text, Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"workflow_dispatch"}
    profile = workflow["on"]["workflow_dispatch"]["inputs"]["profile"]
    assert profile == {"description": "Exact authenticated stage profile", "required": "true",
                       "type": "choice", "default": "source-only",
                       "options": ["source-only", "prepared-host", "ubuntu-dependencies"]}
    job = workflow["jobs"]["publish"]
    assert workflow["permissions"] == {"contents": "read"}
    assert job["permissions"] == {"actions": "read", "contents": "write"}
    assert job["if"] == ("github.repository == 'cisco-open/intelligent-release-image-staging' "
                         "&& github.ref == 'refs/heads/main'")
    assert job["env"]["RELEASE_PROFILE"] == "${{ inputs.profile }}"


@pytest.mark.parametrize("profile,refuse", [(None, False), ("source-only", False),
    ("prepared-host", False), ("ubuntu-dependencies", False), ("prepared-host", True),
    ("", False), ("prepared-host --tag other; $(touch profile-injection)", False)])
def test_actual_publisher_command_forwards_profile_before_inert_publication(tmp_path, profile, refuse):
    """Run the actual YAML shell body with real CLI parsing and inert endpoints.

    The helper's verification endpoint and gh executable are fixture recorders;
    this is command wiring, never hosted authentication or publication evidence.
    """
    workflow = yaml.load((ROOT / ".github/workflows/publish-release.yml").read_text(), Loader=yaml.BaseLoader)
    job = workflow["jobs"]["publish"]
    if profile is None:
        profile = workflow["on"]["workflow_dispatch"]["inputs"]["profile"]["default"]
    references = {"github.token": "inert-token", "inputs.profile": profile, "inputs.tag": TAG,
        "inputs.commit": COMMIT, "inputs.stage_run_id": "31", "inputs.stage_run_attempt": "2",
        "inputs.artifact_id": "47", "inputs.artifact_sha256": "a" * 64,
        "inputs.qualification_json": '{"fixture":"literal; $(touch qualification-injection)"}',
        "inputs.qualification_sha256": "b" * 64, "inputs.confirmation": "publish " + TAG + " " + "c" * 64}
    environment = {key: references[value.removeprefix("${{ ").removesuffix(" }}")]
                   for key, value in job["env"].items()}
    fixture_bin, fixture_tools = tmp_path / "bin", tmp_path / "tools"
    fixture_bin.mkdir()
    fixture_tools.mkdir()
    helper_log, gh_log = tmp_path / "helper.json", tmp_path / "gh.json"
    environment.update(PATH=str(fixture_bin) + ":" + str(Path(sys.executable).parent) + ":/usr/bin:/bin",
        LC_ALL="C", RUNNER_TEMP=str(tmp_path / "runner temp"), GITHUB_RUN_ID="91", GITHUB_RUN_ATTEMPT="3",
        GITHUB_ACTOR="dispatcher", GITHUB_ACTOR_ID="17", GITHUB_TRIGGERING_ACTOR="reviewer",
        IRIS_TEST_HELPER_LOG=str(helper_log), IRIS_TEST_GH_LOG=str(gh_log), IRIS_TEST_REFUSE=str(int(refuse)))
    # Execute the shipped CLI parser; replace only its external verification
    # endpoint, before main(), so malformed choices still use real argparse.
    (fixture_tools / "release-stage.py").write_text(
        "import importlib.util, json, os, sys\nfrom pathlib import Path\n"
        f"sys.path.insert(0, {str(ROOT / 'tools')!r})\n"
        f"spec = importlib.util.spec_from_file_location('fixture_stage', {str(ROOT / 'tools/release-stage.py')!r})\n"
        "module = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(module)\n"
        "def inert(selected, output, **options):\n"
        "    options['qualification'] = options['qualification'].decode()\n"
        "    Path(os.environ['IRIS_TEST_HELPER_LOG']).write_text(json.dumps({'argv':sys.argv[1:], "
        "'selection':selected, 'options':options}))\n"
        "    if os.environ['IRIS_TEST_REFUSE'] == '1':\n"
        "        raise module.InstallError('inert verification refusal')\n"
        "    assets = Path(output) / 'assets'\n    assets.mkdir(parents=True)\n"
        "    (assets / 'fixture.txt').write_text('inert verified placeholder')\n"
        "module.prepare_publication = inert\nraise SystemExit(module.main())\n")
    gh = fixture_bin / "gh"
    gh.write_text(f"#!{sys.executable}\nimport json, os, sys\nfrom pathlib import Path\n"
                  "Path(os.environ['IRIS_TEST_GH_LOG']).write_text(json.dumps(sys.argv[1:]))\n")
    gh.chmod(0o755)
    run = next(step["run"] for step in job["steps"] if "run" in step)
    result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", run], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, timeout=30)
    assert not (tmp_path / "profile-injection").exists()
    assert not (tmp_path / "qualification-injection").exists()
    if profile not in STAGE.PROFILES:
        assert result.returncode == 2 and "invalid choice" in result.stderr
        assert not helper_log.exists() and not gh_log.exists()
        return
    called = json.loads(helper_log.read_bytes())
    assert called["selection"] == STAGE.selection(TAG, COMMIT, 31, 2, 47, "a" * 64)
    assert called["argv"].count("--profile") == 1
    assert called["argv"][called["argv"].index("--profile") + 1] == profile
    assert called["options"] == {"profile": profile,
        "qualification": references["inputs.qualification_json"], "qualification_sha256": "b" * 64,
        "confirmation": references["inputs.confirmation"], "actor": "dispatcher", "actor_id": 17,
        "triggering_actor": "reviewer", "token": "inert-token"}
    if refuse:
        assert result.returncode == 1 and not gh_log.exists()
    else:
        assert result.returncode == 0, result.stderr
        assert json.loads(gh_log.read_bytes()) == ["release", "create", TAG,
            str(tmp_path / "runner temp/iris-publish-91-3/assets/fixture.txt"),
            "--repo", STAGE.REPOSITORY, "--verify-tag", "--title", "IRIS " + TAG, "--generate-notes"]
