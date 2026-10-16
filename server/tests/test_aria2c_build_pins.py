# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exact inputs for the aria2 client distributed with its matching GPLv3 source.

Two failure modes, two kinds of test here:

* Drift. A pin quietly relaxed to a floating package name would make a rebuild
  produce something other than what the recipe describes. The hermetic tests
  below assert the pinning discipline the file is built around: base image by
  digest, every apk package by exact version, no `latest`.

* Withdrawal. An Alpine release branch indexes only the newest `-rN` of each
  package, so a security bump deletes the version we pinned and `apk add`
  refuses the whole set. That is a hard, correct failure -- but it strands the
  original index-based recipe. The retained-input helper instead acquires exact
  checksum-locked APKs and uses the original source and compiler commands.
  Opt-in tests download that complete lock, including transitive dependencies.
  A changed dependency requires a deliberately matched binary/source release,
  never a pin-only change to the published client's recipe.

The opt-in test needs network, so it runs under the same IRIS_TEST_HOST_INTEGRATION=1
gate as the real-`docker build` tests."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import os
from pathlib import Path
import re

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
DOCKERFILE = os.path.join(HERE, "..", "..", "tools", "aria2c-build", "Dockerfile")

# build.sh drives both architectures; a pin must resolve for each.
ARCHES = ("x86_64", "aarch64")


def _text():
    return open(DOCKERFILE).read()


def _from_ref():
    """The first FROM line's image reference."""
    for line in _text().splitlines():
        m = re.match(r"^FROM\s+(\S+)", line)
        if m:
            return m.group(1)
    raise AssertionError("no FROM line in %s" % DOCKERFILE)


def _apk_add_block():
    """The `RUN apk add ...` command, continuation lines joined."""
    joined = _text().replace("\\\n", " ")
    for line in joined.splitlines():
        stripped = line.strip()
        if stripped.startswith("RUN apk add"):
            return re.sub(r"\s+", " ", stripped)
    raise AssertionError("no `RUN apk add` line in %s" % DOCKERFILE)


def _apk_packages():
    """Package arguments of the apk add command, as written (flags dropped)."""
    args = _apk_add_block().split()[3:]  # drop RUN, apk, add
    return [a for a in args if not a.startswith("-")]


def _apk_pins():
    """[(name, version)] for every pinned package."""
    pins = []
    for pkg in _apk_packages():
        name, sep, version = pkg.partition("=")
        assert sep, "package %r in %s is not version-pinned" % (pkg, DOCKERFILE)
        pins.append((name, version))
    return pins


# --------------------------------------------------------------------------
# Hermetic: the pinning discipline itself.
# --------------------------------------------------------------------------

def test_base_image_is_pinned_by_digest():
    ref = _from_ref()
    assert "@sha256:" in ref, (
        "the aria2c build base must be pinned by digest, got %s" % ref)
    assert not ref.split("@")[0].endswith(":latest"), (
        "the aria2c build base must not float on :latest, got %s" % ref)


def test_every_apk_package_is_pinned_to_an_exact_version():
    pins = _apk_pins()
    assert pins, "no packages found in the apk add line"
    for name, version in pins:
        assert re.fullmatch(r"[0-9][0-9A-Za-z._]*-r\d+", version), (
            "%s is not pinned to an exact Alpine version (got %r)" % (name, version))


def test_apk_add_does_not_float():
    block = _apk_add_block()
    assert "--no-cache" in block, "apk add must not leave an index cache behind"
    assert "latest" not in block, "no package in the apk add line may float on latest"
    # `apk upgrade` would pull newer packages than the pins name, defeating them.
    assert "apk upgrade" not in _text(), (
        "apk upgrade would move packages off their pins")


def test_openssl_dev_and_static_pins_move_together():
    # openssl-dev and openssl-libs-static are built from one source package;
    # a build that mixes versions links headers against a different library
    # than it statically embeds.
    pins = dict(_apk_pins())
    assert "openssl-dev" in pins and "openssl-libs-static" in pins
    assert pins["openssl-dev"] == pins["openssl-libs-static"], (
        "openssl-dev=%s but openssl-libs-static=%s"
        % (pins["openssl-dev"], pins["openssl-libs-static"]))


# --------------------------------------------------------------------------
# Opt-in: can the exact retained-input path still acquire every package?
# --------------------------------------------------------------------------

def _pinned_helper():
    spec = importlib.util.spec_from_file_location("aria2_pinned_inputs",
        Path(DOCKERFILE).with_name("rebuild-pinned.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_recorded_apk_lock_covers_each_original_recipe_pin():
    lock = _pinned_helper().lock_data()
    assert lock['base_image'] == _from_ref()
    for architecture in ARCHES:
        for name, version in _apk_pins():
            assert name + '-' + version + '.apk' in lock['packages'][architecture]


@pytest.mark.skipif(
    os.environ.get("IRIS_TEST_HOST_INTEGRATION") != "1",
    reason="network test: set IRIS_TEST_HOST_INTEGRATION=1 to download and verify "
           "all checksum-locked aria2 build APKs",
)
@pytest.mark.parametrize("arch", ARCHES)
def test_every_locked_build_input_remains_available(arch, tmp_path):
    helper = _pinned_helper()
    lock = helper.lock_data()
    with ThreadPoolExecutor(max_workers=4) as pool:
        files = list(pool.map(lambda item: helper.cached_package(
            tmp_path, arch, item[0], item[1], lock['mirrors']), lock['packages'][arch].items()))
    assert len(files) == len(lock['packages'][arch])


def test_size_gate_reads_a_byte_count_not_filesystem_stats():
    """The published build's size gate must actually compare a number.

    `stat -f %z` is BSD/macOS for "size of this file", but on GNU coreutils
    `-f` is --file-system: it SUCCEEDS and prints a block of filesystem stats.
    With the BSD form tried first the `||` fallback never runs on Linux,
    $bytes becomes multi-line text, and every `[ "$bytes" -gt ... ]` below
    dies with "integer expression expected" -- which is not fatal inside an
    `if`, so the gate silently passed everything, including a binary over the
    hard-fail ceiling it exists to catch. GNU form must come first.
    """
    import subprocess
    build_sh = os.path.join(HERE, "..", "..", "tools", "aria2c-build", "build.sh")
    with open(build_sh, encoding="utf-8") as fh:
        src = fh.read()
    line = next((l for l in src.splitlines() if l.strip().startswith("bytes=")), None)
    assert line, "build.sh no longer assigns bytes= for the size gate"
    gnu, bsd = line.find("stat -c"), line.find("stat -f")
    assert gnu != -1 and bsd != -1, "expected both stat forms with a fallback"
    assert gnu < bsd, (
        "BSD `stat -f %%z` is tried before GNU `stat -c %%s`, so on Linux the "
        "size gate reads filesystem stats and never fires: %s" % line.strip())

    # And prove it end to end on this host rather than trusting the ordering.
    out = subprocess.run(["bash", "-c", line.strip() + '; printf "%s" "$bytes"'],
                         capture_output=True, text=True,
                         env={"ARTIFACT": build_sh, "PATH": "/usr/bin:/bin"})
    assert out.stdout.strip().isdigit(), (
        "the size-gate assignment did not yield a plain byte count: %r" % out.stdout)


@pytest.mark.parametrize("value", ["", "0", "-1", "01", "2.5", "auto", "2;exit 0"])
def test_build_rejects_invalid_parallelism_before_source_access(value):
    import subprocess
    driver = os.path.join(HERE, "..", "..", "tools", "aria2c-build", "build.sh")
    env = dict(os.environ, ARIA2C_BUILD_JOBS=value)
    result = subprocess.run(["bash", driver, "aarch64"], env=env,
                            capture_output=True, text=True)
    assert result.returncode == 2
    assert "ARIA2C_BUILD_JOBS must be a positive integer" in result.stderr


def test_compiler_and_lto_share_explicit_worker_bound():
    # Both compiler scheduling and GCC's separately spawned LTRANS workers
    # must use the same argument; limiting Ninja alone leaves LTO unbounded.
    text = _text()
    assert "ARG ARIA2C_BUILD_JOBS=2" in text
    assert '-j"$ARIA2C_BUILD_JOBS"' in text
    assert '-DIRIS_LTO_JOBS="$ARIA2C_BUILD_JOBS"' in text
    assert 'CMAKE_${lang}_COMPILE_OPTIONS_IPO REPLACE "^-flto(=.*)?$" "-flto=${IRIS_LTO_JOBS}"' in text
    assert "-DARIA2_RELEASE_LTO=ON" in text
    assert "$(nproc)" not in text
