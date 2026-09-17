# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import os
from pathlib import Path
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "tools/check-host-time.sh"


@pytest.mark.parametrize("status,ok", [
    ("Leap status : Normal\nStratum : 5\nReference ID : C000027B", True),
    ("Leap status : Not synchronised\nStratum : 0", False),
    ("Leap status : Normal\nStratum : 16", False),
    ("Leap status : Normal\nStratum : 5", False),
    ("Leap status : Normal\nStratum : 5\nReference ID : 7F7F0101 (LOCAL)", False),
    ("", False),
])
def test_host_check_is_read_only_and_requires_sync(tmp_path, status, ok):
    command = tmp_path / "chronyc"
    command.write_text('#!/bin/sh\n[ "$*" = tracking ] || exit 99\n'
                       'printf "%s\\n" "$FIXTURE_STATUS"\n')
    command.chmod(0o755)
    result = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True,
                            env=dict(os.environ, PATH=str(tmp_path) + ":" + os.environ["PATH"],
                                     FIXTURE_STATUS=status), timeout=15)
    assert (result.returncode == 0) is ok
    assert "100.90.0.254" not in SCRIPT.read_text()


@pytest.mark.parametrize("sync,enabled,ok", [
    ("yes", "yes", True), ("yes", "no", False),
    ("no", "yes", False), ("", "yes", False),
])
def test_systemd_requires_enabled_and_synchronized(tmp_path, sync, enabled, ok):
    # Isolate discovery from any real host chrony installation.
    for name in ("timeout", "grep"):
        import shutil
        (tmp_path / name).symlink_to(shutil.which(name))
    command = tmp_path / "timedatectl"
    command.write_text('#!/bin/sh\ncase "$*" in\n'
                       '"show -p NTPSynchronized --value") echo "$FIXTURE_SYNC";;\n'
                       '"show -p NTP --value") echo "$FIXTURE_ENABLED";;\n'
                       '*) exit 99;;\nesac\n')
    command.chmod(0o755)
    result = subprocess.run(["/bin/bash", str(SCRIPT)], capture_output=True, text=True,
                            env=dict(os.environ, PATH=str(tmp_path),
                                     FIXTURE_SYNC=sync, FIXTURE_ENABLED=enabled), timeout=15)
    assert (result.returncode == 0) is ok
