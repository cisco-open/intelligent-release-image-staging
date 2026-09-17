# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.parametrize("rc,detailed,kept", [(0, "off", False), (0, "on", True),
                                           (255, "off", True)])
def test_success_close_notice_only_is_quiet(tmp_path, rc, detailed, kept):
    script = (Path(__file__).resolve().parents[1] / "device-run.sh").read_text()
    block = script.split('if [ -s "$ERR_COPY" ]; then', 1)[1].split('\nfi', 1)[0]
    error = tmp_path / "stderr"
    error.write_text("Connection to 192.0.2.1 closed.\n"
                     "Connection to 192.0.2.1 closed by remote host.\n"
                     "Permission denied fixture-secret\n")
    result = subprocess.run(["bash", "-c", 'iris_ssh_explain() { :; };\n' + block],
                            env=dict(os.environ, ERR_COPY=str(error), HOST="192.0.2.1",
                                     RUN_STATUS=str(rc), IRIS_LOG=detailed,
                                     DEVICE_PASS="fixture-secret"),
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0
    assert ("Connection to" in result.stderr) is kept
    assert "Permission denied [REDACTED]" in result.stderr
    assert "fixture-secret" not in result.stderr
