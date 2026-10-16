# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Actual worker projections consumed by the Console's production parser.

This is a local contract check, not live Docker or Kubernetes qualification.
"""

import json
from pathlib import Path
import shutil
import subprocess
import uuid

import pytest

from test_lifecycle_retention import worker, finished


def test_console_parses_real_history_retirement_and_unknown_archive_status(worker):
    node = shutil.which('node')
    if node is None:
        pytest.skip('Console contract check requires Node.js')
    failed = finished()
    capture = dict(finished('backup'), state='captured')
    worker.jobs = [failed, capture]
    worker.save()
    # An unowned physical directory has a nullable date and no delete action.
    (worker.backup_dir / str(uuid.uuid4())).mkdir(mode=0o700)
    before = worker.status()
    payload = {'action': 'retire-history', 'request_id': str(uuid.uuid4()),
               'expected_revision': before['retention']['revision'], 'job_ids': [failed['id']]}
    result = worker.submit(payload)
    after = worker.status(payload['request_id'])
    source = Path(__file__).parents[1] / 'console-ui/src'
    program = '''
import assert from 'node:assert/strict';
import fs from 'node:fs';
const {workerStatus} = await import(process.argv[1]);
const {matchingRetention} = await import(process.argv[2]);
const {before, after, payload, result} = JSON.parse(fs.readFileSync(0, 'utf8'));
assert.ok(workerStatus(before, 'backups'), 'Actual pre-retirement worker status');
assert.ok(workerStatus(after, 'backups'), 'Actual post-retirement worker status');
assert.ok(matchingRetention(result.retention_operation, payload));
assert.equal(after.retention.operation.request_id, payload.request_id);
assert.equal(after.retention.capacity.history_used, before.retention.capacity.history_used - 1);
assert.equal(after.retention.backups[0].created_at, null);
assert.equal(after.retention.backups[0].delete_allowed, false);
'''
    subprocess.run([node, '--input-type=module', '-e', program,
                    (source / 'worker-lifecycle-model.mjs').as_uri(),
                    (source / 'backup-retention-model.mjs').as_uri()],
                   input=json.dumps(dict(before=before, after=after, payload=payload, result=result)),
                   text=True, capture_output=True, check=True, timeout=15)
