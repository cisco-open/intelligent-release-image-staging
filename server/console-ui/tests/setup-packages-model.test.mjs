// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {setupStatus, setupChip, packageRemedy, telemetryNote, firstIncomplete, incompleteCount} from '../src/setup-packages-model.mjs';
import {setupFixture} from './setup-packages-fixtures.mjs';

test('setup projection is complete, bounded and does not copy extra fields', () => {
  const raw = setupFixture(); raw.secret = 'must-not-render'; raw.packages.items[0].secret = 'must-not-render';
  const status = setupStatus(raw); assert.ok(status); assert.equal(JSON.stringify(status).includes('must-not-render'), false);
  assert.equal(status.packages.items[0].built_at, 1790000000); assert.equal(firstIncomplete(status), 2); assert.equal(incompleteCount(status), 0);
});
const invalid = [
  ['missing account', value => {delete value.admin;}],
  ['unknown account shown done', value => {value.admin.username = '';}],
  ['enabled export with no endpoint shown done', value => {value.telemetry.state = 'ok'; value.telemetry.enabled = true;}],
  ['unknown export source', value => {value.telemetry.source = 'maybe';}],
  ['missing package list', value => {value.packages.items = [];}],
  ['missing Guest Shell readiness', value => {value.packages.items.pop();}],
  ['missing required wrapper', value => {value.packages.items.shift();}],
  ['duplicate package', value => {value.packages.items[1] = value.packages.items[0];}],
  ['unknown package', value => {value.packages.items[1].name = 'other.tar';}],
  ['package not a deployment-neutral wrapper', value => {value.packages.items[0].fingerprint = 'cert';}],
  ['missing provenance on ready wrapper', value => {value.packages.items[0].provenance = null;}],
  ['bad canonical digest', value => {value.packages.items[0].provenance.canonical_index_digest = 'sha256:bad';}],
  ['missing timestamp on ready wrapper', value => {value.packages.items[0].built_at = null;}],
  ['out of range timestamp', value => {value.packages.items[0].built_at = Number.MAX_SAFE_INTEGER;}],
  ['unbounded evidence', value => {value.packages.items[0].detail = 'a'.repeat(4097);}],
  ['unknown rollup', value => {value.packages.state = 'future';}],
  ['unjustified healthy rollup', value => {value.packages.items[0].state = 'stale'; value.packages.items[0].provenance = null;}],
  ['null certificate without failure reason', value => {value.packages.reference_fingerprint = null;}],
  ['malformed certificate fingerprint', value => {value.packages.reference_fingerprint = 'ab';}],
  ['unknown certificate failure', value => {value.packages.reason = 'maybe';}],
  ['unknown verification state', value => {value.image_verification.state = 'running';}],
];
for (const [name, mutate] of invalid) test('reject ' + name, () => {const raw = setupFixture(); mutate(raw); assert.equal(setupStatus(raw), null);});
test('absent platform is inactive and only real package failures trigger a nudge', () => {
  const raw = setupFixture(); Object.assign(raw.packages.items[1], {state: 'absent', built_at: null, provenance: null, reason: 'absent'}); raw.packages.state = 'absent';
  const status = setupStatus(raw); assert.ok(status); assert.equal(setupChip('packages', status.packages.state).level, 'inactive'); assert.equal(firstIncomplete(status), 1); assert.equal(incompleteCount(status), 0);
  Object.assign(raw.packages.items[1], {state: 'unknown', reason: 'provenance-absent'}); raw.packages.state = 'unknown';
  assert.equal(incompleteCount(setupStatus(raw)), 1);
});
test('valid Guest Shell startup evidence is distinct from wrapper provenance', () => {
  const raw = setupFixture();
  assert.ok(setupStatus(raw)); raw.packages.items[3].reason = 'startup-provisioning-unconfirmed'; assert.equal(setupStatus(raw), null);
});
test('certificate mismatch remains separate and never prescribes a package rebuild', () => {
  const raw = setupFixture(); raw.packages.state = 'unknown'; raw.packages.reason = 'served-vs-distributed-mismatch';
  const status = setupStatus(raw); assert.ok(status); const remedy = packageRemedy(status.packages);
  assert.match(remedy, /Fix the certificate copies/); assert.doesNotMatch(remedy, /tools\//); assert.equal(status.packages.items.every(row => row.state === 'ok'), true);
});
test('remedies include unknown manifests and deduplicate commands', () => {
  const raw = setupFixture(); raw.packages.state = 'unknown'; raw.packages.items.forEach(row => {Object.assign(row, {state: 'unknown', provenance: null, reason: 'provenance-absent'});});
  const remedy = packageRemedy(setupStatus(raw).packages); assert.equal((remedy.match(/tools\/provision-iox-packages.sh/g) || []).length, 1); assert.match(remedy, /tools\/build-xr-package.sh/); assert.doesNotMatch(remedy, /re-onboard/);
});
test('configured verification is not conflated with success or unknown evidence', () => {
  assert.equal(setupChip('image_verification', 'unset', true).label, 'Configured — no successful run yet');
  assert.equal(setupChip('image_verification', 'unknown', true).label, 'Cannot determine');
  assert.equal(setupChip('image_verification', 'ok', true).label, 'Done');
  assert.equal(setupChip('image_verification', 'unset', null).level, 'info');
  assert.equal(telemetryNote(setupFixture().telemetry), 'Export is disabled (deployment default).');
});
test('the shipped native setup_status outputs satisfy the browser contract', () => {
  const script = `import json, pathlib, tempfile, hashlib, sys, tarfile, io
sys.path.insert(0, sys.argv[1])
import setup_status as native
with tempfile.TemporaryDirectory(prefix='iris-setup-contract-') as directory:
    root = pathlib.Path(directory)
    # This parser only fingerprints DER bytes; no TLS acceptance is claimed.
    cert = root / 'public.pem'
    cert.write_text('-----BEGIN CERTIFICATE-----\\nYWJj\\n-----END CERTIFICATE-----\\n')
    other = root / 'other.pem'
    other.write_text('-----BEGIN CERTIFICATE-----\\nZGVm\\n-----END CERTIFICATE-----\\n')
    provision = root / 'served-bundle.json'
    def status(**kwargs):
        return native.build_status(str(root), str(kwargs.pop('served', cert)), str(kwargs.pop('distributed', cert)), 'operator', provision_status_path=str(provision), provision_startup_state=kwargs.pop('provision_startup_state', 'ok'), **kwargs)
    cases = [status(), status(served='/missing-certificate')]
    for name, kind, platform, remedy in native._PACKAGE_SPECS:
        data = ('fixture:' + name).encode()
        (root / name).write_bytes(data)
        values = {'format': 'iris-device-wrapper-v1', 'wrapper_kind': kind, 'wrapper_file': name, 'platform': platform, 'wrapper_sha256': hashlib.sha256(data).hexdigest(), 'canonical_index_digest': 'sha256:' + 'a' * 64, 'canonical_archive_sha256': 'b' * 64, 'canonical_source_sha256': 'c' * 64}
        (root / (name + '.manifest')).write_text(''.join(key + '=' + value + '\\n' for key, value in values.items()))
    embedded = {'iris-signers.allowed_signers': b'public-signers', 'iris-root.allowed_signers': b'public-roots'}
    with tarfile.open(root / 'iris-agent.tgz', 'w:gz') as archive:
        for name, data in embedded.items():
            member = tarfile.TarInfo(name); member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    (root / 'iris-signers.pem').write_bytes(embedded['iris-signers.allowed_signers'])
    (root / 'bootstrap.sh').write_bytes(b'fixture-bootstrap')
    bundle_hash = hashlib.sha256((root / 'iris-agent.tgz').read_bytes()).hexdigest()
    (root / 'iris-agent.tgz.sha256').write_text(bundle_hash + '\\n')
    record = {'format': 'iris-served-bundle-v1', 'state': 'ok'}
    for name in ('iris-agent.tgz', 'iris-agent.tgz.sha256', 'bootstrap.sh', 'iris-signers.pem'):
        record[name] = hashlib.sha256((root / name).read_bytes()).hexdigest()
    for name, data in embedded.items(): record[name] = hashlib.sha256(data).hexdigest()
    provision.write_text(json.dumps(record))
    cases += [status(), status(distributed=other), status(provision_startup_state='failed')]
    (root / 'iris-amd64.tar').write_bytes(b'changed')
    cases.append(status())
    print(json.dumps(cases))
`;
  const result = spawnSync('python3', ['-c', script, fileURLToPath(new URL('../../', import.meta.url))], {encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr); const cases = JSON.parse(result.stdout); assert.equal(cases.length, 6);
  cases.forEach((row, index) => assert.ok(setupStatus(row), 'native fixture ' + index));
});
