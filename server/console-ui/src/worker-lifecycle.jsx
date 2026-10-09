// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {createPortal} from 'react-dom';
import {WorkerLifecycleController} from './worker-lifecycle-controller.mjs';
import {familyLabels, topologyLabels, activeJobs} from './worker-lifecycle-model.mjs';
import {trustFamilies} from './deployment-trust-model.mjs';
import {maintenanceAction} from './key-maintenance-model.mjs';

function WorkerLifecycle({controller: c, roots}) {
  const s = useSyncExternalStore(c.subscribe, c.snapshot), focus = useRef(null), outcomes = useRef({});
  useLayoutEffect(() => {
    const {node, group} = focus.current || {};
    if (!c.visible() || !node) return;
    if ((!node.isConnected || node.disabled) && (document.activeElement === document.body || document.activeElement === node)) outcomes.current[group]?.focus();
  }, [s, c]);
  const message = (group, id) => <p id={id} role="status" aria-live="polite" tabIndex={-1} ref={node => {outcomes.current[group] = node;}}>{s.messages[group]?.text || ''}</p>;
  const files = (name, title, action, accept) => <label className="worker-field">{title}<input key={s.fileEpoch + ':' + name} id={'deployment-rotation-' + name} type="file" accept={accept} disabled={!c.canTrust(action)} onChange={event => c.file(name, event.target.files[0])} /></label>;
  const item = s.valid.trust ? c.item() : null, trust = trustFamilies.includes(s.family), state = item?.state || 'unavailable', worker = s.valid.rotation ? s.rotation : null;
  const attest = item?.family === 'instruction-roots' && ['idle', 'published', 'cancelled'].includes(state) && Object.keys(item.roots).length === 2;
  const blockers = c.ready('rotation', 'backups') ? activeJobs(s) : [];
  const trustButton = (action, label) => <button className={'btn' + (action === 'cancel' ? ' ghost' : '')} id={'deployment-rotation-' + action} disabled={!c.canTrust(action)} onClick={() => c.performTrust(action)}>{label}</button>;
  const deployment = <div className="card" id="deployment-rotation-workflow" data-worker-group="deployment">
    <h3>Rotate deployment trust and keys</h3>
    <p>Plan a maintenance window. The host worker verifies a cold backup before changing credentials. Device trust changes require removing IRIS from affected devices first, then onboarding with the replacement trust.</p>
    <label className="worker-field">Credential family<select id="deployment-rotation-family" value={s.family} disabled={s.busy} onChange={event => c.field('family', event.target.value)}>{Object.entries(familyLabels).filter(([family]) => family !== 'age-recovery').map(([family, label]) => <option value={family} key={family}>{label}</option>)}</select></label>
    <p id="deployment-rotation-worker" role="status">{s.loading.rotation ? 'Checking deployment maintenance…' : worker ? 'Deployment: ' + topologyLabels[worker.target] + '. ' + worker.note : 'Worker state unavailable. Refresh before starting maintenance.'}</p>
    <p id="deployment-rotation-state" role="status">{trust ? 'Trust request: ' + state.replaceAll('-', ' ') + '. Publication requires stopped writers and confirmed device removal.'
      : s.family === 'age-identity' ? 'Replace the server encryption identity and retain the independently held recovery recipient. Existing backups keep their original recovery requirements.'
        : s.family === 'seeder-announce' ? 'Pause normal writers while an isolated tracker and seeder verify the replacement credential against published torrents.'
          : 'Replace the internal TLS key and certificate, update Console trust, and verify authenticated connections from every deployed Console.'}</p>
    {blockers.length > 0 && <p className="muted">A worker operation is running or requires recovery. Review its history before starting another operation.</p>}
    {s.unknown.backups && <p>Review the uncertain operation in <a href="#settings/backups">Backup &amp; restore</a> before starting maintenance.</p>}
    <div id="deployment-rotation-trust" hidden={!trust}>
      <p><a href="#devices">Open devices to remove IRIS deployments</a>. A missing or abandoned device is not proof of removal.</p>
      {item?.request_id && <p className="machine">Request: {item.request_id}{item.names.length > 0 && <><br />Requested names: {item.names.join(', ')}</>}</p>}
      {s.valid.trust && <p>{s.trust.drain.ready ? 'Recorded deployments are removed; the worker will check again after stopping writers.' : 'Removal required: ' + s.trust.drain.blocked_device_ids.join(', ') + '.'}</p>}
      <div id="deployment-rotation-tls" className="maintenance-form" hidden={s.family !== 'device-tls'}>
        <label>Exact device-facing DNS names or IP addresses, comma-separated<input id="deployment-rotation-names" value={s.names} disabled={!c.canTrust('prepare')} onChange={event => c.field('names', event.target.value)} placeholder="iris.example.com, 192.0.2.10" /></label>
        <label>Approval method<select id="deployment-rotation-mode" value={s.mode} disabled={!c.canTrust('prepare')} onChange={event => c.field('mode', event.target.value)}><option value="ca">Request approval from my CA</option><option value="self-signed">Create a self-signed certificate (90 days)</option></select></label>
      </div>
      <div id="deployment-rotation-roots" hidden={s.family !== 'instruction-roots'}>
        <p>Create replacement keys in <strong>IRIS Offline signing</strong> on the key holder's machine. Import only the public root files and keep the existing root names.</p>
        <div className="maintenance-form"><label>First existing root name<input id="deployment-rotation-root-a-name" value={s.rootA} disabled={!c.canTrust('prepare')} onChange={event => c.field('rootA', event.target.value)} /></label>
          {files('root-a', 'First replacement public root', 'prepare', '.pub')}
          <label>Second existing root name<input id="deployment-rotation-root-b-name" value={s.rootB} disabled={!c.canTrust('prepare')} onChange={event => c.field('rootB', event.target.value)} /></label>
          {files('root-b', 'Second replacement public root', 'prepare', '.pub')}</div>
        <p>The first root approves the preserved revocation list. Approve the online key with either replacement root.</p>
        {item?.requires_package_rebuild && <p className="muted">Replacing offline roots requires rebuilt device packages and re-onboarding. The worker verifies package preparation before completing maintenance.</p>}
      </div>
      <p className="worker-actions">{trustButton('prepare', 'Prepare replacement trust')}
        <button className="btn ghost" id="deployment-rotation-download" disabled={!c.available('deployment') || !c.ready('trust') || !(item?.csr || item?.certificate || item?.online_public_key)} onClick={() => c.downloadTrust()}>Download public approval files</button>
        {trustButton('cancel', 'Cancel replacement')}</p>
      <div id="deployment-rotation-approval" hidden={!item || !['awaiting-approval', 'approved'].includes(state) || s.family === 'peer-ca' || item.mode === 'self-signed'}>
        {files('certificate', 'Approved public certificate', 'approve', '.pub,.pem,.crt,.cer')}
        <div id="deployment-rotation-keylist-label" hidden={s.family !== 'instruction-roots'}>{files('keylist', 'Approved public revocation list', 'approve')}</div>
        <p className="worker-actions">{trustButton('approve', 'Validate public approval')}</p>
      </div>
      <p className="machine" id="deployment-rotation-fingerprint">{item?.fingerprint_sha256 ? 'Replacement SHA256: ' + item.fingerprint_sha256 : ''}</p>
      <div id="deployment-rotation-attestation" hidden={!attest}>
        <h4>Confirm each offline root's custody</h4>
        <p id="deployment-rotation-attested" role="status">Fresh signed custody evidence: {item?.attested_root_ids.join(', ') || 'none'}. Each root needs its own signed approval.</p>
        <label className="worker-field">Root to attest<select id="deployment-rotation-attestation-root" value={s.attestRoot} disabled={s.busy || !attest} onChange={event => c.field('attestRoot', event.target.value)}>{Object.keys(item?.roots || {}).map(root => <option key={root}>{root}</option>)}</select></label>
        <p className="worker-actions">{trustButton('attestation-request', 'Download root attestation request')}</p>
        {files('attestation-keylist', 'Approved public revocation list', 'attestation-apply')}
        <p className="worker-actions">{trustButton('attestation-apply', 'Validate root attestation')}</p>
      </div>
    </div>
    <p className="worker-actions"><button className="btn" id="deployment-rotation-apply" disabled={!c.canRotate()} onClick={() => c.rotate()}>Back up and rotate during downtime</button>
      <button className="btn ghost" id="deployment-rotation-refresh" disabled={s.busy || ['rotation', 'backups', 'trust'].some(key => s.loading[key])} onClick={() => c.review('deployment')}>Refresh maintenance evidence</button></p>
    {message('deployment', 'deployment-rotation-result')}
    <div className="table-scroll" tabIndex={0} role="region" aria-label="Deployment rotation history"><table className="tbl"><thead><tr>{['Family / operation', 'State', 'Evidence'].map(title => <th key={title} scope="col">{title}</th>)}</tr></thead><tbody id="deployment-rotation-jobs">
      {(worker?.jobs || []).slice().reverse().map(row => <tr key={row.id}><td>{familyLabels[row.family]}<br /><span className="machine">{row.id}</span></td><td>{row.state.replaceAll('-', ' ')}</td><td>{row.detail}{row.proof && <pre className="worker-proof">{JSON.stringify(row.proof, null, 2)}</pre>}
        {row.state === 'recovery-required' && <button className="btn ghost" disabled={!c.canRotate(row.id)} onClick={() => c.rotate(row.id)}>Recover approved operation</button>}</td></tr>)}</tbody></table></div>
  </div>;
  const maintenance = s.valid.maintenance ? s.maintenance : null, draft = s.schedule, editable = c.available('maintenance') && c.ready('maintenance');
  const actionNames = {reviewed: 'Acknowledge review', 'retire-management': 'Retire previous credential', 'reconcile-management': 'Check credential recovery', retry: 'Retry after custody review'};
  const scheduler = <div className="card" id="key-maintenance" data-worker-group="maintenance"><h3>Scheduled key maintenance</h3>
    <p>Choose a UTC window and an action for each key family. No schedules are enabled initially. Review reminders leave credentials unchanged; signer preparation still needs offline approval.</p>
    <p id="maintenance-worker" role="status">{s.loading.maintenance ? 'Checking scheduler…' : maintenance ? 'Scheduler: ' + maintenance.worker.replaceAll('-', ' ') + (maintenance.observed_at === null ? '.' : '. Last check ' + new Date(maintenance.observed_at * 1000).toISOString() + '.') : 'Scheduler status unavailable. Refresh before changing a schedule.'}</p>
    <p className="worker-actions"><button className="btn ghost" id="maintenance-refresh" disabled={s.busy || s.loading.maintenance} onClick={() => c.review('maintenance')}>Refresh maintenance</button></p>
    <div className="table-scroll" tabIndex={0} role="region" aria-label="Scheduled maintenance actions"><table className="tbl"><thead><tr>{['Key family', 'Scheduled action', 'Approval or verification'].map(title => <th key={title} scope="col">{title}</th>)}</tr></thead>
      <tbody id="maintenance-families">{(maintenance?.families || []).map(row => <tr key={row.id}><td>{row.label}</td><td>{{prepare: 'Prepare for approval', rotate: 'Rotate credential', review: 'Review reminder'}[row.action]}</td><td>{row.requirement}</td></tr>)}</tbody></table></div>
    <form id="maintenance-form" className="maintenance-form" onSubmit={event => {event.preventDefault(); c.schedule();}}>
      <label>Schedule<select id="maintenance-policy" disabled={!editable} value={draft.selected} onChange={event => c.chooseSchedule(event.target.value)}><option value="">New schedule</option>{(maintenance?.policies || []).map(row => <option key={row.id} value={row.id}>{row.family + ' / ' + row.target + (row.enabled ? ' — enabled' : ' — disabled')}</option>)}</select></label>
      <label>Key family<select id="maintenance-family" required disabled={!editable} value={draft.family} onChange={event => c.scheduleField('family', event.target.value)}>{(maintenance?.families || []).map(row => <option key={row.id} value={row.id}>{row.label}</option>)}</select></label>
      <label>Device ID<input id="maintenance-target" disabled={!editable || draft.family !== 'device-instruction'} required={draft.family === 'device-instruction'} value={draft.target} onChange={event => c.scheduleField('target', event.target.value)} placeholder="Enrolled device ID" /></label>
      <label>Next window starts (UTC)<input id="maintenance-next" type="datetime-local" step="1" required disabled={!editable} value={draft.next} onChange={event => c.scheduleField('next', event.target.value)} /></label>
      <label>Repeat every (days)<input id="maintenance-interval" type="number" min={draft.family === 'device-instruction' ? 8 : 1} max={draft.family === 'device-instruction' ? 21 : 365} required disabled={!editable} value={draft.interval} onChange={event => c.scheduleField('interval', event.target.value)} /></label>
      <label>Window length (minutes)<input id="maintenance-window" type="number" min="5" max="1440" required disabled={!editable} value={draft.window} onChange={event => c.scheduleField('window', event.target.value)} /></label>
      <label className="maintenance-enable"><input id="maintenance-enabled" type="checkbox" disabled={!editable} checked={draft.enabled} onChange={event => c.scheduleField('enabled', event.target.checked)} /> Enable schedule</label>
      <button className="btn" id="maintenance-save" type="submit" disabled={!c.canSchedule()}>Save schedule</button>
      <button className="btn ghost" id="maintenance-reload" type="button" disabled={!editable} onClick={() => c.chooseSchedule(draft.selected, true)}>Reload saved schedule</button>
    </form>
    {maintenance && s.draftRevision !== maintenance.revision && <p className="muted">Schedules changed while you were editing. Reload the saved schedule and review its UTC window before saving.</p>}
    <p className="muted">Missed windows are recorded, not replayed. Unfinished credential transitions pause further rotations. Device encryption keys require an 8–21 day interval and seven-day overlap.</p>
    <div className="table-scroll" tabIndex={0} role="region" aria-label="Key maintenance history"><table className="tbl"><thead><tr>{['Operation', 'Due (UTC)', 'State and evidence', 'Next action'].map(title => <th key={title} scope="col">{title}</th>)}</tr></thead><tbody id="maintenance-jobs">
      {(maintenance?.jobs || []).slice().reverse().map(row => {const action = maintenanceAction(row); return <tr key={row.id}><td>{row.family + ' / ' + row.target}<br /><span className="machine">{row.id}</span></td><td>{new Date(row.due_at * 1000).toISOString()}</td><td>{row.state.replaceAll('-', ' ') + ': ' + row.detail}</td><td>{action ? <button className="btn ghost" disabled={!c.canSchedule(action, row.id)} onClick={() => c.schedule(action, row.id)}>{actionNames[action]}</button>
        : row.state === 'approval-required' ? <a href="#signer-rotation" onClick={event => {event.preventDefault(); c.services.openSigner();}}>Complete signer approval above</a> : null}</td></tr>;})}
      {maintenance && !maintenance.jobs.length && <tr><td colSpan={4}>No maintenance operations yet.</td></tr>}</tbody></table></div>
    {message('maintenance', 'maintenance-result')}
  </div>;
  const backup = s.valid.backups ? s.backups : null, recovery = c.recoveryRestore();
  const backupButton = (action, name, label) => <button className={'btn' + (action === 'restore' ? '' : ' ghost')} id={'backup-' + name} disabled={!c.canBackup(action, action === 'recover-restore' ? recovery?.id : null)} onClick={() => c.backup(action, action === 'recover-restore' ? recovery?.id : null)}>{label}</button>;
  const backups = <div data-worker-group="backups"><div className="card"><h3>Deployment backups</h3>
    <p id="backup-worker-note" className="muted">{s.loading.backups ? 'Checking the deployment worker…' : backup ? topologyLabels[backup.target] + '. ' + backup.note : 'Backup status unavailable. Refresh after the Console returns or use the host recovery window.'}</p>
    <p>Capture includes deployment data, imported images, device packages, deployment files and container images. The service identity has a separate encrypted recovery set.</p>
    {blockers.length > 0 && <p className="muted">A worker operation is running or requires recovery. Check backup and rotation history before starting another operation.</p>}
    {s.unknown.deployment && <p>Review the uncertain operation in <a href="#settings/certificates">Certificates &amp; keys</a> before starting backup or restore.</p>}
    <p className="worker-actions"><button className="btn" id="backup-create" disabled={!c.canBackup('backup')} onClick={() => c.backup('backup')}>Back up now</button>
      <button className="btn ghost" id="backup-refresh" disabled={s.busy || s.loading.backups || s.loading.rotation} onClick={() => c.review('backups')}>Refresh backup history</button></p>
    {message('backups', 'backup-operation-result')}
    <div className="table-scroll" tabIndex={0} role="region" aria-label="Backup history"><table className="tbl"><thead><tr>{['Started', 'Operation', 'Backup set', 'Result'].map(title => <th key={title} scope="col">{title}</th>)}</tr></thead><tbody id="backup-job-rows">
      {(backup?.jobs || []).slice().reverse().map(row => <tr key={row.id}><td>{c.services.formatDate(row.started_at)}</td><td><span>{row.action}</span><br /><span className="machine">{row.id}</span></td><td className="machine">{row.backup_id}</td><td>{row.state.replaceAll('-', ' ')}<br /><small>{row.detail}</small>
        {row.action === 'restore' && row.state === 'recovery-required' && <p><button className="btn ghost" disabled={!c.canBackup('recover-restore', row.id)} onClick={() => c.backup('recover-restore', row.id)}>Resume this interrupted restore</button></p>}</td></tr>)}</tbody></table></div>
  </div><div className="card"><h3>Restore deployment</h3>
    <p>Verify decrypts and checks both sets. Isolated extraction writes to a new protected host directory. It does not start IRIS or contact devices.</p>
    <label className="worker-field">Captured backup<select id="backup-selected" disabled={s.busy || !c.ready('backups')} value={s.backupSelected} onChange={event => c.field('backupSelected', event.target.value)}><option value="">Choose a backup</option>{(backup?.jobs || []).filter(row => row.action === 'backup' && row.state === 'captured').map(row => <option key={row.id} value={row.backup_id}>{c.services.formatDate(row.started_at) + ' · ' + row.backup_id}</option>)}</select></label>
    <p className="worker-actions">{backupButton('verify', 'verify', 'Verify backup')}{backupButton('extract', 'extract', 'Extract for isolated recovery')}{backupButton('restore', 'restore', 'Restore selected backup')}{backupButton('recover-restore', 'recover', 'Resume interrupted restore')}</p>
    <p className="muted">Restore stops this deployment, verifies the backup against current security authority, replaces saved content and checks restarted services. Changed credentials or missing instruction history prevent cutover. Use the host recovery window if the Console is offline.</p>
  </div></div>;
  return <div onFocusCapture={event => {focus.current = {node: event.target, group: event.target.closest('[data-worker-group]')?.dataset.workerGroup};}}>{createPortal(deployment, roots.deployment)}{createPortal(scheduler, roots.maintenance)}{createPortal(backups, roots.backups)}</div>;
}
export function mountWorkerLifecycle() {
  const c = new WorkerLifecycleController(); window.irisWorkerLifecycle = c;
  const root = document.getElementById('iris-worker-lifecycle-root'), roots = {deployment: document.getElementById('iris-worker-deployment'), maintenance: document.getElementById('iris-worker-maintenance'), backups: document.getElementById('iris-worker-backups')};
  if (!root || Object.values(roots).some(node => !node)) throw Error('Worker lifecycle mount points missing');
  createRoot(root).render(<WorkerLifecycle controller={c} roots={roots} />);
}
