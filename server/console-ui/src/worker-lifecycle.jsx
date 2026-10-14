// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {createPortal} from 'react-dom';
import {WorkerLifecycleController} from './worker-lifecycle-controller.mjs';
import {familyLabels, topologyLabels, activeJobs} from './worker-lifecycle-model.mjs';
import {trustFamilies} from './deployment-trust-model.mjs';
import {maintenanceAction, activeMaintenance} from './key-maintenance-model.mjs';
import {deploymentGuidance, trustState} from './certificate-guidance.mjs';
import {upgradeArchivePhases} from './backup-retention-model.mjs';

function WorkerLifecycle({controller: c, roots}) {
  const s = useSyncExternalStore(c.subscribe, c.snapshot), focus = useRef(null), outcomes = useRef({});
  useLayoutEffect(() => {
    const {node, group} = focus.current || {};
    if (!c.visible() || !node) return;
    if ((!node.isConnected || node.disabled) && (document.activeElement === document.body || document.activeElement === node)) outcomes.current[group]?.focus();
  }, [s, c]);
  const message = (group, id) => <p id={id} role="status" aria-live="polite" tabIndex={-1} ref={node => {outcomes.current[group] = node;}}>{s.messages[group]?.text || ''}</p>;
  const disclosureStatus = group => {
    if (s.unknown[group]) return 'Outcome unknown: open, refresh and review before continuing';
    if (group === 'deployment' && s.unknown.backups) return 'Backup outcome unknown: review Backup & restore before maintenance';
    if (group === 'deployment' && s.backups?.retention?.busy) return 'Maintenance is unfinished: open to review the operation history';
    const jobs = group === 'deployment' ? c.ready('rotation', 'backups') ? activeJobs(s) : []
      : s.valid.maintenance ? s.maintenance.jobs.filter(row => activeMaintenance.includes(row.state)) : [];
    if (jobs.some(row => ['recovery-required', 'intervention-required'].includes(row.state))) return 'Operation needs recovery or intervention: open to review';
    if (s.busy && s.messages[group]) return 'Request in progress: open to follow its outcome';
    if (jobs.length) return 'An operation is running or awaiting follow-up: open to review';
    if (s.messages[group]?.kind === 'error') return 'Action needs review: open the latest result';
    if (group === 'deployment' && s.valid.trust && s.trust.items.some(row => ['awaiting-approval', 'approved', 'committing'].includes(row.state))) return 'Replacement in progress: open to review approval or recovery';
    if (s.messages[group]?.text) return 'Latest operation result available: open to review';
    if (group === 'deployment' ? !c.ready('rotation', 'trust') : !s.valid.maintenance) return 'Status unavailable: open and refresh before making changes';
    return group === 'deployment' ? 'Planned downtime; some changes require removing and onboarding devices again' : 'Optional schedules and operation history';
  };
  const files = (name, title, action, accept) => <label className="worker-field">{title}<input key={s.fileEpoch + ':' + name} id={'deployment-rotation-' + name} type="file" accept={accept} disabled={!c.canTrust(action)} onChange={event => c.file(name, event.target.files[0])} /></label>;
  const item = s.valid.trust ? c.item() : null, trust = trustFamilies.includes(s.family), state = item?.state || 'unavailable', worker = s.valid.rotation ? s.rotation : null;
  const attest = item?.family === 'instruction-roots' && ['idle', 'published', 'cancelled'].includes(state) && Object.keys(item.roots).length === 2;
  const blockers = c.ready('rotation', 'backups') ? activeJobs(s) : [];
  const trustButton = (action, label) => <button className={'btn' + (action === 'cancel' ? ' ghost' : '')} id={'deployment-rotation-' + action} disabled={!c.canTrust(action)} onClick={() => c.performTrust(action)}>{label}</button>;
  const deployment = <div className="card" id="deployment-rotation-workflow" data-worker-group="deployment">
    <h3>Deployment keys</h3>
    <p>Use the installer's maintenance worker to replace deployment credentials. It stops services and verifies a recoverable backup before changing keys. Keep a host session available during downtime.</p>
    <label className="worker-field">What needs replacing?<select id="deployment-rotation-family" value={s.family} disabled={s.busy} onChange={event => c.field('family', event.target.value)}>{Object.entries(familyLabels).filter(([family]) => family !== 'age-recovery').map(([family, label]) => <option value={family} key={family}>{label}</option>)}</select></label>
    <p id="deployment-rotation-purpose"><strong>{deploymentGuidance[s.family]?.[0]}.</strong> {deploymentGuidance[s.family]?.[1]}</p>
    <p id="deployment-rotation-worker" role="status">{s.loading.rotation ? 'Checking deployment maintenance…' : worker ? 'Deployment: ' + topologyLabels[worker.target] + '. ' + worker.note : 'Worker state unavailable. Refresh before starting maintenance.'}</p>
    {trust && <p id="deployment-rotation-state" role="status">{trustState(state)}.</p>}
    {blockers.length > 0 && <p className="muted">A worker operation is running or requires recovery. Review its history before starting another operation.</p>}
    {s.unknown.backups && <p>Review the uncertain operation in <a href="#settings/backups">Backup &amp; restore</a> before starting maintenance.</p>}
    {s.backups?.retention?.operation && s.backups.retention.operation.state !== 'completed' && <p>Backup cleanup is unfinished. Open <a href="#settings/backups">Backup &amp; restore</a> to check its result before starting maintenance.</p>}
    {s.backups?.retention && !c.backupSpace() && <p>Backup storage is full. Review saved backups in <a href="#settings/backups">Backup &amp; restore</a> before starting another rotation.</p>}
    {s.backups?.retention && !c.historySpace() && <p>Recent maintenance history is full. Clear finished history in <a href="#settings/backups">Backup &amp; restore</a> before starting another operation.</p>}
    <div id="deployment-rotation-trust" hidden={!trust}>
      <p><a href="#devices">Open devices to remove IRIS deployments</a>. A missing or abandoned device is not proof of removal.</p>
      {item?.request_id && <p className="machine">Request: {item.request_id}{item.names.length > 0 && <><br />Requested names: {item.names.join(', ')}</>}</p>}
      {s.valid.trust && <p>{s.trust.drain.ready ? 'Recorded deployments are removed; the worker will check again after stopping writers.' : 'Removal required: ' + s.trust.drain.blocked_device_ids.join(', ') + '.'}</p>}
      <div id="deployment-rotation-tls" className="maintenance-form" hidden={s.family !== 'device-tls'}>
        <label>Exact device-facing DNS names or IP addresses, comma-separated<input id="deployment-rotation-names" value={s.names} disabled={!c.canTrust('prepare')} onChange={event => c.field('names', event.target.value)} placeholder="iris.example.com, 192.0.2.10" /></label>
        <label>Approval method<select id="deployment-rotation-mode" value={s.mode} disabled={!c.canTrust('prepare')} onChange={event => c.field('mode', event.target.value)}><option value="ca">Request approval from my CA</option><option value="self-signed">Create a self-signed certificate (90 days)</option></select></label>
      </div>
      <div id="deployment-rotation-roots" hidden={s.family !== 'instruction-roots'}>
        <p>Each root signing key holder creates a replacement with <code>iris-key-setup</code> wherever they keep that private key. Import only public root files and keep the existing root names.</p>
        <div className="maintenance-form"><label>First existing root name<input id="deployment-rotation-root-a-name" value={s.rootA} disabled={!c.canTrust('prepare')} onChange={event => c.field('rootA', event.target.value)} /></label>
          {files('root-a', 'First replacement public root', 'prepare', '.pub')}
          <label>Second existing root name<input id="deployment-rotation-root-b-name" value={s.rootB} disabled={!c.canTrust('prepare')} onChange={event => c.field('rootB', event.target.value)} /></label>
          {files('root-b', 'Second replacement public root', 'prepare', '.pub')}</div>
        <p>The first root approves the preserved revocation list. Approve the online key with either replacement root.</p>
        {item?.requires_package_rebuild && <p className="muted">Replacing signing roots requires rebuilt device packages and re-onboarding. The worker verifies package preparation before completing maintenance.</p>}
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
        <h4>Confirm root key access</h4>
        <p>Ask each holder to sign a public request with their root key. This confirms recent access to that key without replacing it or stopping services.</p>
        <p id="deployment-rotation-attested" role="status">Recent signed confirmations: {item?.attested_root_ids.join(', ') || 'none'}. Each root needs its own approval, renewed before 180 days.</p>
        <label className="worker-field">Root key to confirm<select id="deployment-rotation-attestation-root" value={s.attestRoot} disabled={s.busy || !attest} onChange={event => c.field('attestRoot', event.target.value)}>{Object.keys(item?.roots || {}).map(root => <option key={root}>{root}</option>)}</select></label>
        <p className="worker-actions">{trustButton('attestation-request', 'Download root confirmation request')}</p>
        {files('attestation-keylist', 'Approved public revocation list', 'attestation-apply')}
        <p className="worker-actions">{trustButton('attestation-apply', 'Validate root confirmation')}</p>
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
  const actionNames = {reviewed: 'Acknowledge review', 'retire-management': 'Retire previous credential', 'reconcile-management': 'Check credential recovery', retry: 'Retry after key review'};
  const scheduler = <div className="card" id="key-maintenance" data-worker-group="maintenance"><h3>Scheduled key maintenance</h3>
    <p>Choose a UTC window for each credential. All schedules start disabled. Some actions prepare or replace keys; others only remind you to review them. Signing-key replacement still needs a root key holder's approval.</p>
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
  const backup = s.valid.backups ? s.backups : null, recovery = c.recoveryRestore(), retention = backup?.retention;
  const backupButton = (action, name, label) => <button className={'btn' + (action === 'restore' ? '' : ' ghost')} id={'backup-' + name} disabled={!c.canBackup(action, action === 'recover-restore' ? recovery?.id : null)} onClick={() => c.backup(action, action === 'recover-restore' ? recovery?.id : null)}>{label}</button>;
  const backups = <div data-worker-group="backups"><div className="card"><h3>Deployment backups</h3>
    <p id="backup-worker-note" className="muted">{s.loading.backups ? 'Checking the deployment worker…' : backup ? topologyLabels[backup.target] + '. ' + backup.note : 'Backup status unavailable. Refresh after the Console returns or use the host recovery window.'}</p>
    <p>Capture includes deployment data, imported images, device packages, deployment files and container images. The service identity has a separate encrypted recovery set.</p>
    {blockers.length > 0 && <p className="muted">A worker operation is running or requires recovery. Check backup and rotation history before starting another operation.</p>}
    {s.unknown.deployment && <p>Review the uncertain operation in <a href="#settings/certificates">Certificates &amp; keys</a> before starting backup or restore.</p>}
    <p className="worker-actions"><button className="btn" id="backup-create" disabled={!c.canBackup('backup')} onClick={() => c.backup('backup')}>Back up now</button>
      <button className="btn ghost" id="backup-refresh" disabled={s.busy || s.loading.backups || s.loading.rotation} onClick={() => c.review('backups')}>Refresh backup history</button></p>
    {message('backups', 'backup-operation-result')}
    {s.retentionUncertain && <p className="machine" id="backup-cleanup-request">Cleanup request: {s.retentionAttempt?.request_id}</p>}
    <div className="table-scroll" tabIndex={0} role="region" aria-label="Backup history"><table className="tbl"><thead><tr>{['Started', 'Operation', 'Backup set', 'Result'].map(title => <th key={title} scope="col">{title}</th>)}</tr></thead><tbody id="backup-job-rows">
      {(backup?.jobs || []).slice().reverse().map(row => <tr key={row.id}><td>{c.services.formatDate(row.started_at)}</td><td><span>{row.action}</span><br /><span className="machine">{row.id}</span></td><td className="machine">{row.backup_id}</td><td>{row.state.replaceAll('-', ' ')}<br /><small>{row.detail}</small>
        {row.action === 'restore' && row.state === 'recovery-required' && <p><button className="btn ghost" disabled={!c.canBackup('recover-restore', row.id)} onClick={() => c.backup('recover-restore', row.id)}>Resume this interrupted restore</button></p>}
        {backup.can_recover_backup && row.action === 'backup' && row.state === 'recovery-required' && <p><button className="btn ghost" disabled={!c.canBackup('recover-backup', row.id)} onClick={() => c.backup('recover-backup', row.id)}>Recover services after this backup</button></p>}</td></tr>)}</tbody></table></div>
    {retention && <div id="backup-history-retention"><h4>Finished history</h4>
      <p id="backup-history-capacity">{retention.capacity.history_used} of {retention.capacity.history_limit} recent maintenance records. Clear finished backup and rotation history to make room. Saved backups and recovery records stay.</p>
      <p className="worker-actions"><button className="btn ghost" id="backup-history-clear" disabled={!c.canRetire('retire-history')} onClick={() => c.retire('retire-history')}>Clear finished history</button></p>
      <p className="muted">Up to 25 records at a time. Records needed for recovery stay in place.</p>
    </div>}
  </div><div className="card"><h3>Restore deployment</h3>
    <p>Verify decrypts and checks both sets. Isolated extraction writes to a new protected host directory. It does not start IRIS or contact devices.</p>
    <label className="worker-field">Captured backup<select id="backup-selected" disabled={s.busy || !c.ready('backups')} value={s.backupSelected} onChange={event => c.field('backupSelected', event.target.value)}><option value="">Choose a backup</option>{(backup?.jobs || []).filter(row => row.action === 'backup' && row.state === 'captured').map(row => <option key={row.id} value={row.backup_id}>{c.services.formatDate(row.started_at) + ' · ' + row.backup_id}</option>)}</select></label>
    <p className="worker-actions">{backupButton('verify', 'verify', 'Verify backup')}{backupButton('extract', 'extract', 'Extract for isolated recovery')}{backupButton('restore', 'restore', 'Restore selected backup')}{backupButton('recover-restore', 'recover', 'Resume interrupted restore')}</p>
    <p className="muted">Restore stops this deployment, verifies the backup against current security authority, replaces saved content and checks restarted services. Changed credentials or missing instruction history prevent cutover. Use the host recovery window if the Console is offline.</p>
    {retention && <div id="backup-archive-retention"><h4>Saved backups</h4>
      <p id="backup-storage-capacity">{retention.capacity.backup_used} of {retention.capacity.backup_limit} backups saved on this host. Deleting a backup removes its deployment and recovery archives.</p>
      {retention.protected_upgrade_backups?.length > 0 && <details id="backup-upgrade-archives">
        <summary>{retention.capacity.protected_upgrade_used} protected upgrade {retention.capacity.protected_upgrade_used === 1 ? 'backup' : 'backups'}</summary>
        <p>These archives also use host storage. They stay with their upgrade recovery records and cannot be deleted here.</p>
        <ul>{retention.protected_upgrade_backups.map(row => <li key={row.operation_id + ':' + row.attempt}>
          <span className="machine">{row.operation_id}</span> · Attempt {row.attempt} · {upgradeArchivePhases[row.phase]}<br />
          {row.deployment_archive && row.recovery_archive ? 'Deployment and identity recovery archives present.'
            : row.deployment_archive ? 'Deployment archive present; identity recovery archive absent.'
              : 'Identity recovery archive present; deployment archive absent.'}
        </li>)}</ul>
      </details>}
      <label className="worker-field">Saved backup to delete<select id="backup-delete-selected" disabled={s.busy || !c.ready('backups')} value={s.backupDeleteSelected} onChange={event => c.field('backupDeleteSelected', event.target.value)}><option value="">Choose a saved backup</option>{retention.backups.map(row => <option key={row.backup_id} value={row.backup_id}>{(row.created_at === null ? 'Date unavailable' : c.services.formatDate(row.created_at)) + ' · ' + row.backup_id}</option>)}</select></label>
      <p className="worker-actions"><button className="btn danger" id="backup-delete" disabled={!c.canRetire('delete-backup')} onClick={() => c.retire('delete-backup')}>Delete selected backup</button></p>
      {s.backupDeleteSelected && retention.backups.find(row => row.backup_id === s.backupDeleteSelected && !row.delete_allowed)?.delete_reason && <p id="backup-delete-reason" className="muted">{retention.backups.find(row => row.backup_id === s.backupDeleteSelected).delete_reason}</p>}
      {retention.busy && <p id="backup-cleanup-status" role="status">Maintenance is unfinished. Refresh history to check its result before starting another operation.</p>}
      {retention.operation?.state === 'recovery-required' && <div id="backup-delete-recovery"><p>Deletion of backup <span className="machine">{retention.operation.backup_id}</span> was interrupted. Resume this exact deletion after resolving the host error.</p>
        <p className="worker-actions"><button className="btn danger" id="backup-delete-resume" disabled={!c.canRetire('resume-delete')} onClick={() => c.retire('resume-delete')}>Resume backup deletion</button></p></div>}
    </div>}
  </div></div>;
  return <div onFocusCapture={event => {focus.current = {node: event.target, group: event.target.closest('[data-worker-group]')?.dataset.workerGroup};}}>{createPortal(deployment, roots.deployment)}{createPortal(scheduler, roots.maintenance)}{createPortal(backups, roots.backups)}{createPortal(disclosureStatus('deployment'), roots.deploymentSummary)}{createPortal(disclosureStatus('maintenance'), roots.maintenanceSummary)}</div>;
}
export function mountWorkerLifecycle() {
  const c = new WorkerLifecycleController(); window.irisWorkerLifecycle = c;
  const root = document.getElementById('iris-worker-lifecycle-root'), roots = {deployment: document.getElementById('iris-worker-deployment'), maintenance: document.getElementById('iris-worker-maintenance'), backups: document.getElementById('iris-worker-backups'), deploymentSummary: document.getElementById('deployment-key-summary'), maintenanceSummary: document.getElementById('scheduled-key-summary')};
  if (!root || Object.values(roots).some(node => !node)) throw Error('Worker lifecycle mount points missing');
  createRoot(root).render(<WorkerLifecycle controller={c} roots={roots} />);
}
