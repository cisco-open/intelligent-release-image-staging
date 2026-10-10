// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {requestId, publicCertificate} from './certificates-model.mjs';
import {normalizeNames, publicPem} from './security-lifecycle-model.mjs';
import {urls, workerStatus, activeJobs, acceptedJob, matchingJob, workerBody, workerRefusalHint, familyLabels} from './worker-lifecycle-model.mjs';
import {trustFamilies, trustStatus, trustAllows, checkedTrust, rootId, rootsPublic, signedKeylist} from './deployment-trust-model.mjs';
import {maintenanceStatus, maintenanceAction, checkedMaintenance, scheduleDraft, schedulePayload, equalPolicy} from './key-maintenance-model.mjs';
import {matchingRetention, retentionOperation} from './backup-retention-model.mjs';

export class WorkerLifecycleController {
  constructor() {
    this.state = {rotation: null, trust: null, maintenance: null, backups: null, valid: {}, loading: {}, unknown: {}, messages: {}, busy: false,
      family: 'management-tls', names: '', mode: 'ca', rootA: 'root-a', rootB: 'root-b', attestRoot: '', attestation: null,
      files: {}, fileEpoch: 0, schedule: scheduleDraft(null, Date.now()), draftDirty: false, draftRevision: null, backupSelected: '', backupDeleteSelected: '', retentionAttempt: null, retentionUncertain: false};
    this.listeners = new Set(); this.generations = {}; this.readers = {}; this.pending = {}; this.context = 0; this.pane = null;
  }
  snapshot = () => this.state;
  subscribe = listener => {this.listeners.add(listener); return () => this.listeners.delete(listener);};
  update(patch) {this.state = {...this.state, ...patch}; this.listeners.forEach(listener => listener());}
  connect(services) {this.services = services;}
  visible() {return !!this.pane && this.services?.visible(this.pane) === true;}
  say(group, text, kind = 'error', source = 'action') {this.update({messages: {...this.state.messages, [group]: {text, kind, source}}});}
  cancelReads() {for (const key of Object.keys(urls)) {this.generations[key] = (this.generations[key] || 0) + 1; this.readers[key]?.abort();} this.readers = {}; this.update({loading: {}});}
  clearFiles() {this.update({files: {}, fileEpoch: this.state.fileEpoch + 1});}
  hide() {this.context++; this.cancelReads(); this.clearFiles(); this.update({valid: {}});}
  select(pane) {
    const next = ['certificates', 'backups'].includes(pane) ? pane : null;
    if (next !== this.pane) {this.hide(); this.pane = next;}
    if (this.visible()) return this.refreshAll();
  }
  group(key) {return ['rotation', 'trust'].includes(key) ? 'deployment' : key;}
  available(group) {return this.visible() && !this.state.busy && !this.state.unknown[group];}
  ready(...keys) {return keys.every(key => this.state.valid[key] && !this.state.loading[key]);}
  item() {return this.state.trust?.items.find(row => row.family === this.state.family);}
  workerReady() {return this.ready('rotation', 'backups') && !this.state.unknown.deployment && !this.state.unknown.backups;}
  workerIdle(except = null) {return this.workerReady() && !this.state.backups?.retention?.busy && !activeJobs(this.state).some(row => row.id !== except);}
  backupSpace() {const capacity = this.state.backups?.retention?.capacity; return !capacity || capacity.backup_used < capacity.backup_limit;}
  historySpace() {const capacity = this.state.backups?.retention?.capacity; return !capacity || capacity.history_used < capacity.history_limit;}
  retirableJobs() {return this.state.backups?.retention?.jobs.filter(row => row.retire_allowed).slice(0, 25) || [];}
  canRetire(action) {
    const retention = this.state.backups?.retention;
    if (this.pane !== 'backups' || !this.available('backups') || !this.workerReady() || !this.state.backups.available || !retention) return false;
    if (action === 'resume-delete') return !activeJobs(this.state).length && retention.operation?.action === 'delete-backup' && retention.operation.state === 'recovery-required';
    if (!this.workerIdle()) return false;
    if (action === 'retire-history') return this.retirableJobs().length > 0;
    return action === 'delete-backup' && retention.backups.some(row => row.backup_id === this.state.backupDeleteSelected && row.delete_allowed);
  }
  canTrust(action) {
    if (this.pane !== 'certificates' || !this.available('deployment') || !this.ready('trust') || !this.workerIdle() || !trustAllows(this.item(), action)) return false;
    if (action === 'attestation-apply') return this.item().attestation_root_id === this.state.attestRoot && requestId(this.item().attestation_request_id);
    return true;
  }
  canRotate(recovery = null) {
    if (this.pane !== 'certificates' || !this.available('deployment') || !this.state.rotation?.can_rotate || !this.workerReady()) return false;
    if (recovery) {const row = this.state.rotation.jobs.find(row => row.id === recovery);
      return !!row && row.state === 'recovery-required' && this.state.rotation.families.includes(row.family) && this.workerIdle(row.id);}
    const item = this.item();
    return this.workerIdle() && this.backupSpace() && this.historySpace() && this.state.rotation.families.includes(this.state.family) &&
      (!trustFamilies.includes(this.state.family) || this.ready('trust') && item?.state === 'approved' && this.state.trust.drain.ready);
  }
  canBackup(action, recovery = null) {
    if (this.pane !== 'backups' || !this.available('backups') || !this.state.backups?.available || !this.workerReady()) return false;
    if (action === 'recover-restore') {
      const row = this.state.backups.jobs.find(row => row.id === recovery);
      return this.state.backups.can_restore && row?.action === 'restore' && row.state === 'recovery-required' && this.workerIdle(row.id);
    }
    if (!['backup', 'verify', 'extract', 'restore'].includes(action) || !this.workerIdle() || !this.historySpace()) return false;
    if (action === 'backup') return this.backupSpace();
    return this.state.backups['can_' + action] && this.state.backups.jobs.some(row => row.backup_id === this.state.backupSelected && row.action === 'backup' && row.state === 'captured');
  }
  recoveryRestore() {
    const rows = this.state.backups?.jobs.filter(row => row.action === 'restore' && row.state === 'recovery-required') || [];
    return rows.length === 1 ? rows[0] : null;
  }
  canSchedule(action = 'save-policy', id = null) {
    if (this.pane !== 'certificates' || !this.available('maintenance') || !this.ready('maintenance')) return false;
    return action === 'save-policy' ? this.state.draftRevision === this.state.maintenance.revision
      : maintenanceAction(this.state.maintenance.jobs.find(row => row.id === id)) === action;
  }
  field(key, value) {
    if (!this.visible() || this.state.busy) return;
    if (key === 'family') {
      if (!Object.hasOwn(familyLabels, value) || value === 'age-recovery' || value === this.state.family) return;
      this.clearFiles(); this.update({family: value, attestRoot: ''}); this.pickAttestRoot(); return;
    }
    if (['backupSelected', 'backupDeleteSelected'].includes(key)) {if (this.ready('backups')) this.update({[key]: value}); return;}
    if (key === 'attestRoot') {if (!Object.hasOwn(this.item()?.roots || {}, value)) return; this.clearFiles(); this.update({attestRoot: value}); return;}
    if (!['names', 'mode', 'rootA', 'rootB'].includes(key) || !this.canTrust('prepare') || key === 'mode' && !['ca', 'self-signed'].includes(value)) return;
    this.update({[key]: value});
  }
  pickAttestRoot() {
    const item = this.item(); if (item?.family !== 'instruction-roots') return;
    if (!Object.hasOwn(item.roots, this.state.attestRoot)) this.update({attestRoot: item.attestation_root_id || Object.keys(item.roots)[0] || ''});
  }
  file(key, file) {
    const action = ['root-a', 'root-b'].includes(key) ? 'prepare' : key === 'attestation-keylist' ? 'attestation-apply' : 'approve';
    if (['root-a', 'root-b', 'certificate', 'keylist', 'attestation-keylist'].includes(key) && this.canTrust(action)) this.update({files: {...this.state.files, [key]: file}});
  }
  scheduleField(key, value) {
    if (!this.available('maintenance') || !this.ready('maintenance') || !['family', 'target', 'next', 'interval', 'window', 'enabled'].includes(key)) return;
    this.update({schedule: {...this.state.schedule, [key]: value}, draftDirty: true});
  }
  chooseSchedule(id, reload = false) {
    if (!this.available('maintenance') || !this.ready('maintenance')) return;
    const policy = this.state.maintenance.policies.find(row => row.id === id);
    if (id && !policy) return;
    if (this.state.draftDirty && !this.services.confirm('Discard the unsaved schedule and load the saved values?')) return;
    this.update({schedule: scheduleDraft(policy, this.services.now()), draftDirty: false, draftRevision: this.state.maintenance.revision});
    delete this.pending.schedule;
    if (reload) this.say('maintenance', 'Saved values loaded. Review the UTC window before saving.', 'info');
  }
  async refresh(key) {
    if (!urls[key] || !this.visible() || this.state.busy) return false;
    const generation = (this.generations[key] || 0) + 1, context = this.context;
    this.generations[key] = generation; this.readers[key]?.abort(); const reader = new AbortController(); this.readers[key] = reader;
    this.update({loading: {...this.state.loading, [key]: true}, valid: {...this.state.valid, [key]: false}});
    try {
      const address = urls[key] + (key === 'backups' && this.state.retentionAttempt ? '?retention_request_id=' + encodeURIComponent(this.state.retentionAttempt.request_id) : '');
      const response = await this.services.fetch(address, {signal: reader.signal}), data = await response.json();
      if (generation !== this.generations[key] || context !== this.context || !this.visible()) return false;
      const state = key === 'trust' ? trustStatus(data) : key === 'maintenance' ? maintenanceStatus(data) : workerStatus(data, key);
      if (response.status !== 200 || !state) throw Error();
      const patch = {[key]: state, valid: {...this.state.valid, [key]: true}}, group = this.group(key);
      if (this.state.messages[group]?.source === 'read') patch.messages = {...this.state.messages, [group]: null};
      if (key === 'maintenance' && !this.state.draftDirty) {
        patch.schedule = scheduleDraft(state.policies.find(row => row.id === this.state.schedule.selected), this.services.now()); patch.draftRevision = state.revision;
      }
      if (key === 'trust') {
        const old = this.item(), next = state.items.find(row => row.family === this.state.family);
        if (old?.request_id !== next?.request_id || old?.attestation_request_id !== next?.attestation_request_id) this.clearFiles();
      }
      this.update(patch); if (key === 'trust') this.pickAttestRoot(); return true;
    } catch {
      if (generation === this.generations[key] && context === this.context && this.visible()) {
        this.update({[key]: null, valid: {...this.state.valid, [key]: false}});
        const group = this.group(key); if (!this.state.messages[group] || this.state.messages[group].source === 'read') this.say(group, 'Current evidence unavailable. Refresh before continuing.', 'error', 'read');
      }
      return false;
    } finally {if (generation === this.generations[key]) this.update({loading: {...this.state.loading, [key]: false}});}
  }
  refreshAll() {return Promise.all((this.pane === 'certificates' ? ['rotation', 'backups', 'trust', 'maintenance'] : ['rotation', 'backups']).map(key => this.refresh(key)));}
  async review(group) {
    if (!this.visible() || this.state.busy) return;
    const context = this.context, family = this.state.family;
    const keys = group === 'deployment' ? ['rotation', 'backups', 'trust'] : group === 'backups' ? ['rotation', 'backups'] : ['maintenance'];
    const reads = keys.map(key => this.refresh(key)), generations = keys.map(key => this.generations[key]);
    const results = await Promise.all(reads);
    if (!results.every(Boolean) || keys.some((key, index) => this.generations[key] !== generations[index]) || context !== this.context || !this.visible() || group === 'deployment' && family !== this.state.family || !this.ready(...keys)) return;
    if (group === 'backups' && this.state.retentionUncertain &&
        !matchingRetention(this.state.backups?.retention?.operation, this.state.retentionAttempt)) {
      this.say('backups', 'The worker has not confirmed this exact cleanup request. Keep its request ID and review it on the installer host before continuing.');
      return;
    }
    this.update({unknown: {...this.state.unknown, [group]: false}, ...(group === 'backups' ? {retentionUncertain: false, retentionAttempt: null} : {})});
    if (group === 'deployment') this.clearFiles();
    for (const [key, pending] of Object.entries(this.pending)) {
      if (pending.group !== group) continue;
      const current = pending.payload;
      if (current?.policy && equalPolicy(current.policy, this.state.maintenance?.policies.find(row => row.id === current.policy.id))) {
        this.update({schedule: scheduleDraft(current.policy, this.services.now()), draftDirty: false, draftRevision: this.state.maintenance.revision});
        delete this.pending[key];
      } else if (current && [...(this.state.rotation?.jobs || []), ...(this.state.backups?.jobs || [])].some(row => matchingJob(row, current)) ||
          pending.kind === 'trust' && this.state.trust?.items.some(row => row.family === pending.family && row.request_id === pending.id)) delete this.pending[key];
    }
    this.say(group, 'Current evidence loaded. Review the request, operation and state before continuing.', 'info');
  }
  pendingId(key, parameters, group, kind, family = null) {
    if (!this.pending[key] || this.pending[key].parameters !== parameters) this.pending[key] = {id: this.services.uuid(), parameters, group, kind, family};
    return this.pending[key].id;
  }
  async publicFile(key, limit, transform, context) {
    const file = this.state.files[key];
    if (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > limit) throw Error('Choose the required bounded public approval file.');
    const text = await file.text();
    if (context !== this.context || !this.visible()) throw Error('The approval was not submitted because you left this page.');
    if (typeof text !== 'string' || /PRIVATE KEY|AGE-SECRET-KEY/i.test(text)) throw Error('Upload public approvals only. Keep private keys with their holder.');
    return transform(text);
  }
  downloadTrust() {
    if (!this.available('deployment') || !this.ready('trust')) return;
    const item = this.item(); if (!item) return;
    try {
      for (const [key, name] of [['csr', 'iris-device.csr'], ['certificate', 'iris-approved-certificate.pem'], ['online_public_key', 'online.pub'], ['keylist_payload', 'keylist-payload.json']]) if (item[key]) this.services.download(name, item[key]);
      this.say('deployment', 'Public files downloaded. Keep their request ID with the approval.', 'info');
    } catch {this.say('deployment', 'Public download unavailable. Retry the download before requesting approval.');}
  }
  async performTrust(action) {
    if (!this.canTrust(action)) return;
    const before = this.item(), family = before.family;
    await this.write('deployment', 'trust', async context => {
      const payload = {action, family, request_id: before.request_id};
      if (action === 'prepare') {
        if (family === 'device-tls') {payload.names = normalizeNames(this.state.names); payload.mode = this.state.mode;}
        if (family === 'instruction-roots') {
          const a = this.state.rootA.trim(), b = this.state.rootB.trim();
          if (!rootId(a) || !rootId(b) || a === b) throw Error('Provide two distinct existing root names.');
          payload.roots = rootsPublic({[a]: await this.publicFile('root-a', 4096, value => value, context), [b]: await this.publicFile('root-b', 4096, value => value, context)});
          payload.keylist_signer = a;
        }
        if (!this.services.confirm('Prepare replacement trust? Active credentials remain unchanged until separately confirmed maintenance.')) return;
        payload.request_id = this.pendingId('trust:' + family, JSON.stringify(payload), 'deployment', 'trust', family);
      } else if (action === 'approve') {
        payload.certificate = await this.publicFile('certificate', 65536, value => {
          if (family !== 'instruction-roots') return publicPem(value);
          if (!publicCertificate(value)) throw Error('Choose the approved public online certificate.'); return value;
        }, context);
        if (family === 'instruction-roots') payload.keylist = await this.publicFile('keylist', 128 * 1024, value => signedKeylist(value, before.keylist_signer, before.keylist_payload), context);
      } else if (action.startsWith('attestation-')) {
        payload.root_id = this.state.attestRoot;
        if (action === 'attestation-request') payload.request_id = this.pendingId('attestation', payload.root_id, 'deployment', 'trust', family);
        else {
          payload.request_id = before.attestation_request_id;
          const expected = this.state.attestation?.request_id === payload.request_id && this.state.attestation.root_id === payload.root_id ? this.state.attestation.payload : null;
          payload.keylist = await this.publicFile('attestation-keylist', 128 * 1024, value => signedKeylist(value, payload.root_id, expected), context);
        }
      } else if (!this.services.confirm('Discard this uncommitted trust request? Active trust remains unchanged.')) return;
      return payload;
    }, (payload, data) => checkedTrust(payload, before, data));
  }
  async rotate(recovery = null) {
    if (!this.canRotate(recovery)) return;
    const row = recovery && this.state.rotation.jobs.find(row => row.id === recovery), family = row?.family || this.state.family, item = this.item();
    await this.write('deployment', 'rotation', async () => {
      if (!this.services.confirm(recovery ? 'Resume this previously approved operation? The worker rechecks backup and recovery access, stops writers and verifies the replacement.'
        : 'Stop this IRIS deployment, verify a cold backup, and rotate this credential? Trust changes require confirmed IRIS removal from devices. Acceptance is not completion.')) return;
      return {action: recovery ? 'recover-rotation' : 'rotate', family, allow_downtime: true,
        request_id: row?.id || (trustFamilies.includes(family) ? item.request_id : this.pendingId('rotate:' + family, family, 'deployment', 'rotation', family))};
    }, (payload, data) => acceptedJob(data, payload) ? {accepted: payload.request_id} : null);
  }
  async backup(action, recovery = null) {
    if (!this.canBackup(action, recovery)) return;
    const row = recovery && this.state.backups.jobs.find(row => row.id === recovery), selected = row?.backup_id || this.state.backupSelected;
    await this.write('backups', 'backups', async () => {
      const question = action === 'backup' ? 'Stop IRIS and the Console briefly to capture a consistent encrypted backup? Active transfers and management requests will be interrupted.'
        : action === 'extract' ? 'Extract both sets into a new protected recovery directory? It includes secret recovery material and starts no services.'
          : ['restore', 'recover-restore'].includes(action) ? 'Restore this deployment from the selected backup? The worker stops IRIS, checks current security and replay authority, and retains previous files for recovery.' : null;
      if (question && !this.services.confirm(question)) return;
      const payload = {action, request_id: row?.id || this.pendingId('backup:' + action, action === 'backup' ? action : action + ':' + selected, 'backups', 'backups')};
      if (action !== 'backup') payload.backup_id = selected;
      if (['backup', 'restore', 'recover-restore'].includes(action)) payload.allow_downtime = true;
      if (['restore', 'recover-restore'].includes(action)) payload.confirm_restore = true;
      return payload;
    }, (payload, data) => acceptedJob(data, payload) ? {accepted: payload.request_id} : null);
  }
  async retire(action) {
    if (!this.canRetire(action)) return;
    const retention = this.state.backups.retention, rows = this.retirableJobs(), prior = retention.operation;
    const selected = action === 'resume-delete' ? prior.backup_id : this.state.backupDeleteSelected;
    await this.write('backups', 'backups', async () => {
      const question = action === 'retire-history'
        ? 'Clear ' + rows.length + ' finished history record' + (rows.length === 1 ? '' : 's') + '? Saved backups, security records and recovery records are kept.'
        : action === 'resume-delete'
          ? 'Resume deletion of backup ' + selected + '? This continues the same interrupted deletion of its deployment and recovery archives.'
          : 'Delete backup ' + selected + '? This permanently removes its encrypted deployment and recovery archives from this host. Check any independently stored copies before continuing.';
      if (!this.services.confirm(question)) return;
      const payload = {action, request_id: action === 'resume-delete' ? prior.request_id : this.services.uuid(), expected_revision: retention.revision,
        ...(action === 'retire-history' ? {job_ids: rows.map(row => row.id)} : {backup_id: selected, confirm_delete: true})};
      this.update({retentionAttempt: structuredClone(payload), retentionUncertain: false});
      return payload;
    }, (payload, data) => matchingRetention(data?.retention_operation, payload) ? {retention: retentionOperation(data.retention_operation)} : null);
  }
  async schedule(action = 'save-policy', id = null) {
    if (!this.canSchedule(action, id)) return;
    const before = this.state.maintenance;
    await this.write('maintenance', 'maintenance', async () => {
      if (action === 'save-policy') {
        const draft = this.state.schedule, identifier = draft.selected || this.pendingId('schedule', JSON.stringify(draft), 'maintenance', 'maintenance');
        const payload = schedulePayload(draft, this.state.draftRevision, identifier), capability = before.families.find(row => row.id === draft.family);
        if (draft.enabled && !this.services.confirm('Enable this UTC schedule for ' + capability.label + '? ' + capability.requirement + '.')) return;
        return payload;
      }
      const message = action === 'reviewed' ? 'Acknowledge review? This does not record a completed rotation.'
        : action === 'retire-management' ? 'Have you updated and verified every Console using the replacement credential? Retire the previous credential now?'
          : action === 'retry' ? 'Have you reviewed recovery access and the interrupted operation? Retry this exact operation now?'
            : 'Check the credential files against this interrupted operation? This does not retire either credential.';
      if (!this.services.confirm(message)) return;
      return {action, job_id: id, confirm: true};
    }, (payload, data) => {const state = checkedMaintenance(payload, before, data); return state ? {state} : null;});
  }
  async write(group, kind, build, check) {
    const context = this.context; let sent = false, payload;
    this.cancelReads(); this.update({busy: true});
    try {
      payload = await build(context);
      if (!payload || context !== this.context || !this.visible()) return;
      if (payload.request_id !== undefined && !requestId(payload.request_id)) throw Error('Request identity unavailable. Refresh before continuing.');
      const body = workerBody(payload, kind);
      for (const pending of Object.values(this.pending)) if (pending.id === (payload.request_id || payload.policy?.id)) pending.payload = structuredClone(payload);
      if (kind === 'trust') this.clearFiles();
      this.say(group, 'Submitting… Leaving this page does not cancel the request.', 'info'); sent = true;
      let response, data;
      try {response = await this.services.fetch(urls[kind], {method: 'POST', headers: this.services.headers({'Content-Type': 'application/json'}), body}); data = await response.json().catch(() => null);} catch { /* No result is not proof of refusal. */ }
      const result = response?.status === 200 ? check(payload, data) : null;
      if (!result) {
        const retention = kind === 'backups' && ['retire-history', 'delete-backup', 'resume-delete'].includes(payload.action);
        if (retention && [400, 401, 403, 409].includes(response?.status)) {
          this.update({retentionAttempt: null, retentionUncertain: false});
          this.say(group, 'Cleanup request refused (' + response.status + '). ' + workerRefusalHint(response.status, data) + 'Refresh backup history and review the available actions before continuing.');
          return;
        }
        this.update({unknown: {...this.state.unknown, [group]: true}, ...(retention ? {retentionUncertain: true} : {})});
        this.say(group, (response?.status >= 400 && response.status < 500 ? 'Request refused (' + response.status + '). ' + workerRefusalHint(response.status, data) : 'Outcome unknown. The server may have accepted the request. ') + 'Refresh and review the exact operation before continuing.'); return;
      }
      for (const [key, pending] of Object.entries(this.pending)) if (pending.id === (payload.request_id || payload.policy?.id)) delete this.pending[key];
      if (result.retention) {
        const operation = result.retention;
        this.update({retentionUncertain: false, retentionAttempt: null});
        this.say(group, operation.state === 'completed'
          ? operation.action === 'retire-history' ? 'Cleared ' + operation.retired_count + ' finished history record' + (operation.retired_count === 1 ? '' : 's') + '. Saved backups and recovery records are kept.' : 'Deleted the deployment and recovery archives for backup ' + operation.backup_id + '.'
          : operation.state === 'recovery-required' ? 'Backup deletion needs recovery. Refresh history, then resume this exact deletion.'
            : 'Accepted cleanup request ' + operation.request_id + '. Refresh backup history to check its result.', operation.state === 'recovery-required' ? 'error' : 'success');
      } else if (result.accepted) this.say(group, 'Accepted operation ' + result.accepted + '. Refresh history for the worker result. During downtime, use host recovery if the Console remains offline.', 'success');
      else if (kind === 'maintenance') {
        this.update({maintenance: result.state});
        if (payload.action === 'save-policy') this.update({schedule: scheduleDraft(payload.policy, this.services.now()), draftDirty: false, draftRevision: result.state.revision});
        const job = result.state.jobs.find(row => row.id === payload.job_id);
        this.say(group, payload.action === 'save-policy' ? 'Schedule saved at revision ' + result.state.revision + '.' : job.state === 'intervention-required' ? 'Operation still requires intervention. Review its evidence before another retry.'
          : payload.action === 'reviewed' ? 'Review acknowledged. This is not evidence of credential rotation.' : 'Operation ' + job.id + ': ' + job.state.replaceAll('-', ' ') + '. Review its evidence.', job?.state === 'intervention-required' ? 'error' : 'success');
      } else if (result.request) {
        this.update({attestation: result.request});
        try {this.services.download('keylist-payload.json', result.request.payload); this.say(group, 'Public root confirmation request downloaded for ' + result.request.root_id + '. Its holder approves it with that root key, then returns the signed public list.', 'success');}
        catch {this.say(group, 'Attestation request prepared, but download failed. Refresh, then download the current request again.');}
      } else {
        if (this.state.trust) this.update({trust: {...this.state.trust, items: this.state.trust.items.map(row => row.family === result.state.family ? result.state : row)}});
        this.say(group, payload.action === 'approve' ? 'Public approval validated for request ' + payload.request_id + '. Confirm downtime separately before publication.'
          : payload.action === 'cancel' ? 'Replacement request ' + payload.request_id + ' cancelled. Active trust remains unchanged.'
            : payload.action === 'attestation-apply' ? 'Signed root confirmation applied for ' + payload.root_id + ', request ' + payload.request_id + '. Confirm the other root separately.'
              : 'Replacement prepared: ' + payload.request_id + '. Download public files and complete the required approvals.', 'success');
      }
    } catch (error) {
      if (sent) {
        const retention = kind === 'backups' && ['retire-history', 'delete-backup', 'resume-delete'].includes(payload?.action);
        this.update({unknown: {...this.state.unknown, [group]: true}, ...(retention ? {retentionUncertain: true} : {})}); this.say(group, 'Outcome unknown. Refresh and review current evidence before continuing.');
      }
      else this.say(group, error.message);
    } finally {
      if (!sent && context !== this.context) this.say(group, 'The request was not submitted because you left this page.', 'info');
      this.cancelReads(); this.update({busy: false}); if (this.visible()) await this.refreshAll();
    }
  }
}
