// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {checkedIds} from './assignments-model.mjs';
import {revisionOk, checkedRolePreview, roleFailureText, rolePreviewText, roleProblem, roleCommitResult, quarantineResult, quarantineConflict} from './role-actions-model.mjs';

export class RoleActionsController {
  constructor() {
    this.state = {open: false, ids: [], choice: '', preview: null, busy: false, externalBusy: false,
      policy: null, policyOk: false, warning: '', message: '', failed: false, reviewRequired: false, results: []};
    this.listeners = new Set(); this.generation = 0; this.ownsLock = false;
  }
  snapshot = () => this.state;
  subscribe = listener => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  update(patch) { this.state = {...this.state, ...patch}; this.listeners.forEach(listener => listener()); }
  connect(services) { this.services = services; }
  visible() { return this.services?.isVisible?.() !== false; }
  report(message, failed = false) { this.services?.report?.(message, failed); }
  prerequisites(state) {
    this.update({policy: state.policy, policyOk: state.policyOk, warning: this.services?.warning?.() || '',
      externalBusy: (state.bulkBusy && !this.ownsLock) || state.rowBusy.size > 0});
  }
  warning() { return this.services.warning() || (this.services.policyWriteBusy() ? 'Another policy change is still running. Wait before trying again.' : ''); }
  open(ids) {
    if (this.state.busy || this.state.externalBusy) return;
    const warning = this.warning(); if (warning) {this.report(warning, true); return;}
    try {ids = checkedIds(ids); if (!ids.length) return;} catch {this.report('Select valid devices before setting a role.', true); return;}
    this.close(); this.update({open: true, ids, choice: '', results: [],
      message: this.state.reviewRequired ? 'The previous role result is uncertain. Refresh policy before retrying.' : '',
      failed: this.state.reviewRequired});
  }
  close() { this.generation++; this.update({open: false, preview: null}); if (!this.state.busy) this.release(); }
  hide() { this.close(); }
  choice(value) {
    if (this.state.busy) return;
    this.generation++; this.update({choice: value, preview: null,
      message: this.state.reviewRequired ? 'The previous role result is uncertain. Refresh policy before retrying.' : '',
      failed: this.state.reviewRequired}); this.release();
  }
  claim() {
    if (this.ownsLock) return true;
    // Mark ownership before synchronous Inventory subscribers see this lock.
    this.ownsLock = true;
    if (!this.services.claimBulk()) {this.ownsLock = false; return false;}
    this.update({externalBusy: false}); return true;
  }
  release() { if (this.ownsLock) {this.ownsLock = false; this.services.releaseBulk();} }
  async refresh() {
    if (this.visible()) {try {return await this.services.refreshInventory() === true;} catch { /* Independent read state. */ }}
    return false;
  }
  async review() {
    if (this.state.busy) return;
    const generation = this.generation, refreshed = await this.refresh();
    if (refreshed && generation === this.generation && this.state.open && this.state.policyOk && revisionOk(this.state.policy?.revision)) {
      this.update({reviewRequired: false, message: 'Policy refreshed. Review the targets and preview again.', failed: false});
    } else if (generation === this.generation && this.state.open) {
      this.update({message: 'Current policy could not be confirmed. Refresh and review before retrying.', failed: true});
    }
  }
  async apply() {
    if (!this.state.open || this.state.busy || this.state.reviewRequired) return;
    const warning = this.warning();
    if (warning) {this.update({preview: null, message: warning, failed: true}); this.release(); return;}
    const preview = this.state.preview, choice = this.state.choice, committing = !!preview;
    if (!choice) {this.update({message: 'Choose a role, or no role to clear the declared role.', failed: true}); return;}
    if (!committing && choice !== '__none' && !Object.hasOwn(this.state.policy?.roles?.members || {}, choice)) {
      this.update({message: 'This role is unavailable. Refresh and choose a current role.', failed: true}); return;
    }
    const ids = (preview?.ids || this.state.ids).slice(), revision = preview?.revision ?? this.state.policy?.revision;
    const role = committing ? preview.role : choice === '__none' ? null : choice;
    if (!this.state.policyOk || !revisionOk(revision)) {this.update({message: 'Peer policy revision unavailable. Refresh before previewing.', failed: true}); this.release(); return;}
    if (!this.claim()) {this.update({message: 'Another device action is still running. Wait before trying again.', failed: true}); return;}
    const generation = this.generation; let keepLock = false;
    this.update({busy: true, message: committing ? 'Setting role… Closing this dialog does not cancel the request.' : 'Previewing change…', failed: false});
    if (committing) this.services.invalidatePolicyReads();
    try {
      const response = await this.services.fetch('/api/v1/devices/bulk-role' + (committing ? '' : '?dry_run=1'), {
        method: 'POST', headers: this.services.headers({'Content-Type': 'application/json', 'If-Match': `"iris-peer-policy-${revision}"`}),
        body: JSON.stringify({device_ids: ids, role, ...(committing ? {confirm_token: preview.body.confirm_token} : {})})});
      const body = await response.json();
      if (!committing && generation !== this.generation) return;
      if (committing) {
        const result = roleCommitResult(response, body, ids, revision);
        const message = result === 'unknown' ? 'Response incomplete or unavailable. Role changes may have been saved; refresh and review before trying again.'
          : result === 'refused' ? roleProblem(response.status, body)
            : `Set role applied to ${body.applied}/${ids.length} device(s)` + roleFailureText(body.failed) + `; role drift: ${body.role_drift.count}.`
              + (result === 'partial' ? ' Review the remaining failures or drift before another preview.' : '');
        this.report(message, result !== 'saved');
        // Keep uncertainty through close/navigation, even when the response
        // belongs to a dialog that has already closed.
        this.update({reviewRequired: result === 'unknown'});
        if (generation === this.generation) {
          this.update({preview: null, message, failed: result !== 'saved', reviewRequired: result === 'unknown'});
          if (result === 'saved') this.close();
        }
      } else if (!response.ok) this.update({preview: null, message: roleProblem(response.status, body), failed: true});
      else {
        const checked = checkedRolePreview(body, ids, revision);
        if (!checked) this.update({preview: null, message: 'No role changes can be applied' + roleFailureText(body.failed) + '.', failed: true});
        else {
          this.update({preview: {ids, role, revision, body: checked, text: rolePreviewText(checked, role, ids.length)},
            message: 'Review the preview, then choose Set role to save or Cancel to leave roles unchanged.', failed: false});
          keepLock = true;
        }
      }
    } catch (error) {
      const message = committing ? 'Response unavailable. Role changes may have been saved; refresh and review before trying again.'
        : error.message?.startsWith('Preview') ? error.message : 'Preview unavailable. No commit was sent; refresh and preview again.';
      if (committing) {this.report(message, true); this.update({reviewRequired: true});}
      if (generation === this.generation) this.update({preview: null, message, failed: true, reviewRequired: committing});
    } finally {
      this.update({busy: false});
      if (!keepLock || generation !== this.generation) this.release();
      if (committing) this.services.invalidatePolicyReads();
      if (committing || !keepLock) await this.refresh();
    }
  }
  async quarantine(ids, value) {
    if (this.state.busy || this.ownsLock || this.state.externalBusy || this.services.policyWriteBusy()) return;
    let revision = this.state.policy?.revision;
    if (!this.state.policyOk || !revisionOk(revision) || this.state.policy.fail_closed || this.state.policy.degraded) {
      this.report('Peer policy unavailable. Refresh before changing quarantine.', true); return;
    }
    try {ids = checkedIds(ids); if (!ids.length) return;} catch {return;}
    const verb = value ? 'Quarantine' : 'Release';
    if (!this.services.confirm(`${verb} ${ids.length} device(s)?\n\n${ids.join(', ')}\n\nChanges peer and server access for all images. Existing device-to-device transfers may continue. Device software is unchanged.`) || !this.claim()) return;
    this.update({busy: true, results: []}); this.services.invalidatePolicyReads();
    const results = []; let stopped = false;
    try {
      for (const id of ids) {
        if (stopped) {results.push({id, result: 'not attempted'}); continue;}
        let result = 'unknown';
        for (let attempt = 0; attempt < 2; attempt++) {
          try {
            const response = await this.services.fetch('/api/v1/peer-policy/quarantine/' + encodeURIComponent(id), {
              method: 'PUT', headers: this.services.headers({'Content-Type': 'application/json', 'If-Match': `"iris-peer-policy-${revision}"`}),
              body: JSON.stringify({quarantined: value, if_revision: revision})});
            const body = await response.json(); result = quarantineResult(response, body, value, revision);
            if (result === 'saved') revision = body.revision;
            else if (attempt === 0 && quarantineConflict(response, body)) {
              const read = await this.services.fetch('/api/v1/peer-policy'), policy = await read.json();
              if (read.ok && revisionOk(policy?.revision) && !policy.fail_closed && !policy.degraded) {revision = policy.revision; continue;}
              result = 'refused; current policy unavailable'; stopped = true;
            }
          } catch {result = 'unknown';}
          break;
        }
        results.push({id, result}); if (result === 'unknown') stopped = true;
      }
      const saved = results.filter(row => row.result === 'saved').length;
      this.update({results});
      this.report(`${verb} intent saved for ${saved}/${ids.length} device(s).`
        + results.filter(row => row.result !== 'saved').map(row => ` ${row.id}: ${row.result}.`).join('')
        + (stopped ? ' Refresh and review before trying again.' : ''), saved !== ids.length);
    } finally {this.update({busy: false}); this.release(); this.services.invalidatePolicyReads(); await this.refresh();}
  }
}
