// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {checkedPolicy, roleCapabilityMessage} from './policy-model.mjs';
import {revisionOk} from './role-actions-model.mjs';
import {OriginEnforcementController} from './origin-enforcement-controller.mjs';
import {POLICY_BODY_LIMIT, POLICY_CSV_LIMIT, checkedDefinitions, definitionForm, definitionPayload, policyBody,
  checkedDefinitionPreview, definitionWriteResult, definitionProblem, definitionPreviewText} from './policy-definitions-model.mjs';

export class PoliciesController {
  constructor() {
    this.origin = new OriginEnforcementController();
    this.state = {policy: {}, policyOk: false, definitions: {}, definitionsRevision: null, definitionsOk: false,
      loading: false, readError: '', dialog: null, editor: null, form: definitionForm(), preview: null,
      busy: false, committing: false, externalBusy: false, message: '', failed: false, formMessage: '', reviewRequired: false,
      downloading: false, downloadMessage: ''};
    this.listeners = new Set(); this.readGeneration = 0; this.writeGeneration = 0; this.ownsLock = false;
  }
  snapshot = () => this.state;
  subscribe = listener => {this.listeners.add(listener); return () => this.listeners.delete(listener);};
  update(patch) {this.state = {...this.state, ...patch}; this.listeners.forEach(listener => listener());}
  connect(services) {
    this.services = services;
    this.origin.connect({...services, warning: () => this.capability(), policyRevision: () => this.state.policyOk ? this.state.policy.revision : null});
  }
  visible() {return this.services?.isVisible?.() === true;}
  capability(policy = this.state.policy, ready = this.state.policyOk) {return roleCapabilityMessage(policy, ready);}
  current() {return this.state.policyOk && this.state.definitionsOk && this.state.definitionsRevision === this.state.policy.revision;}
  policy(policy, policyOk) {this.update({policy, policyOk}); this.origin.policy(policyOk ? policy.revision : null);}
  prerequisites(inventory) {
    this.update({externalBusy: (inventory.bulkBusy && !this.ownsLock) || inventory.rowBusy.size > 0});
    this.origin.prerequisites(inventory);
  }
  say(message, failed = false) {this.update({message, failed});}
  cancelReads() {this.readGeneration++; this.reader?.abort(); this.reader = null; this.update({loading: false});}
  close() {this.writeGeneration++; this.update({dialog: null, preview: null}); if (!this.state.busy) this.release();}
  hide() {this.close(); this.origin.hide(); this.cancelReads(); this.downloadReader?.abort(); this.downloadReader = null; this.update({downloading: false});}
  pause() {
    if (this.state.busy && !this.state.committing) {
      this.writeGeneration++;
      this.update({formMessage: 'Preview interrupted. Preview again when you return.', message: 'Review interrupted before saving. Start a new preview when you return.'});
    }
    this.cancelReads(); this.origin.pause(); this.downloadReader?.abort(); this.downloadReader = null; this.update({downloading: false});
  }
  advanced() {if (this.state.dialog === 'editor') this.close(); this.update({dialog: 'advanced'});}
  async refresh(review = false) {
    if (!this.visible() || this.state.busy) return false;
    const mine = ++this.readGeneration, ticket = this.services.beginPolicyRead();
    this.reader?.abort(); const reader = this.reader = new AbortController();
    this.update({loading: true});
    const current = () => mine === this.readGeneration && this.visible();
    let next, accepted = false;
    try {
      const response = await this.services.fetch('/api/v1/peer-policy', {signal: reader.signal});
      next = await response.json();
      if (!current()) return false;
      accepted = this.services.publishPolicy(next, response.ok && checkedPolicy(next), ticket);
      if (!accepted) return false;
      if (!this.state.policyOk) throw Error('Peer policy unavailable. Refresh before editing.');
      if (review || !this.state.definitionsOk || this.state.definitionsRevision !== next.revision) {
        const response = await this.services.fetch('/api/v1/peer-policy/roles', {signal: reader.signal});
        const body = await response.json();
        if (!current()) return false;
        if (!response.ok || body?.degraded || body?.fail_closed) throw Error('Role definitions unavailable. Refresh before editing.');
        const checked = checkedDefinitions(body);
        this.update({definitions: checked.definitions, definitionsRevision: checked.revision, definitionsOk: true});
      }
      if (!current()) return false;
      this.update({readError: this.current() ? '' : 'Policy changed during the read. Refresh to review current definitions.'});
      if (review && this.current() && !this.capability()) {
        const editor = this.state.editor;
        this.update({reviewRequired: false, preview: null,
          editor: editor ? {...editor, stale: editor.stale || this.state.reviewRequired || editor.revision !== next.revision} : null});
        this.release();
        this.say('Policies refreshed. Review current definitions before another preview.');
      }
      await this.origin.refresh();
      return this.current() && !this.capability();
    } catch (error) {
      if (!current()) return false;
      if (!accepted) this.services.publishPolicy(null, false, ticket);
      this.update({definitionsOk: false, readError: 'Policy or role definitions unavailable. Refresh before editing.'});
      return false;
    } finally {if (mine === this.readGeneration) {this.reader = null; this.update({loading: false});}}
  }
  open(name = null) {
    if (this.state.busy || this.state.externalBusy) return;
    const warning = this.capability();
    if (warning || !this.current()) {this.say(warning || 'Current role definitions unavailable. Refresh before editing.', true); return;}
    if (name && !Object.hasOwn(this.state.definitions, name)) {this.say('This role is unavailable. Refresh before editing.', true); return;}
    this.close();
    const original = structuredClone(name ? this.state.definitions[name] : {});
    this.update({dialog: 'editor', editor: {name, original, key: this.writeGeneration, revision: this.state.definitionsRevision, stale: this.state.reviewRequired},
      form: definitionForm(name || '', original), formMessage: this.state.reviewRequired ? 'Previous change is uncertain. Reload and review current definitions before retrying.' : ''});
  }
  field(name, value, qos = false) {
    if (this.state.committing || this.state.dialog !== 'editor') return;
    this.writeGeneration++;
    const form = qos ? {...this.state.form, qos: {...this.state.form.qos, [name]: value}} : {...this.state.form, [name]: value};
    this.update({form, preview: null, formMessage: this.state.reviewRequired ? 'Previous change is uncertain. Reload and review before retrying.' : 'The definition changed. Preview again before saving.'});
    if (!this.state.busy) this.release();
  }
  async reloadEditor() {
    if (this.state.busy || !this.state.editor) return;
    if (!this.services.confirm('Reload the current definition? Unsaved changes in this editor will be discarded.')) return;
    const name = this.state.editor.name || this.state.form.name.trim(), generation = this.writeGeneration;
    if (!await this.refresh(true) || generation !== this.writeGeneration || this.state.dialog !== 'editor') return;
    if (Object.hasOwn(this.state.definitions, name)) this.open(name);
    else {this.close(); this.say('No current definition named ' + name + '. Choose New role to create it.');}
  }
  claim() {
    if (this.ownsLock) return true;
    this.ownsLock = true;
    if (!this.services.claimBulk()) {this.ownsLock = false; this.say('Another device or policy action is still running.', true); return false;}
    this.update({externalBusy: false}); return true;
  }
  release() {if (this.ownsLock) {this.ownsLock = false; this.services.releaseBulk();}}
  invalidateWriteReads() {this.cancelReads(); this.services.invalidatePolicyReads(); this.update({definitionsOk: false});}
  async write(method, path, payload, revision) {
    const body = policyBody(payload, path.split('?')[0].endsWith('/import-csv') ? POLICY_CSV_LIMIT : POLICY_BODY_LIMIT);
    const response = await this.services.fetch(path, {method, headers: this.services.headers({'Content-Type': 'application/json', 'If-Match': `"iris-peer-policy-${revision}"`}), body});
    return {response, body: response.status === 204 ? null : await response.json().catch(() => null)};
  }
  async finish(committing, keepLock = false) {
    if (committing) this.invalidateWriteReads();
    this.update({busy: false, committing: false});
    if (!keepLock) this.release();
    if (committing && this.visible()) await this.refresh();
  }
  async save() {
    if (this.state.dialog !== 'editor' || this.state.busy || this.state.reviewRequired || this.state.editor.stale) return;
    const warning = this.capability();
    if (warning) {this.update({formMessage: warning, preview: null}); this.release(); return;}
    const preview = this.state.preview, committing = !!preview, editor = this.state.editor;
    let built;
    try {built = preview || definitionPayload(this.state.form, editor); policyBody({...built.definition, ...(committing ? {confirm_token: preview.body.confirm_token} : {})});}
    catch (error) {this.update({formMessage: error.message}); return;}
    if (!revisionOk(editor.revision) || !this.claim()) return;
    const generation = this.writeGeneration; let keepLock = false;
    this.update({busy: true, committing, formMessage: committing ? 'Saving role… Closing does not cancel this request.' : 'Previewing change…'});
    if (committing) this.invalidateWriteReads();
    try {
      const {response, body} = await this.write('PUT', '/api/v1/peer-policy/roles/' + encodeURIComponent(built.name) + (committing ? '' : '?dry_run=1'),
        {...built.definition, ...(committing ? {confirm_token: preview.body.confirm_token} : {})}, editor.revision);
      if (!committing && generation !== this.writeGeneration) return;
      if (committing) {
        const result = definitionWriteResult(response, body, editor.revision);
        const message = result.kind === 'saved' ? `Role ${built.name} saved at policy revision ${result.revision}.`
          : result.kind === 'unknown' ? 'Response incomplete or unavailable. The role may have been saved; refresh and review before retrying.' : definitionProblem(response.status, body, 'Save');
        this.say(message, result.kind !== 'saved'); this.update({reviewRequired: result.kind === 'unknown'});
        if (generation === this.writeGeneration) {
          this.update({preview: null, formMessage: message, editor: {...editor, stale: result.kind === 'unknown' || response.status === 412 || (body?.code || body?.error) === 'revision_conflict'}});
          if (result.kind === 'saved') this.close();
        }
      } else if (!response.ok) {
        this.update({preview: null, formMessage: definitionProblem(response.status, body, 'Preview'),
          editor: {...editor, stale: response.status === 412 || (body?.code || body?.error) === 'revision_conflict'}});
      } else {
        const checked = checkedDefinitionPreview(body, editor.revision);
        this.update({preview: {...built, body: checked, text: definitionPreviewText((editor.name ? 'Replace role ' : 'Create role ') + built.name, checked)},
          formMessage: 'Review the preview, then choose Save role to apply or Cancel to leave definitions unchanged.'}); keepLock = true;
      }
    } catch (error) {
      const message = committing ? 'Response unavailable. The role may have been saved; refresh and review before retrying.' : 'Preview unavailable. No commit was sent; refresh and preview again.';
      if (committing) {this.say(message, true); this.update({reviewRequired: true});}
      if (generation === this.writeGeneration) this.update({preview: null, formMessage: message, editor: {...editor, stale: committing}});
    } finally {await this.finish(committing, keepLock && generation === this.writeGeneration);}
  }
  async confirmedChange(kind, input, filename = '') {
    if (this.state.busy || this.state.externalBusy || this.state.reviewRequired) return;
    const warning = this.capability();
    if (warning || !this.current()) {this.say(warning || 'Refresh current definitions before changing them.', true); return;}
    const deleting = kind === 'delete', revision = this.state.definitionsRevision;
    if (deleting && !Object.hasOwn(this.state.definitions, input)) return;
    if (!this.claim()) return;
    const generation = this.writeGeneration; let committing = false;
    this.update({busy: true});
    try {
      let payload = {};
      if (!deleting) {
        if (!input || !Number.isSafeInteger(input.size) || input.size < 0 || input.size > POLICY_CSV_LIMIT) throw Error('This CSV is too large. Reduce it before importing.');
        this.say('Reading ' + filename + '…');
        const csv = await input.text(); if (typeof csv !== 'string') throw Error('Cannot read this CSV.');
        payload = {csv}; policyBody(payload, POLICY_CSV_LIMIT);
      }
      if (generation !== this.writeGeneration || !this.visible()) return;
      const path = deleting ? '/api/v1/peer-policy/roles/' + encodeURIComponent(input) : '/api/v1/peer-policy/roles/import-csv', method = deleting ? 'DELETE' : 'POST';
      this.say(deleting ? 'Previewing deletion of ' + input + '…' : 'Previewing import of ' + filename + '…');
      const preview = await this.write(method, path + '?dry_run=1', payload, revision);
      if (generation !== this.writeGeneration || !this.visible()) return;
      if (!preview.response.ok) {this.say(definitionProblem(preview.response.status, preview.body, deleting ? 'Delete' : 'Import'), true); return;}
      const checked = checkedDefinitionPreview(preview.body, revision, !deleting);
      const title = deleting ? 'Delete role ' + input : `Replace every role definition with the ${checked.roles} role(s) in ${filename}`;
      if (!this.services.confirm(definitionPreviewText(title, checked) + (deleting ? '\n\nDelete this role definition?' : '\n\nRoles missing from the file are removed. Continue?'))) {
        this.say((deleting ? 'Deletion of ' + input : 'Import of ' + filename) + ' cancelled; nothing changed.'); return;
      }
      payload = {...payload, confirm_token: checked.confirm_token}; policyBody(payload, deleting ? POLICY_BODY_LIMIT : POLICY_CSV_LIMIT);
      committing = true; this.update({committing: true}); this.invalidateWriteReads();
      const {response, body} = await this.write(method, path, payload, revision);
      const result = definitionWriteResult(response, body, revision, deleting, deleting ? null : checked.roles);
      this.update({reviewRequired: result.kind === 'unknown'});
      this.say(result.kind === 'saved' ? (deleting ? `Role ${input} deleted` : `Imported ${body.roles} role definition(s) from ${filename}`) + ` at policy revision ${result.revision}.`
        : result.kind === 'unknown' ? 'Response incomplete or unavailable. Definitions may have changed; refresh and review before retrying.'
          : definitionProblem(response.status, body, deleting ? 'Delete' : 'Import'), result.kind !== 'saved');
    } catch (error) {
      if (committing) this.update({reviewRequired: true});
      this.say(committing ? 'Response unavailable. Definitions may have changed; refresh and review before retrying.' : error.message + ' No commit was sent.', true);
    } finally {await this.finish(committing);}
  }
  delete(name) {return this.confirmedChange('delete', name);}
  importFile(file) {if (file) return this.confirmedChange('import', file, file.name);}
  async exportCsv() {
    if (this.state.downloading || this.state.busy || this.capability()) return;
    const reader = this.downloadReader = new AbortController(); this.update({downloading: true, downloadMessage: 'Downloading roles.csv…'});
    const current = () => this.downloadReader === reader && this.visible();
    try {
      const response = await this.services.fetch('/api/v1/peer-policy/roles/export-csv', {signal: reader.signal});
      if (!response.ok || !/^text\/csv(?:;|$)/i.test(response.headers.get('Content-Type') || '')) throw Error('Export unavailable. Refresh before retrying.');
      const text = await response.text(); if (!current()) return;
      this.services.saveCsv(text, 'roles.csv'); this.update({downloadMessage: 'Downloaded roles.csv.'});
    } catch {if (current()) this.update({downloadMessage: 'Export unavailable. Refresh before retrying.'});}
    finally {if (this.downloadReader === reader) {this.downloadReader = null; this.update({downloading: false});}}
  }
}
