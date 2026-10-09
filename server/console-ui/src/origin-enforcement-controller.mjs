// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {checkedOrigin, checkedOriginPreview, originEtag, originForm, originPayload, originProblem, originWriteResult} from './origin-enforcement-model.mjs';

const PATH = '/api/v1/peer-policy/origin-enforcement';
const UNKNOWN = 'The response was lost or incomplete. The change may have been saved. Refresh and review before trying again.';
export class OriginEnforcementController {
  constructor() {
    this.state = {value: null, ready: false, loading: false, busy: false, committing: false, externalBusy: false,
      form: originForm(), dirty: false, preview: null, message: '', failed: false, reviewRequired: false};
    this.listeners = new Set(); this.readGeneration = 0; this.writeGeneration = 0; this.ownsLock = false;
  }
  snapshot = () => this.state;
  subscribe = listener => {this.listeners.add(listener); return () => this.listeners.delete(listener);};
  update(patch) {this.state = {...this.state, ...patch}; this.listeners.forEach(listener => listener());}
  connect(services) {this.services = services;}
  visible() {return this.services?.isVisible?.() === true;}
  warning() {return this.services?.warning?.() || '';}
  prerequisites(inventory) {this.update({externalBusy: (inventory.bulkBusy && !this.ownsLock) || inventory.rowBusy.size > 0});}
  policy(revision) {
    if (this.observedPolicyRevision !== revision) {
      this.observedPolicyRevision = revision;
      if (this.state.preview || (this.state.busy && !this.state.committing)) this.cancel('Peer policy changed. Refresh and preview again.');
      if (this.state.value?.policy_revision !== revision) this.update({ready: false});
    }
  }
  release() {if (this.ownsLock) {this.ownsLock = false; this.services.releaseBulk();}}
  claim() {
    if (this.ownsLock) return true;
    this.ownsLock = true;
    if (!this.services.claimBulk()) {this.ownsLock = false; this.update({message: 'Another device or policy action is running.', failed: true}); return false;}
    this.update({externalBusy: false}); return true;
  }
  cancel(message = 'Review cancelled. No new change was sent.') {
    this.writeGeneration++; this.update({preview: null, message});
    if (!this.state.busy) this.release();
  }
  hide() {
    this.cancel(this.state.committing ? 'A change is still being saved. Leaving this page does not cancel it.' : '');
    this.readGeneration++; this.reader?.abort(); this.reader = null; this.update({loading: false});
  }
  field(name, value) {
    if (this.state.committing || !Object.hasOwn(this.state.form, name)) return;
    this.cancel('Settings changed. Preview again before applying.');
    this.update({form: {...this.state.form, [name]: value}, dirty: true, failed: false});
  }
  async refresh(review = false) {
    if (!this.visible() || this.state.busy) return false;
    const mine = ++this.readGeneration, reader = new AbortController();
    this.reader?.abort(); this.reader = reader; this.update({loading: true});
    const current = () => mine === this.readGeneration && this.visible();
    try {
      const response = await this.services.fetch(PATH, {signal: reader.signal});
      const body = await response.json(); if (!current()) return false;
      if (!response.ok) throw Error(originProblem(response.status, body));
      const value = checkedOrigin(body, response.headers.get('ETag'));
      if (value.policy_revision !== this.services.policyRevision()) throw Error('Peer policy changed during the read. Refresh policies before reviewing distribution access.');
      if (this.state.preview && (value.revision !== this.state.preview.revision || value.policy_revision !== this.state.preview.request.if_policy_revision)) {
        this.cancel('Distribution access changed. Preview again before applying.');
      }
      if (review) this.cancel('Status refreshed. Review the current settings before another preview.');
      this.update({value, ready: true, failed: false, ...(review ? {reviewRequired: false} : {}),
        ...(!this.state.dirty || review ? {form: originForm(value), dirty: false} : {})});
      return true;
    } catch (error) {
      if (current()) {this.cancel(); this.update({ready: false, message: error.message || 'Distribution-access status unavailable.', failed: true});}
      return false;
    } finally {if (mine === this.readGeneration) {this.reader = null; this.update({loading: false});}}
  }
  async save() {
    if (!this.visible() || this.state.busy || this.state.externalBusy || this.state.reviewRequired) return;
    const warning = this.warning();
    if (warning || !this.state.ready || this.state.value?.policy_revision !== this.services.policyRevision()) {
      this.update({message: warning || 'Refresh distribution access before previewing.', failed: true}); return;
    }
    const previous = this.state.preview, committing = !!previous;
    let request;
    try {request = previous?.request || originPayload(this.state.form, this.services.policyRevision());}
    catch (error) {this.update({message: error.message, failed: true}); return;}
    if (previous?.body.blockers.length || !this.claim()) return;
    const revision = previous?.revision ?? this.state.value.revision, mine = this.writeGeneration;
    this.readGeneration++; this.reader?.abort(); this.reader = null;
    this.update({busy: true, committing, loading: false, failed: false,
      message: committing ? 'Saving the reviewed change. Leaving this page does not cancel it.' : 'Reviewing the affected devices…'});
    let keepLock = false;
    try {
      const response = await this.services.fetch(PATH, {method: 'PUT',
        headers: this.services.headers({'Content-Type': 'application/json', 'If-Match': originEtag(revision)}),
        body: JSON.stringify({...request, dry_run: !committing, ...(committing ? {confirm_token: previous.body.confirm_token} : {})})});
      const body = await response.json().catch(() => null);
      if (!committing && (mine !== this.writeGeneration || !this.visible())) return;
      if (committing) {
        const result = originWriteResult(response, body, request, revision);
        this.update({preview: null, ready: false, reviewRequired: result === 'unknown', dirty: false,
          message: result === 'saved' ? 'Review saved. Waiting for the transfer service to confirm application.' : result === 'unknown' ? UNKNOWN : originProblem(response.status, body),
          failed: result !== 'saved'});
      } else if (!response.ok) {
        this.update({preview: null, ready: false, message: originProblem(response.status, body), failed: true});
      } else {
        const checked = checkedOriginPreview(body, response.headers.get('ETag'), request, revision);
        this.update({preview: {request: structuredClone(request), revision, body: checked},
          message: checked.blockers.length ? 'Resolve these checks, then refresh and preview again.' : 'Review the counts, then apply or cancel. No change has been made.'});
        keepLock = !checked.blockers.length;
      }
    } catch (error) {
      if (committing) this.update({preview: null, ready: false, reviewRequired: true, message: UNKNOWN, failed: true});
      else if (mine === this.writeGeneration) this.update({preview: null, message: 'Preview unavailable or incomplete. No commit was sent; refresh and preview again.', failed: true});
    } finally {
      this.update({busy: false, committing: false});
      if (!keepLock || mine !== this.writeGeneration) this.release();
      // An automatic status poll is never enough to clear an unknown write.
      if (committing && this.visible()) await this.refresh();
    }
  }
}
