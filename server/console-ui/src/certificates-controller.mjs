// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {CERTIFICATE_LIMIT, KEYLIST_LIMIT, certificateUrl, signerUrl, checkedInventory, checkedSigner, checkedRenewalRequest,
  checkedRenewal, checkedSignerResult, signerAllows, retirementPayload, approvalBody, publicApproval, requestId, refusedCertificateMessage} from './certificates-model.mjs';

const confirmations = {
  prepare: 'Prepare a new signing key for a root key holder to approve? The current key keeps working until you apply approval.',
  activate: 'Switch to the approved replacement signer? This cannot be cancelled afterward. Device roots and counters stay unchanged.',
  retire: 'Publish the approved revocation of the previous signing key? Devices must fetch current instructions and the new revocation list. Verify device acceptance afterward.',
  cancel: 'Discard the pending replacement? The current signer will be kept.',
};
export class CertificatesController {
  constructor() {
    this.state = {inventory: null, signer: null, request: null, valid: {}, loading: {}, messages: {}, unknown: {}, busy: false,
      files: {}, fileEpoch: 0, root: ''};
    this.listeners = new Set(); this.generations = {}; this.readers = {}; this.context = 0; this.pendingId = null;
  }
  snapshot = () => this.state;
  subscribe = listener => {this.listeners.add(listener); return () => this.listeners.delete(listener);};
  update(patch) {this.state = {...this.state, ...patch}; this.listeners.forEach(listener => listener());}
  connect(services) {this.services = services;}
  visible() {return this.services?.visible() === true;}
  say(group, text, kind = 'error', source = 'action') {this.update({messages: {...this.state.messages, [group]: {text, kind, source}}});}
  cancelReads() {
    for (const group of ['inventory', 'signer']) {this.generations[group] = (this.generations[group] || 0) + 1; this.readers[group]?.abort();}
    this.readers = {}; this.update({loading: {}});
  }
  clearFiles() {this.update({files: {}, fileEpoch: this.state.fileEpoch + 1});}
  hide() {
    this.context++; this.cancelReads(); this.clearFiles(); this.update({request: null, valid: {}, inventory: null});
  }
  file(action, file) {if (!this.state.busy && this.visible()) this.update({files: {...this.state.files, [action]: file}});}
  root(value) {if (!this.state.busy && this.state.signer?.root_ids.includes(value)) this.update({root: value});}
  available(group) {return this.visible() && !this.state.busy && !this.state.loading[group] && this.state.valid[group] === true && !this.state.unknown[group];}
  refreshAll() {return Promise.all([this.refresh('inventory'), this.refresh('signer')]);}
  async refresh(group, explicit = false) {
    if (!['inventory', 'signer'].includes(group) || !this.visible() || this.state.busy) return false;
    const generation = (this.generations[group] || 0) + 1; this.generations[group] = generation;
    const reader = new AbortController(); this.readers[group]?.abort(); this.readers[group] = reader;
    this.update({loading: {...this.state.loading, [group]: true}, valid: {...this.state.valid, [group]: false}});
    try {
      const response = await this.services.fetch(group === 'inventory' ? certificateUrl : signerUrl, {signal: reader.signal});
      const data = await response.json();
      if (generation !== this.generations[group] || !this.visible()) return false;
      if (response.status !== 200 || !(group === 'inventory' ? checkedInventory(data) : checkedSigner(data))) throw Error();
      const patch = {[group]: data, valid: {...this.state.valid, [group]: true}};
      if (this.state.messages[group]?.source === 'read') patch.messages = {...this.state.messages, [group]: null};
      if (group === 'signer') {
        patch.root = data.root_ids.includes(this.state.root) ? this.state.root : data.root_ids[0] || '';
        if (explicit) {
          patch.unknown = {...this.state.unknown, signer: false};
          // A lost prepare can be retried with the SAME ID only after a fresh
          // explicit read proves no pending request. Do not mint a second ID.
          if (data.request_id === this.pendingId || !signerAllows(data.state, 'prepare')) this.pendingId = null;
          this.clearFiles();
        }
        if (this.state.signer?.request_id !== data.request_id) this.clearFiles();
      }
      this.update(patch);
      if (explicit && group === 'signer') this.say('signer', 'Current rotation loaded. Review the request and fingerprints before continuing.', 'info');
      return true;
    } catch {
      if (generation === this.generations[group] && this.visible()) {
        this.update({[group]: null, valid: {...this.state.valid, [group]: false}});
        if (!this.state.messages[group] || this.state.messages[group].source === 'read') this.say(group,
          group === 'inventory' ? 'Certificate inventory unavailable. Retry after checking the server connection.' : 'Rotation status unavailable. Refresh before continuing.', 'error', 'read');
      }
      return false;
    } finally {if (generation === this.generations[group]) this.update({loading: {...this.state.loading, [group]: false}});}
  }
  async renewalRequest() {
    if (this.state.busy || !this.visible()) return;
    const context = this.context; this.cancelReads(); this.clearFiles(); this.update({busy: true, request: null});
    this.say('renew', 'Preparing public renewal request…', 'info');
    try {
      const response = await this.services.fetch(certificateUrl + '/instruction/request', {method: 'POST', headers: this.services.headers({'Content-Type': 'application/json'}), body: '{}'});
      const data = await response.json();
      if (context !== this.context || !this.visible()) {
        this.say('renew', 'Public request was not kept because you left this page. Download a fresh request.', 'info'); return;
      }
      if (response.status !== 200 || !checkedRenewalRequest(data)) throw Error();
      this.update({request: data, unknown: {...this.state.unknown, renew: false}});
      this.download('iris-online.pub', data.public_key, 'renew', 'Ask a root signing key holder to approve iris-online.pub with iris-key-setup. Return only the public certificate. If you reopen this page, download a fresh request before importing.');
    } catch {
      this.say('renew', 'Public renewal request unavailable. Check signing status and prepare the request again.');
    } finally {this.update({busy: false}); if (this.visible()) await this.refreshAll();}
  }
  download(name, bytes, group, message) {
    if (!this.visible()) return;
    try {this.services.download(name, bytes); if (message) this.say(group, message, 'info');}
    catch {this.say(group, 'Download unavailable. No approval was submitted; retry the public download.');}
  }
  downloadSigner() {if (this.available('signer') && this.state.signer?.public_key) this.download('iris-replacement.pub', this.state.signer.public_key, 'signer');}
  async perform(action) {
    const group = action === 'renew' ? 'renew' : 'signer';
    if (!this.visible() || this.state.busy || this.state.unknown[group]) return;
    if (group === 'renew' ? !this.state.request : !this.available('signer') || !signerAllows(this.state.signer.state, action)) return;
    const before = this.state.signer, renewal = this.state.request, root = this.state.root, file = this.state.files[action], context = this.context;
    // Lock before the first asynchronous file read, not just before POST.
    this.cancelReads(); this.update({busy: true});
    let payload, sent = false;
    try {
      payload = group === 'renew' ? {public_key_sha256: renewal.public_key_sha256, certificate_sha256: renewal.certificate_sha256}
        : {action, request_id: before.request_id};
      if (['renew', 'activate', 'retire'].includes(action)) {
        const limit = action === 'retire' ? KEYLIST_LIMIT : CERTIFICATE_LIMIT;
        if (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > limit) throw Error('Choose a public approval within ' + (limit / 1024) + ' KiB.');
        const raw = await file.text();
        if (context !== this.context || !this.visible()) return;
        if (typeof raw !== 'string' || new TextEncoder().encode(raw).length > limit) throw Error('Public approval exceeds its size limit.');
        payload[action === 'retire' ? 'artifact' : 'certificate'] = publicApproval(raw, action);
        if (group === 'signer') payload.confirm = true;
      }
      if (action === 'retirement-request') {
        if (!before.root_ids.includes(root)) throw Error('Choose a configured approving root.');
        payload.root_id = root;
      }
      if (confirmations[action] && !this.services.confirm(confirmations[action])) return;
      if (context !== this.context || !this.visible()) return;
      if (action === 'prepare') {
        this.pendingId ||= this.services.uuid();
        if (!requestId(this.pendingId)) throw Error('Could not create a request ID. Reload the Console.');
        payload.request_id = this.pendingId;
      }
      const body = approvalBody(payload);
      this.clearFiles(); this.say(group, 'Submitting… Leaving this page does not cancel the request.', 'info'); sent = true;
      let response, data;
      try {
        response = await this.services.fetch(group === 'renew' ? certificateUrl + '/instruction/renew' : signerUrl,
          {method: 'POST', headers: this.services.headers({'Content-Type': 'application/json'}), body});
        data = await response.json().catch(() => null);
      } catch { /* Unknown writes are never automatically replayed. */ }
      let outcome = response?.status === 200 ? 'confirmed' : response?.status >= 400 && response.status < 500 ? 'refused' : 'unknown', publicBytes;
      if (outcome === 'confirmed') {
        try {
          if (action === 'retirement-request') publicBytes = retirementPayload(data, payload);
          else if (!(group === 'renew' ? checkedRenewal(data) : checkedSignerResult(action, payload, before, data))) outcome = 'unknown';
        } catch {outcome = 'unknown';}
      }
      if (outcome === 'confirmed') {
        if (group === 'renew') {
          this.update({request: null});
          this.say(group, 'Renewal applied. Expires ' + this.services.formatDate(data.expires_at) + '; signing stops ' + this.services.formatDate(data.refuse_at) +
            '. The signing key and device trust are unchanged.' + (data.status_refreshed ? '' : ' Signing status refresh is pending; check again shortly.'), 'success');
        } else if (action === 'retirement-request') {
          this.say(group, 'Retirement request prepared. Download it again if you left this page before it finished.', 'info');
          if (context === this.context && this.visible()) this.download('keylist.payload', publicBytes, group, 'Retirement request downloaded. Ask the holder of ' + payload.root_id + ' to approve it with iris-key-setup.');
        } else {
          this.pendingId = null; this.update({signer: data});
          this.say(group, action === 'activate' ? (data.state === 'completed' ? 'Replacement signer active; previous key retirement is published. Verify fleet acceptance.' : 'Replacement signer active. Ask a root key holder to approve retirement of the previous key next.')
            : action === 'retire' ? 'Retirement approval validated and published. Verify fleet acceptance.'
              : action === 'cancel' ? 'Pending replacement cancelled; active signer unchanged.' : 'Replacement prepared. Download its public key for a root key holder to approve.', 'success');
        }
      } else {
        this.update({unknown: {...this.state.unknown, [group]: true}, ...(group === 'renew' ? {request: null} : {})});
        const review = group === 'renew' ? 'Prepare a fresh public renewal request before submitting again.' : 'Refresh rotation and review the request and fingerprints before continuing.';
        this.say(group, outcome === 'unknown' ? 'Outcome unknown. The server may have applied the request. ' + review
          : 'Request refused (' + response.status + '). ' + refusedCertificateMessage(response.status, data) + ' ' + review);
      }
    } catch (error) {
      if (sent) this.update({unknown: {...this.state.unknown, [group]: true}, ...(group === 'renew' ? {request: null} : {})});
      this.say(group, sent ? 'Outcome unknown. Refresh and review signing status before continuing.' : error.message);
    }
    finally {
      if (!sent && context !== this.context) this.say(group, 'Approval was not submitted because you left this page.', 'info');
      this.cancelReads(); this.update({busy: false});
      if (this.visible()) await this.refreshAll();
    }
  }
}
