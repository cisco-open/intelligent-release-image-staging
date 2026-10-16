// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {requestId} from './certificates-model.mjs';
import {TLS_URL, CREDENTIAL_URL, FAMILIES, normalizeNames, publicPem, browserStatus, tlsAllows, checkedTlsResult,
  collectorEndpoint, collectorHeaders, metricsToken, credentialStatus, credentialAllows, checkedCredentialResult, lifecycleBody, refusalHint} from './security-lifecycle-model.mjs';

export class SecurityLifecycleController {
  constructor() {
    this.state = {tls: null, credentials: null, family: 'metrics-token', valid: {}, loading: {}, unknown: {}, messages: {}, busy: false,
      names: '', mode: 'ca', token: '', endpoint: '', headers: [{id: 1, name: 'Authorization', value: ''}], file: null, fileEpoch: 0};
    this.listeners = new Set(); this.readers = {}; this.generations = {}; this.context = 0; this.rowId = 1;
    this.pending = {}; this.namesEdited = false; this.endpointEdited = false;
  }
  snapshot = () => this.state;
  subscribe = listener => {this.listeners.add(listener); return () => this.listeners.delete(listener);};
  update(patch) {this.state = {...this.state, ...patch}; this.listeners.forEach(listener => listener());}
  connect(services) {this.services = services; if (!this.namesEdited) this.update({names: services.hostname || ''});}
  visible() {return this.services?.visible() === true;}
  say(key, text, kind = 'error', source = 'action', identity = null) {this.update({messages: {...this.state.messages, [key]: {text, kind, source, identity}}});}
  cancelReads() {
    for (const group of ['tls', 'credentials']) {this.generations[group] = (this.generations[group] || 0) + 1; this.readers[group]?.abort();}
    this.readers = {}; this.update({loading: {}});
  }
  clearSecrets(resetForm = false) {
    this.update({token: '', headers: resetForm ? [{id: ++this.rowId, name: 'Authorization', value: ''}] : this.state.headers.map(row => ({...row, value: ''})),
      ...(resetForm ? {endpoint: ''} : {})});
    if (resetForm) this.endpointEdited = false;
  }
  clearFile() {this.update({file: null, fileEpoch: this.state.fileEpoch + 1});}
  hide() {this.context++; this.cancelReads(); this.clearSecrets(true); this.clearFile(); this.update({valid: {}});}
  groupKey(group) {return group === 'tls' ? 'tls' : this.state.family;}
  available(group, key = this.groupKey(group)) {
    return this.visible() && !this.state.busy && !this.state.loading[group] && this.state.valid[group] === true && !this.state.unknown[key];
  }
  item(family = this.state.family) {return this.state.credentials?.items.find(row => row.family === family);}
  canTls(action) {return this.available('tls') && tlsAllows(this.state.tls, action);}
  canCredential(action) {return this.available('credentials') && credentialAllows(this.item(), action);}
  field(key, value) {
    if (this.state.busy || !this.visible()) return;
    if (['names', 'mode'].includes(key)) {
      if (!this.canTls('prepare') || key === 'mode' && !['ca', 'self-signed'].includes(value)) return;
      this.namesEdited = true;
    } else if (['token', 'endpoint'].includes(key)) {
      if (!this.canCredential('replace')) return;
      if (key === 'endpoint') this.endpointEdited = true;
    } else return;
    this.update({[key]: value});
  }
  file(file) {if (this.canTls('approve')) this.update({file});}
  family(family) {
    if (this.state.busy || !this.visible() || !FAMILIES.includes(family) || family === this.state.family) return;
    this.clearSecrets(true); this.update({family});
    const endpoint = this.item()?.endpoint; if (endpoint) this.update({endpoint});
  }
  header(id, key, value) {
    if (!this.canCredential('replace') || !['name', 'value'].includes(key)) return;
    this.update({headers: this.state.headers.map(row => row.id === id ? {...row, [key]: value} : row)});
  }
  addHeader() {
    if (this.canCredential('replace') && this.state.headers.length < 16) this.update({headers: [...this.state.headers, {id: ++this.rowId, name: '', value: ''}]});
  }
  removeHeader(id) {if (this.canCredential('replace') && this.state.headers.length > 1) this.update({headers: this.state.headers.filter(row => row.id !== id)});}
  generateToken() {
    if (!this.canCredential('replace') || this.state.family !== 'metrics-token') return;
    try {
      const token = this.services.randomToken(); if (!metricsToken(token)) throw Error(); this.update({token});
    } catch {this.say('metrics-token', 'Token generation unavailable. Use a secure replacement supplied by your administrator.');}
  }
  download(kind) {
    if (!this.visible() || this.state.busy) return;
    const key = kind === 'token' ? 'metrics-token' : 'tls';
    try {
      if (kind === 'token') {
        if (this.state.family !== 'metrics-token' || !this.canCredential('replace') || !metricsToken(this.state.token)) throw Error('Generate or enter a valid replacement token first.');
        this.services.download('iris-metrics-token', this.state.token + '\n');
        this.say(key, 'Private credential downloaded. Store it securely and provision it only to authorized scrapers.', 'info');
      } else {
        if (!['csr', 'certificate'].includes(kind) || !this.available('tls') || !this.state.tls?.[kind]) return;
        this.services.download(kind === 'csr' ? 'iris-console.csr' : 'iris-console.crt', this.state.tls[kind]);
      }
    } catch {this.say(key, kind === 'token' ? 'Private token download unavailable. Check the entered token and browser download settings.' : 'Public download unavailable. Retry the download before requesting approval.');}
  }
  refreshAll() {return Promise.all([this.refresh('tls'), this.refresh('credentials')]);}
  async refresh(group, explicit = false) {
    if (!['tls', 'credentials'].includes(group) || this.state.busy || !this.visible()) return false;
    const generation = (this.generations[group] || 0) + 1, key = this.groupKey(group), context = this.context;
    this.generations[group] = generation; this.readers[group]?.abort(); const reader = new AbortController(); this.readers[group] = reader;
    this.update({loading: {...this.state.loading, [group]: true}, valid: {...this.state.valid, [group]: false}});
    try {
      const response = await this.services.fetch(group === 'tls' ? TLS_URL : CREDENTIAL_URL, {signal: reader.signal}), data = await response.json();
      if (generation !== this.generations[group] || context !== this.context || !this.visible()) return false;
      const state = group === 'tls' ? browserStatus(data) : credentialStatus(data);
      if (response.status !== 200 || !state) throw Error();
      const patch = {[group]: state, valid: {...this.state.valid, [group]: true}};
      if (this.state.messages[key]?.source === 'read') patch.messages = {...this.state.messages, [key]: null};
      for (const currentKey of group === 'tls' ? ['tls'] : FAMILIES) {
        const message = this.state.messages[currentKey], identity = group === 'tls' ? state.request_id : state.items.find(row => row.family === currentKey).request_id;
        if (message?.kind === 'success' && message.identity && message.identity !== identity) {
          patch.messages = {...(patch.messages || this.state.messages), [currentKey]: {text: 'The operation changed. Review the current identity and state before continuing.', kind: 'info', source: 'read'}};
        }
      }
      if (group === 'tls' && this.state.tls?.request_id !== state.request_id) this.clearFile();
      if (group === 'credentials' && !this.endpointEdited && this.state.family === 'collector-headers') patch.endpoint = state.items.find(row => row.family === 'collector-headers').endpoint || '';
      const reviewed = explicit && key === this.groupKey(group);
      if (reviewed) {
        patch.unknown = {...this.state.unknown, [key]: false};
        const id = group === 'tls' ? state.request_id : state.items.find(row => row.family === key).request_id;
        if (id === this.pending[key]?.id) delete this.pending[key];
        if (group === 'tls') this.clearFile();
        else if (this.state.unknown[key]) this.clearSecrets();
      }
      this.update(patch);
      if (reviewed) this.say(key, group === 'tls' ? 'Current request loaded. Review its names, fingerprint and state before continuing.' : 'Current credential evidence loaded. Review the operation and observed use before continuing.', 'info');
      return true;
    } catch {
      if (generation === this.generations[group] && context === this.context && this.visible()) {
        this.update({[group]: null, valid: {...this.state.valid, [group]: false}});
        if (!this.state.messages[key] || this.state.messages[key].source === 'read') this.say(key, 'Current evidence unavailable. Refresh before continuing.', 'error', 'read');
      }
      return false;
    } finally {if (generation === this.generations[group]) this.update({loading: {...this.state.loading, [group]: false}});}
  }
  async perform(group, action) {
    if (group === 'tls' ? !this.canTls(action) : group !== 'credentials' || !this.canCredential(action)) return;
    const key = this.groupKey(group), context = this.context, before = group === 'tls' ? this.state.tls : this.item(), file = this.state.file;
    let payload, sent = false, confirmation;
    this.cancelReads(); this.update({busy: true});
    try {
      payload = {action, request_id: before.request_id};
      if (group === 'tls') {
        if (action === 'prepare') {
          payload.names = normalizeNames(this.state.names); payload.mode = this.state.mode;
          confirmation = payload.mode === 'ca' ? 'Generate an encrypted replacement key and a public certificate request for CA approval?'
            : 'Generate a replacement key and self-signed certificate? Browser trust must be updated before applying it.';
        } else if (action === 'approve') {
          if (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > 65536) throw Error('Choose a public PEM certificate chain within 64 KiB.');
          payload.certificate = publicPem(await file.text());
          if (context !== this.context || !this.visible()) return;
        } else if (action === 'apply') {
          payload.confirm = true;
          confirmation = 'Have you approved browser trust for this certificate and verified its names? Apply it to this Console now. Verify a new trusted connection afterward; other Console instances need separate checks.';
        } else confirmation = 'Discard this replacement request? The active certificate remains unchanged.';
      } else {
        payload.family = key; payload.confirm = true;
        if (action === 'replace') {
          if (key === 'metrics-token') {
            if (!metricsToken(this.state.token)) throw Error('Use a 32–256 character token without spaces.');
            payload.token = this.state.token;
          } else {payload.endpoint = collectorEndpoint(this.state.endpoint.trim()); payload.headers = collectorHeaders(this.state.headers);}
          confirmation = key === 'metrics-token' ? 'Have you saved the replacement token for every scraper? Apply it while retaining the previous token?'
            : 'Use these new credentials only at the specified HTTPS collector? Keep the old credential valid there until all senders have moved.';
        } else confirmation = action === 'revert' ? 'Restore the previous IRIS credential setting? External scraper or collector changes will not be rolled back.'
          : key === 'metrics-token' ? 'Have all scrapers moved to the replacement? At least one successful new-token scrape was observed. Remove the previous token now?'
            : 'Have you revoked the previous credential at the collector after moving every sender? Remove the stored previous value from IRIS now?';
      }
      if (confirmation && !this.services.confirm(confirmation)) return;
      if (context !== this.context || !this.visible()) return;
      if (action === 'prepare' || action === 'replace') {
        // Only PUBLIC TLS parameters are cached. Credential retries retain an
        // ID, never a token, header value, payload string or secret fingerprint.
        const parameters = group === 'tls' ? JSON.stringify({names: payload.names, mode: payload.mode}) : null;
        if (!this.pending[key] || this.pending[key].parameters !== parameters) this.pending[key] = {id: this.services.uuid(), parameters};
        payload.request_id = this.pending[key].id;
      }
      if (!requestId(payload.request_id)) throw Error('Could not identify this request. Refresh before continuing.');
      const body = lifecycleBody(payload, group);
      if (group === 'credentials') this.clearSecrets(); else this.clearFile();
      this.say(key, 'Submitting… Leaving this page does not cancel the request.', 'info'); sent = true;
      let response, data;
      try {
        response = await this.services.fetch(group === 'tls' ? TLS_URL : CREDENTIAL_URL, {method: 'POST', headers: this.services.headers({'Content-Type': 'application/json'}), body});
        data = await response.json().catch(() => null);
      } catch { /* A lost response is not proof of refusal. */ }
      const result = response?.status === 200 ? group === 'tls' ? checkedTlsResult(payload, before, data) : checkedCredentialResult(payload, before, data) : null;
      if (result) {
        delete this.pending[key]; this.update({[group]: group === 'tls' ? result.state : result});
        this.say(key, group === 'tls' ? action === 'prepare' ? 'Replacement prepared. Download the public request or approved certificate before continuing.'
          : action === 'approve' ? 'Certificate matches the replacement key, requested names and validity window. Review trust before applying.'
            : action === 'cancel' ? 'Replacement cancelled; active certificate unchanged.'
              : result.reloaded ? 'Certificate published and this Console listener reloaded. Verify a new trusted browser connection.'
                : 'Certificate published; this Console has not confirmed reload. Preserve this request and retry the reload.'
          : action === 'replace' ? 'Replacement saved in encrypted storage. Update consumers and refresh evidence before finishing.'
            : action === 'revert' ? 'Previous IRIS setting restored. Verify external consumers separately.'
              : key === 'metrics-token' ? 'Previous scrape token retired. Verify every scraper continues working.'
                : 'Previous stored collector credentials removed after observed delivery and your retirement confirmation.', 'success', 'action', payload.request_id);
      } else {
        this.update({unknown: {...this.state.unknown, [key]: true}});
        const refused = response?.status >= 400 && response.status < 500;
        this.say(key, (refused ? 'Request refused (' + response.status + '). ' + refusalHint(response.status, data) : 'Outcome unknown. The server may have applied the request. ') +
          (group === 'tls' ? 'Refresh request and review its identity and state before continuing.' : 'Refresh evidence and review this credential operation before continuing.'));
      }
    } catch (error) {
      if (sent) this.update({unknown: {...this.state.unknown, [key]: true}});
      this.say(key, sent ? 'Outcome unknown. Refresh and review current evidence before continuing.' : error.message);
    } finally {
      if (!sent && context !== this.context) this.say(key, 'The request was not submitted because you left this page.', 'info');
      this.cancelReads(); this.update({busy: false}); if (this.visible()) await this.refreshAll();
    }
  }
}
