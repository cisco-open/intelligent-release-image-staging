// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {SETTINGS_LIMIT, initialForms, settingsValidity, formsFromSettings, checkedPeer, groupPane, actionGroup,
  settingsRequest, checkedSettingsResult, successMessage, refusedSettingsMessage, pemCertificate, pemKey, pemFileFields, encryptedKey, count} from './settings-model.mjs';

export class SettingsController {
  constructor() {
    this.state = {pane: null, telemetryHost: 'td-mount', data: {}, valid: {}, forms: initialForms(), dirty: {}, messages: {},
      unknown: {}, busy: false, loading: false, peer: null, peerBase: null, peerOk: false, jobs: {}, fileBusy: false};
    this.listeners = new Set(); this.readGeneration = 0; this.peerGeneration = 0; this.fileGeneration = 0; this.jobGeneration = 0;
    this.timers = {}; this.jobReaders = {}; this.readers = {}; this.edits = {};
  }
  snapshot = () => this.state;
  subscribe = listener => {this.listeners.add(listener); return () => this.listeners.delete(listener);};
  update(patch) {this.state = {...this.state, ...patch}; this.listeners.forEach(listener => listener());}
  connect(services) {this.services = services;}
  visible(pane = this.state.pane) {return !!pane && this.state.pane === pane && this.services?.visible(pane) === true;}
  say(group, text, kind = 'error') {this.update({messages: {...this.state.messages, [group]: {text, kind}}});}
  select(pane, telemetryHost = 'td-mount') {
    if (pane !== this.state.pane || telemetryHost !== this.state.telemetryHost) this.hide();
    this.update({pane, telemetryHost}); this.resumeJobs();
  }
  clearSecrets(group = null) {
    const forms = {...this.state.forms};
    if (!group || group === 'pw') forms.pw = initialForms().pw;
    if (!group || group === 'cert') forms.cert = initialForms().cert;
    if (!group || group === 'trust') forms.trust = initialForms().trust;
    if (!group || group === 'ae') forms.ae = {...forms.ae, password: ''};
    this.update({forms});
  }
  cancelReads() {
    this.readGeneration++; this.peerGeneration++;
    for (const reader of Object.values(this.readers)) reader?.abort(); this.readers = {};
    this.update({loading: false});
  }
  hide() {
    this.cancelReads(); this.fileGeneration++; this.jobGeneration++;
    for (const timer of Object.values(this.timers)) this.services?.clearTimeout(timer); this.timers = {};
    for (const reader of Object.values(this.jobReaders)) reader.abort(); this.jobReaders = {};
    this.clearSecrets(); this.update({fileBusy: false, valid: {}, peerOk: false});
  }
  field(group, key, value) {
    if (this.state.busy) return;
    this.edits[group] = (this.edits[group] || 0) + 1;
    if (group === 'cert') {this.fileGeneration++; this.update({fileBusy: false});}
    this.update({forms: {...this.state.forms, [group]: {...this.state.forms[group], [key]: value}}, dirty: {...this.state.dirty, [group]: true}});
  }
  available(group) {return !this.state.loading && this.visible(groupPane(group)) && this.state.valid[groupPane(group)] === true && (group !== 'peer' || this.state.peerOk);}
  async refresh() {
    if (!this.visible() || this.state.busy) return false;
    const generation = ++this.readGeneration, reader = new AbortController(); this.readers.settings?.abort(); this.readers.settings = reader;
    this.update({loading: true}); let valid = false;
    try {
      const response = await this.services.fetch('/api/v1/settings', {signal: reader.signal}), data = await response.json();
      if (generation !== this.readGeneration || !this.visible()) return false;
      if (!response.ok) throw Error();
      const checked = settingsValidity(data); if (!Object.values(checked).some(Boolean)) throw Error();
      const forms = {...this.state.forms};
      for (const [group, values] of Object.entries(formsFromSettings(data))) if (!this.state.dirty[group]) forms[group] = values;
      this.update({data, valid: checked, forms}); valid = checked[this.state.pane] === true;
    } catch {
      if (generation === this.readGeneration && this.visible()) this.update({valid: {}});
    } finally {if (generation === this.readGeneration) this.update({loading: false});}
    if (generation === this.readGeneration && this.visible('tls')) await this.refreshPeer();
    this.resumeJobs(); return valid && generation === this.readGeneration && this.visible();
  }
  async review(group) {
    if (this.state.busy || this.state.fileBusy || this.state.loading || !this.visible(groupPane(group))) return;
    if (group === 'pw' && this.state.unknown.pw) {this.say(group, 'Password or sessions may have changed. Sign in again before another password change.'); return;}
    if (!this.services.confirm('Reload current settings for this form? Unsaved input will be discarded. A previous uncertain request may already have changed settings; review them before another submission.')) return;
    const pane = this.state.pane, edits = this.edits[group], files = this.fileGeneration;
    if (!await this.refresh() || pane !== this.state.pane || !this.available(group)) return;
    if (edits !== this.edits[group] || files !== this.fileGeneration) {
      this.say(group, 'Settings refreshed. Your newer edits are kept. Review current settings again before retrying.', 'info'); return;
    }
    const forms = formsFromSettings(this.state.data), next = forms[group] || initialForms()[group] || {};
    if (group === 'peer') {if (!this.state.peerOk) return; next.required = this.state.peer.mode === 'required';}
    this.update({forms: {...this.state.forms, [group]: next}, dirty: {...this.state.dirty, [group]: false},
      unknown: {...this.state.unknown, [group]: false}, ...(group === 'peer' ? {peerBase: this.state.peer.mode} : {})});
    this.say(group, 'Current settings loaded. Review before submitting again.', 'info');
  }
  async refreshPeer() {
    if (!this.visible('tls') || this.state.busy) return;
    const generation = ++this.peerGeneration, reader = new AbortController(); this.readers.peer?.abort(); this.readers.peer = reader;
    this.services.clearTimeout(this.timers.peer); delete this.timers.peer;
    try {
      const response = await this.services.fetch('/api/v1/settings/peer-tls', {signal: reader.signal}), data = await response.json();
      if (generation !== this.peerGeneration || !this.visible('tls')) return;
      if (!response.ok || !checkedPeer(data)) throw Error();
      this.update({peer: data, peerOk: true, ...(!this.state.dirty.peer ? {peerBase: data.mode, forms: {...this.state.forms, peer: {required: data.mode === 'required'}}} : {})});
      if (data.origin.active_mode !== data.mode || data.origin.state !== 'running') this.timers.peer = this.services.setTimeout(() => this.refreshPeer(), 2000);
    } catch {if (generation === this.peerGeneration && this.visible('tls')) this.update({peerOk: false});}
  }
  async perform(action, name) {
    const group = actionGroup(action);
    if (this.state.busy || this.state.fileBusy || this.state.unknown[group] || !this.available(group)) return;
    if ((action === 'caRun' || action === 'aeRun') && this.state.jobs[group]) return;
    let request;
    try {request = settingsRequest(action, this.state, name);} catch (error) {this.say(group, error.message); return;}
    if (request.confirmation && !this.services.confirm(request.confirmation)) return;
    this.cancelReads(); this.fileGeneration++; this.update({busy: true}); this.clearSecrets(group);
    this.say(group, 'Submitting… Leaving this page does not cancel the request.', 'info');
    try {await this.submit(request);}
    finally {this.cancelReads(); this.update({busy: false}); if (this.visible()) await this.refresh();}
  }
  async submit(request) {
    const {group, action} = request;
    let response, body, result = 'unknown';
    try {
      response = await this.services.fetch(request.path, {method: request.method, headers: this.services.headers(request.body === undefined ? {} : {'Content-Type': 'application/json'}), body: request.body});
      body = await response.json().catch(() => null); result = checkedSettingsResult(request, response, body);
    } catch { /* A lost response never proves the write was refused. */ }
    if (result === 'saved') {
      if (action !== 'caRun' && action !== 'aeRun') this.update({dirty: {...this.state.dirty, [group]: false}});
      if (action === 'trust') this.update({forms: {...this.state.forms, trust: {pem: ''}}});
      this.say(group, successMessage(action, body), 'success');
      if (action === 'caRun' || action === 'aeRun') {
        this.update({jobs: {...this.state.jobs, [group]: {id: body.job || body.job_id, state: 'running'}}});
        this.resumeJobs();
      }
    } else if (result === 'unknown') {
      this.update({unknown: {...this.state.unknown, [group]: true}});
      this.say(group, group === 'pw' ? 'Response unavailable. Password or sessions may have changed. Sign in again before retrying.'
        : action === 'ae' && body?.detail === 'settings save failed; audit export is disabled. Reload settings, re-enter the destination and password, then save again'
          ? 'Audit export was disabled after a save failure. Reload current settings, re-enter the destination and password, then save again.'
        : 'Response unavailable. Settings may have changed or a job may have started; reload and review current settings before retrying.');
    } else {
      if (response.status === 409) this.update({unknown: {...this.state.unknown, [group]: true}});
      // Secret-bearing requests never reflect an arbitrary proxy/server body.
      this.say(group, refusedSettingsMessage(action, response.status, body));
    }
    return result;
  }
  async certificateFiles(files) {
    if (this.state.busy || !this.visible('tls')) return;
    const generation = ++this.fileGeneration; this.update({fileBusy: true});
    const recognized = [], errors = []; let form = {...this.state.forms.cert};
    for (const file of files) {
      if (generation !== this.fileGeneration || !this.visible('tls')) return;
      let value;
      try {if (file.size > SETTINGS_LIMIT) throw Error(); value = await file.text(); if (new TextEncoder().encode(value).length > SETTINGS_LIMIT) throw Error();}
      catch {errors.push(file.name + ': could not read a PEM file within 64 KiB'); continue;}
      if (generation !== this.fileGeneration || !this.visible('tls')) return;
      let parts;
      try {parts = pemFileFields(value);} catch {errors.push(file.name + ': choose one private key per file'); continue;}
      const cert = !!parts.pem, key = !!parts.key;
      if (!cert && !key) {errors.push(file.name + ': no PEM block recognized'); continue;}
      if (cert) form.pem = parts.pem;
      if (key) {form.key = parts.key; form.passphrase = '';}
      recognized.push(file.name + ': ' + (cert ? 'certificate' : '') + (cert && key ? ' + ' : '') + (key ? encryptedKey(value) ? 'private key (passphrase-protected)' : 'private key' : '') + ' recognized');
    }
    if (generation !== this.fileGeneration || !this.visible('tls')) return;
    this.update({forms: {...this.state.forms, cert: form}, dirty: {...this.state.dirty, cert: true}, fileBusy: false});
    this.say('cert', recognized.concat(errors).join('; ') || 'No files recognized.', errors.length ? 'error' : 'info');
  }
  async trustFiles(files) {
    if (this.state.busy || this.state.fileBusy || this.state.unknown.trust || !this.available('trust')) return;
    const generation = ++this.fileGeneration, list = [...files]; this.cancelReads(); this.update({busy: true});
    const results = [];
    try {
      for (let index = 0; index < list.length; index++) {
        const file = list[index];
        if (generation !== this.fileGeneration || !this.visible('tls')) {results.push(...list.slice(index).map(item => item.name + ': not attempted')); break;}
        let pem;
        try {if (file.size > SETTINGS_LIMIT) throw Error(); pem = await file.text(); if (typeof pem !== 'string') throw Error();}
        catch {results.push(file.name + ': unreadable or too large'); continue;}
        if (generation !== this.fileGeneration || !this.visible('tls')) {results.push(...list.slice(index).map(item => item.name + ': not attempted')); break;}
        if (!pemCertificate(pem) || pemKey(pem)) {results.push(file.name + ': skipped (use public CA certificates only)'); continue;}
        let request;
        try {request = settingsRequest('trust', {...this.state, forms: {...this.state.forms, trust: {pem}}});}
        catch {results.push(file.name + ': too large'); continue;}
        const result = await this.submit(request); results.push(file.name + ': ' + (result === 'saved' ? 'added' : result));
        if (result === 'unknown') {results.push(...list.slice(index + 1).map(item => item.name + ': not attempted')); break;}
      }
      this.say('trust', results.join('; ') + (this.state.unknown.trust ? '. Reload and review installed CAs before retrying.' : ''), results.every(row => row.endsWith(': added')) ? 'success' : 'info');
    } finally {this.cancelReads(); this.update({busy: false}); if (this.visible()) await this.refresh();}
  }
  resumeJobs() {
    for (const group of ['ca', 'ae']) if (this.state.jobs[group] && !this.jobReaders[group] && !this.timers[group] && this.visible(groupPane(group))) this.pollJob(group);
  }
  async pollJob(group) {
    const job = this.state.jobs[group]; if (!job || !this.visible(groupPane(group))) return;
    const generation = this.jobGeneration, reader = new AbortController(); this.jobReaders[group] = reader;
    this.services.clearTimeout(this.timers[group]); delete this.timers[group];
    const current = () => generation === this.jobGeneration && this.state.jobs[group]?.id === job.id && this.visible(groupPane(group));
    let repeat = true;
    try {
      const path = group === 'ca' ? 'ca-trust/refresh/' : 'audit-export/run/';
      const response = await this.services.fetch('/api/v1/settings/' + path + encodeURIComponent(job.id), {signal: reader.signal});
      const body = await response.json().catch(() => null); if (!current()) return;
      if (!response.ok || !['running', 'done', group === 'ca' ? 'failed' : 'error'].includes(body?.state)) {
        if (response.status === 401) repeat = false;
        if (response.status === 404) {repeat = false; this.update({jobs: {...this.state.jobs, [group]: null}, unknown: {...this.state.unknown, [group]: true}});}
        throw Error();
      }
      if (body.state === 'running') return;
      if (body.state === 'done' && (group === 'ca' ? !count(body.certs) : typeof body.detail !== 'string')) throw Error();
      repeat = false; this.update({jobs: {...this.state.jobs, [group]: null}});
      this.say(group, body.state === 'done' ? group === 'ca' ? `Downloaded ${body.certs} certificate(s).` : 'Exported: ' + body.detail
        : group === 'ca' ? 'CA bundle download failed. The previous bundle stays in use.' : 'Audit export failed. Check the destination and server audit trail.', body.state === 'done' ? 'success' : 'error');
      if (!this.state.busy) await this.refresh();
    } catch {if (generation === this.jobGeneration && this.visible(groupPane(group))) this.say(group, 'Job status unavailable. Review current settings; an unavailable response does not mean the job stopped.', 'error');}
    finally {
      if (this.jobReaders[group] === reader) delete this.jobReaders[group];
      if (repeat && current()) this.timers[group] = this.services.setTimeout(() => {delete this.timers[group]; this.pollJob(group);}, 1000);
    }
  }
}
