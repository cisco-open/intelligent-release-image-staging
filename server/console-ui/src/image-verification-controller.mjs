// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {verificationPaths, verificationSettings, scheduleRequest, checkedVerificationResult, countSummary, validOfflineFile} from './image-verification-model.mjs';

export class ImageVerificationController {
  constructor() {
    this.state = {host: null, data: null, valid: false, loading: false, busy: null, unknown: false,
      mode: 'off', hour: '0', dirty: false, messages: {}, progress: 0};
    this.listeners = new Set(); this.generation = 0; this.edits = 0; this.context = 0;
  }
  snapshot = () => this.state;
  subscribe = listener => {this.listeners.add(listener); return () => this.listeners.delete(listener);};
  update(patch) {this.state = {...this.state, ...patch}; this.listeners.forEach(listener => listener());}
  connect(services) {this.services = services;}
  visible() {return !!this.state.host && this.services?.visible(this.state.host) === true;}
  say(action, text, kind = 'error') {this.update({messages: {...this.state.messages, [action]: {text, kind}}});}
  cancelRead() {this.generation++; this.reader?.abort(); this.reader = null; this.update({loading: false});}
  hide() {this.context++; this.cancelRead(); this.update({valid: false});}
  select(host) {if (this.state.host !== host) this.hide(); this.update({host});}
  field(key, value) {
    if (this.state.busy || !['mode', 'hour'].includes(key)) return;
    this.edits++; this.update({[key]: value, dirty: true});
    if (this.state.messages.schedule?.kind === 'success') this.say('schedule', 'Unsaved schedule changes.', 'info');
  }
  canWrite() {return this.visible() && this.state.valid && !this.state.loading && !this.state.busy && !this.state.unknown;}
  async refresh() {
    if (!this.visible() || this.state.busy) return false;
    this.reader?.abort(); const reader = new AbortController(), generation = ++this.generation;
    this.reader = reader; this.update({loading: true});
    try {
      const response = await this.services.fetch(verificationPaths.settings, {signal: reader.signal});
      const data = verificationSettings(await response.json());
      if (generation !== this.generation || !this.visible()) return false;
      if (response.status !== 200 || !data) throw Error();
      this.update({data, valid: true, ...(!this.state.dirty ? {mode: data.mode, hour: String(data.hour_utc)} : {})});
      this.services.annotation?.(data); return true;
    } catch {
      if (generation === this.generation && this.visible()) {this.update({valid: false}); this.services.annotation?.(null);}
      return false;
    } finally {if (generation === this.generation) {this.reader = null; this.update({loading: false});}}
  }
  async review() {
    if (!this.visible() || this.state.busy || this.state.loading) return;
    if (!this.services.confirm('Reload the current schedule and latest check? Unsaved schedule changes will be discarded. A latest check cannot identify an earlier request whose response was lost. Review the result before requesting another check.')) return;
    const edits = this.edits, context = this.context, generation = this.generation + 1;
    if (!await this.refresh() || generation !== this.generation || edits !== this.edits || context !== this.context) return;
    this.update({mode: this.state.data.mode, hour: String(this.state.data.hour_utc), dirty: false, unknown: false, messages: {}});
    this.say('review', 'Current status loaded. This does not prove the outcome of a request whose response was lost. Review before submitting again.', 'info');
  }
  async perform(action, file) {
    if (!['schedule', 'refresh', 'offline'].includes(action) || !this.canWrite()) return;
    let payload;
    if (action === 'schedule') {
      try {payload = scheduleRequest(this.state.mode, this.state.hour);} catch (error) {this.say(action, error.message); return;}
    }
    if (action === 'offline' && !validOfflineFile(file)) {this.say(action, 'Choose one non-empty .tar feed archive, up to 256 MiB.'); return;}
    this.cancelRead(); this.update({busy: action, progress: 0});
    this.say(action, action === 'offline' ? 'Uploading the feed. Leaving this page does not cancel the check.'
      : action === 'refresh' ? 'Checking the live feed. Leaving this page does not cancel the check.' : 'Saving the schedule…', 'info');
    let result = 'unknown', response, body;
    try {
      if (action === 'offline') {
        const uploaded = await this.upload(file); response = uploaded.response; body = uploaded.body;
      } else {
        response = await this.services.fetch(action === 'schedule' ? verificationPaths.settings : verificationPaths.refresh,
          {method: 'POST', headers: this.services.headers({'Content-Type': 'application/json'}), body: JSON.stringify(payload || {})});
        body = await response.json().catch(() => null);
      }
      result = checkedVerificationResult(action, response, body, payload);
    } catch { /* Keep a sent request uncertain; never replay automatically. */ }
    if (result === 'saved') {
      this.update({dirty: false}); this.say(action, 'Schedule saved.', 'success');
    } else if (result === 'complete') {
      this.say(action, `${action === 'offline' ? 'Offline check' : 'Refresh'} complete: ${countSummary(body)}.`, 'success');
    } else if (result === 'failed') {
      this.say(action, 'Check failed: ' + body.detail);
    } else if (result === 'running') {
      this.update({unknown: true}); this.say(action, 'A refresh is already in progress. Review current status before requesting another check.');
    } else if (result === 'refused') {
      const reason = {400: 'The request was rejected. Check the selected values.', 401: 'Sign in again before retrying.',
        403: 'The request was not authorized. Sign in again before retrying.', 404: 'Image verification is unavailable on this server.',
        413: 'The upload exceeds the server limit of 256 MiB.'}[response.status];
      this.say(action, reason);
    } else {
      this.update({unknown: true}); this.say(action, 'Response unavailable. The schedule may have changed or the check may have started. Review current status before retrying.');
    }
    this.cancelRead(); this.update({busy: null, progress: 0});
    // Also refresh assignments: newly quarantined images must immediately stop
    // being offered in a picker, even when this request's response was lost.
    if (action !== 'schedule') {
      try {await this.services.catalogChanged?.();} catch { /* Each catalog reader renders its own unavailable state. */ }
    }
    if (this.visible()) await this.refresh();
  }
  upload(file) {
    return new Promise((resolve, reject) => {
      const xhr = this.services.xhr(); let settled = false;
      const finish = (error, value) => {
        if (settled) return; settled = true;
        xhr.onload = xhr.onerror = xhr.onabort = xhr.ontimeout = null; xhr.upload.onprogress = null;
        error ? reject(error) : resolve(value);
      };
      xhr.open('POST', verificationPaths.offline);
      for (const [name, value] of Object.entries(this.services.headers({}))) xhr.setRequestHeader(name, value);
      xhr.upload.onprogress = event => {
        if (event.lengthComputable && Number.isFinite(event.loaded) && Number.isFinite(event.total) && event.total > 0) {
          this.update({progress: Math.max(0, Math.min(100, Math.round(event.loaded / event.total * 100)))});
        }
      };
      xhr.onload = () => {
        let body = null; try {body = JSON.parse(xhr.responseText);} catch { /* Invalid JSON is an unknown outcome. */ }
        finish(null, {response: {status: xhr.status}, body});
      };
      xhr.onerror = xhr.onabort = xhr.ontimeout = () => finish(Error('Upload response unavailable'));
      try {xhr.send(file);} catch (error) {finish(error);}
    });
  }
}
