// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {validRecordResponse} from './device-details-model.mjs';
import {validRows} from './monitoring-model.mjs';

const uncertain = 'The host-key request outcome is unknown. Check the saved host key before trying again.';

export class DeviceDetailsController {
  constructor() {
    this.state = null;
    this.generation = 0;
    this.fileGeneration = 0;
    this.reads = [];
    this.mutations = new Set();
    this.listeners = new Set();
    this.disposed = false;
  }
  subscribe = listener => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  snapshot = () => this.state;
  update(state) {
    if (this.disposed) return;
    this.state = state;
    this.listeners.forEach(listener => listener());
  }
  patch(patch) { if (this.state) this.update({...this.state, ...patch}); }
  connect(services) { this.services = services; }
  current(generation) { return !this.disposed && !!this.state && generation === this.generation; }
  invalidate() {
    this.generation++; this.fileGeneration++;
    this.reads.forEach(read => read.abort()); this.reads = [];
    this.fileRead?.abort();
  }
  read() { const read = new AbortController(); this.reads.push(read); return read.signal; }
  open(id, data) {
    if (!this.services || this.disposed) return;
    this.invalidate();
    const generation = this.generation;
    this.update({...data, id, generation, record: null, total: 0, note: 'Loading…', logs: [],
      logNote: 'Loading…', file: null, forgetBusy: this.mutations.has(id),
      forgetStatus: this.mutations.has(id) ? 'Earlier host-key request is still pending.' : ''});
    // Independent reads: malformed/missing records must not hide device logs.
    return Promise.all([this.loadRecord(id, generation), this.loadLogs(id, generation)]);
  }
  async loadRecord(id, generation) {
    try {
      const response = await this.services.fetch(`/api/v1/devices/${encodeURIComponent(id)}/deployment`, {signal: this.read()});
      if (!this.current(generation)) return;
      if (response.status === 404) { this.patch({note: 'Deployment records are unavailable on this server.'}); return; }
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const body = await response.json();
      if (!this.current(generation)) return;
      if (!validRecordResponse(body)) throw new Error('Invalid deployment record');
      this.patch({record: body.record, total: body.total ?? 0,
        note: body.record ? '' : 'No deployment record. Onboard or adopt this device to create one.'});
    } catch (error) {
      if (this.current(generation)) this.patch({note: 'Deployment details unavailable. Close this panel and try again.'});
    }
  }
  async loadLogs(id, generation) {
    try {
      const response = await this.services.fetch('/api/v1/deploy-logs?device_id=' + encodeURIComponent(id), {signal: this.read()});
      if (!this.current(generation)) return;
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const body = await response.json();
      if (!this.current(generation)) return;
      if (!validRows(body?.logs, 'deploylogs', {allowUndated: true}) || body.logs.some(log => log.previous_registration != null
        && typeof log.previous_registration !== 'boolean')) throw new Error('Invalid deployment logs');
      this.patch({logs: body.logs, logNote: body.logs.length ? '' : 'No deployment logs for this device yet.'});
    } catch (error) {
      if (this.current(generation)) this.patch({logNote: 'Deployment logs unavailable. Close this panel and try again.'});
    }
  }
  async openFile(file) {
    if (!this.state || !this.state.logs.some(log => log.file === file)) return;
    const generation = this.generation, fileGeneration = ++this.fileGeneration;
    this.fileRead?.abort(); this.fileRead = new AbortController();
    const current = () => this.current(generation) && this.fileGeneration === fileGeneration;
    this.patch({file: {name: file, text: `Loading ${file}…`}});
    try {
      const response = await this.services.fetch('/api/v1/deploy-logs/' + encodeURIComponent(file), {signal: this.fileRead.signal});
      if (!current()) return;
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const text = await response.text();
      if (current()) this.patch({file: {name: file, text}});
    } catch (error) {
      if (current()) this.patch({file: {name: file, text: 'Log unavailable. Select view to try again.'}});
    }
  }
  async forgetHostKey() {
    if (!this.state || this.mutations.has(this.state.id)) return;
    const {id, generation} = this.state;
    this.mutations.add(id); this.patch({forgetBusy: true, forgetStatus: ''});
    let sent = false;
    try {
      const confirmed = await this.services.confirm(`Forget the SSH host key for ${id}?\n\n`
        + 'First verify the device was re-imaged or replaced. The next connection will trust and save any key it presents.');
      if (!confirmed || !this.current(generation)) return;
      this.patch({forgetStatus: 'Forgetting…'}); sent = true;
      // Authenticated POST and CSRF are provided by the shared Console service.
      // Never abort or automatically replay a write on navigation or failure.
      const response = await this.services.post(`/api/v1/devices/${encodeURIComponent(id)}/forget-host-key`, {});
      const body = await response.json();
      if (!this.current(generation)) return;
      if (response.ok && body?.ok === true && typeof body.peer === 'string') {
        this.patch({forgetStatus: `Host key forgotten for ${body.peer || id}. The next session will re-pin its new key.`});
      } else if (!response.ok && response.status < 500 && typeof body?.error === 'string') {
        this.patch({forgetStatus: 'Forget host key failed: ' + body.error});
      } else this.patch({forgetStatus: uncertain});
    } catch {
      if (this.current(generation)) this.patch({forgetStatus: sent ? uncertain : 'Confirmation unavailable. Try again.'});
    } finally {
      this.mutations.delete(id);
      if (this.current(generation)) this.patch({forgetBusy: false});
      else if (this.state?.id === id) this.patch({forgetBusy: false,
        forgetStatus: sent ? 'Earlier host-key request ended. Check the saved host key before trying again.' : ''});
    }
  }
  close(restoreFocus = true) { this.restoreFocus = restoreFocus; this.invalidate(); this.update(null); }
  dispose() { this.invalidate(); this.disposed = true; this.listeners.clear(); }
}
