// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {checkedIds} from './assignments-model.mjs';
import {CSV_LIMIT, initialOptions, jobOptions, csvProblem, actionConfirmation, deviceActionResult, downloads} from './inventory-actions-model.mjs';

export class InventoryActionsController {
  constructor() {
    this.state = {dialog: null, options: initialOptions(), busy: false, externalBusy: false,
      csvBusy: false, csvMessage: '', csvFailed: false, downloadMessage: '', downloadFailed: false};
    this.listeners = new Set(); this.downloads = new Map(); this.downloadGeneration = 0;
  }
  snapshot = () => this.state;
  subscribe = listener => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  update(patch) { this.state = {...this.state, ...patch}; this.listeners.forEach(listener => listener()); }
  connect(services) { this.services = services; }
  visible() { return this.services?.isVisible?.() !== false; }
  report(message, failed = false) { this.services?.report?.(message, failed); }
  prerequisites(state) { this.update({externalBusy: state.bulkBusy || state.rowBusy.size > 0}); }
  targets(ids) {
    try { ids = checkedIds(ids); if (!ids.length) throw new Error('Empty'); return ids; }
    catch { this.report('Select valid devices before starting this action.', true); return null; }
  }
  open(action, ids) {
    if (!['onboard', 'undeploy'].includes(action) || this.state.busy || this.state.externalBusy) return;
    ids = this.targets(ids); if (ids) this.update({dialog: {action, ids}});
  }
  close() { this.update({dialog: null}); }
  option(name, checked) {
    if (!this.state.busy && Object.hasOwn(this.state.options, name)) this.update({options: {...this.state.options, [name]: !!checked}});
  }
  hide() {
    this.close();
    if (this.downloads.size) { this.downloadGeneration++; this.update({downloadMessage: 'Download cancelled.', downloadFailed: false}); }
    for (const reader of this.downloads.values()) reader.abort();
    this.downloads.clear();
  }
  claim() {
    if (this.state.busy || !this.services.claimBulk()) { this.report('Another device action is still running. Wait before trying again.', true); return false; }
    this.update({busy: true}); return true;
  }
  release() { this.update({busy: false}); this.services.releaseBulk(); }
  async refresh() { if (this.visible()) { try { await this.services.refreshInventory(); } catch { /* independent read status */ } } }
  async start() {
    const dialog = this.state.dialog; if (!dialog) return;
    const {action, ids} = dialog, options = jobOptions(action, this.state.options);
    if (!this.claim()) return;
    this.close();
    try { await this.services.startJobs(action, ids.slice(), options); }
    catch { this.report('Job submission outcome is unknown. Check Activity before trying again.', true); }
    finally { this.release(); }
  }
  async act(action, targets) {
    if (!['adopt', 'delete'].includes(action) || this.state.busy || this.state.externalBusy) return;
    const ids = this.targets(targets); if (!ids || !this.services.confirm(actionConfirmation(action, ids)) || !this.claim()) return;
    let cursor = 0; const results = new Map();
    this.report((action === 'delete' ? 'Deleting' : 'Adopting') + ` ${ids.length} reviewed device(s)…`);
    try {
      const worker = async () => {
        while (cursor < ids.length) {
          const id = ids[cursor++]; let result;
          try {
            const path = '/api/v1/devices/' + encodeURIComponent(id);
            const response = action === 'delete' ? await this.services.fetch(path, {method: 'DELETE', headers: this.services.headers()})
              : await this.services.post(path + '/adopt', {acknowledge_adopt: true});
            result = deviceActionResult(action, response, await response.json().catch(() => null));
          } catch { result = {kind: 'unknown', reason: 'Response unavailable; review before trying again'}; }
          results.set(id, result);
        }
      };
      await Promise.all(Array.from({length: Math.min(4, ids.length)}, worker));
      const done = ids.filter(id => results.get(id)?.kind === 'done');
      if (action === 'delete') this.services.removeSelection(done);
      const notes = ids.filter(id => results.get(id)?.kind !== 'done' || results.get(id)?.reason)
        .map(id => `${id}: ${results.get(id)?.kind || 'unknown'} (${results.get(id)?.reason || 'Response unavailable'})`);
      this.report(`${action === 'delete' ? 'Delete' : 'Adopt'} completed for ${done.length}/${ids.length} device(s).`
        + (notes.length ? ' ' + notes.join('; ') : ''), done.length !== ids.length);
    } finally { this.release(); await this.refresh(); }
  }
  async importFile(file) {
    if (!file || this.state.csvBusy || this.state.busy) return;
    const say = (csvMessage, csvFailed = false) => this.update({csvMessage, csvFailed});
    if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > CSV_LIMIT) { say('Import failed: CSV exceeds 8 MiB or has an invalid size. No request sent.', true); return; }
    if (!this.claim()) return;
    this.update({csvBusy: true}); this.services.csvBusy(true); say('Reading CSV…');
    try {
      let csv;
      try { csv = await file.text(); if (typeof csv !== 'string') throw new Error('Invalid text'); }
      catch { say('Cannot read this CSV file. No import request sent.', true); return; }
      if (new TextEncoder().encode(csv).length > CSV_LIMIT) { say('Import failed: CSV exceeds 8 MiB. No request sent.', true); return; }
      say('Importing CSV…'); let response, body;
      try {
        response = await this.services.fetch('/api/v1/devices/import-csv', {method: 'POST', headers: this.services.headers({'Content-Type': 'text/csv'}), body: csv});
        body = await response.json().catch(() => null);
      } catch { say('Import response unavailable. The import may have completed; refresh inventory before retrying.', true); return; }
      if (!response.ok) {
        say('Import failed: ' + csvProblem(body, response.status) + (response.status >= 500 ? '. Refresh inventory before retrying; the outcome may be uncertain.' : ''), true); return;
      }
      if (!Number.isSafeInteger(body?.imported) || body.imported < 0) { say('Import response could not be confirmed. Refresh inventory before retrying.', true); return; }
      say(`Imported ${body.imported} device(s).`); await this.refresh();
    } finally { this.update({csvBusy: false}); this.services.csvBusy(false); this.release(); }
  }
  async download(path, filename) {
    if (!Object.hasOwn(downloads, path) || downloads[path] !== filename || this.downloads.has(path)) return;
    const reader = new AbortController(); this.downloads.set(path, reader);
    const current = () => this.downloads.get(path) === reader;
    const generation = ++this.downloadGeneration;
    const say = (downloadMessage, downloadFailed = false) => {
      if (current() && generation === this.downloadGeneration) this.update({downloadMessage, downloadFailed});
    };
    this.update({downloadMessage: `Downloading ${filename}…`, downloadFailed: false});
    try {
      const response = await this.services.fetch(path, {signal: reader.signal});
      if (!current()) return;
      if (!response.ok) throw new Error(`Download failed (HTTP ${response.status}).`);
      if (response.headers?.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'text/csv') throw new Error('Download response is not CSV. Try again after checking the server.');
      const text = await response.text(); if (!current()) return;
      this.services.saveCsv(text, filename);
      say(`Downloaded ${filename}.`);
    } catch (error) { say(error.message?.startsWith('Download') ? error.message : 'Download unavailable. Try again.', true); }
    finally { if (current()) this.downloads.delete(path); }
  }
}
