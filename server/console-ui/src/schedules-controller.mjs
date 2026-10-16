// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {checkedIds} from './assignments-model.mjs';
import {filterQuery} from './inventory-model.mjs';
import {initialForm, checkedSchedules, formDefinition, scheduleWriteResult, scheduleNextFireText, pendingScheduleText} from './schedules-model.mjs';

export class SchedulesController {
  constructor() {
    this.state = {panelOpen: false, dialog: null, form: initialForm(), rows: [], listOk: false, loading: false,
      history: new Map(), message: '', failed: false, formMessage: '', busy: false, busyId: null,
      externalBusy: false, images: [], imagesOk: false, reviewRequired: false};
    this.listeners = new Set(); this.readGeneration = 0; this.formGeneration = 0;
  }
  snapshot = () => this.state;
  subscribe = listener => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  update(patch) { this.state = {...this.state, ...patch}; this.listeners.forEach(listener => listener()); }
  connect(services) { this.services = services; }
  visible() { return this.services?.isVisible?.() !== false; }
  prerequisites(state) { this.update({externalBusy: state.bulkBusy || state.rowBusy.size > 0, images: state.images, imagesOk: state.imagesOk}); }
  beginScheduleRead() { return ++this.readGeneration; }
  acceptSchedules(result, ticket) {
    if (ticket === this.readGeneration && !this.state.busy) {
      let rows = this.state.rows, listOk = false;
      try { if (result.ok) { rows = checkedSchedules(result.body); listOk = true; } } catch { /* Keep unavailable evidence. */ }
      this.update({rows, listOk});
    }
    return {schedules: this.state.rows, schedulesOk: this.state.listOk};
  }
  scheduled(id) { return pendingScheduleText(id, this.state.rows); }
  stopRead() { this.reader?.abort(); this.reader = null; this.beginScheduleRead(); this.update({loading: false}); }
  hide() { this.close(); this.stopRead(); }
  closePanel() { this.stopRead(); this.update({panelOpen: false}); }
  togglePanel() { if (this.state.panelOpen) this.closePanel(); else { this.update({panelOpen: true}); return this.refresh(); } }
  resume() { if (this.state.panelOpen) return this.refresh(); }
  async json(path, signal) {
    try { const response = await this.services.fetch(path, {signal}); return {ok: response.ok, body: await response.json()}; }
    catch { return {ok: false}; }
  }
  async latest(id, reader, current) {
    const path = '/api/v1/schedules/' + encodeURIComponent(id) + '/occurrences?limit=1';
    const head = await this.json(path, reader.signal); if (!current()) return;
    if (!head.ok || !Number.isSafeInteger(head.body?.total) || head.body.total < 0 || head.body.offset !== 0
      || !Array.isArray(head.body.occurrences) || head.body.occurrences.length !== Math.min(1, head.body.total)) return;
    if (head.body.total === 0) return null;
    const page = await this.json(path + '&offset=' + (head.body.total - 1), reader.signal); if (!current()) return;
    const row = page.body?.occurrences?.[0];
    if (!page.ok || page.body?.offset !== head.body.total - 1 || !Number.isSafeInteger(page.body.total) || page.body.total < head.body.total
      || !Array.isArray(page.body?.occurrences) || page.body.occurrences.length !== 1
      || !row || row.schedule_id !== id || !['pending', 'running', 'interrupted', 'completed', 'missed', 'cancelled', 'stalled', 'failed'].includes(row.state)) return;
    return row;
  }
  async refresh(review = false) {
    if (!this.visible() || !this.state.panelOpen || this.state.busy) return false;
    this.reader?.abort(); const reader = this.reader = new AbortController(), ticket = this.beginScheduleRead();
    const current = () => this.reader === reader && !reader.signal.aborted && this.state.panelOpen && this.visible();
    this.update({loading: true});
    try {
      const result = await this.json('/api/v1/schedules', reader.signal);
      if (!current()) return false;
      const projection = this.acceptSchedules(result, ticket);
      this.services.publishSchedules(projection);
      if (!this.state.listOk || ticket !== this.readGeneration) return false;
      const rows = this.state.rows, history = new Map(); let cursor = 0;
      const stillCurrent = () => current() && ticket === this.readGeneration;
      const worker = async () => {
        while (cursor < Math.min(25, rows.length) && stillCurrent()) {
          const row = rows[cursor++]; history.set(row.id, await this.latest(row.id, reader, stillCurrent));
        }
      };
      await Promise.all(Array.from({length: Math.min(4, rows.length)}, worker));
      if (!stillCurrent()) return false;
      this.update({history, ...(review ? {reviewRequired: false, formMessage: 'Schedules refreshed. Review the list before submitting again.'} : {})});
      return true;
    } finally {
      if (this.reader === reader) { this.reader = null; this.update({loading: false}); }
    }
  }
  open(inventory) {
    if (this.state.busy || this.state.externalBusy) return;
    let ids; try { ids = checkedIds([...inventory.selected], 20000); if (!ids.length) return; } catch { return; }
    this.formGeneration++;
    const filterReady = inventory.readOk && inventory.matchQuery === filterQuery(inventory.filters);
    const form = {...this.state.form, scope: filterReady ? this.state.form.scope : 'selection'};
    if (!form.tz) { try { form.tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch { form.tz = 'UTC'; } }
    this.update({dialog: {ids, filters: {...inventory.filters, q: (inventory.filters.q || '').trim().toLowerCase()}, total: inventory.total, filterReady}, form, formMessage: ''});
  }
  close() { this.formGeneration++; this.update({dialog: null}); }
  field(name, value) { if (!this.state.busy && Object.hasOwn(this.state.form, name)) this.update({form: {...this.state.form, [name]: value}}); }
  claim(id = null) {
    if (this.state.busy || !this.services.claimBulk()) return false;
    this.stopRead(); this.update({busy: true, busyId: id}); return true;
  }
  async release() {
    this.beginScheduleRead(); this.update({busy: false, busyId: null}); this.services.releaseBulk();
    if (this.visible()) { await this.refresh(); try { await this.services.refreshInventory(); } catch { /* Independent read feedback. */ } }
  }
  report(message, failed) { this.update({message, failed}); this.services.report(message, failed); }
  async create() {
    const {dialog, form, images, imagesOk} = this.state, generation = this.formGeneration;
    if (!dialog || this.state.busy || this.state.reviewRequired) return;
    let definition;
    try { definition = formDefinition(form, dialog, images, imagesOk); }
    catch (error) { this.update({formMessage: error.message}); return; }
    if (!this.claim()) { this.update({formMessage: 'Another device action is still running. Wait before trying again.'}); return; }
    this.update({formMessage: 'Creating… Closing this dialog does not cancel the request.'});
    try {
      let response, body, result = 'unknown';
      try { response = await this.services.post('/api/v1/schedules', definition); body = await response.json(); result = scheduleWriteResult(response, body, definition.id); } catch { /* Unknown, never replay. */ }
      const message = result === 'saved' ? `Schedule ${definition.id} created; next run ${scheduleNextFireText(body.schedule)}.`
        : result === 'unknown' ? `Schedule ${definition.id} may have been created. Refresh schedules before trying again.`
          : `Schedule ${definition.id} not created (${typeof body?.code === 'string' ? body.code : response.status}).`;
      this.report(message, result !== 'saved');
      if (result === 'unknown') this.update({reviewRequired: true});
      if (generation === this.formGeneration) {
        if (result === 'saved') { this.close(); if (this.visible()) this.update({panelOpen: true}); }
        else this.update({formMessage: message});
      }
    } finally { await this.release(); }
  }
  async reaffirm(id) {
    const row = this.state.rows.find(row => row.id === id);
    if (!this.state.listOk || !row || row.creator_exists || !this.claim(id)) return;
    try {
      let response, body, result = 'unknown';
      try {
        response = await this.services.fetch('/api/v1/schedules/' + encodeURIComponent(row.id) + '/reaffirm', {
          method: 'POST', headers: this.services.headers({'Content-Type': 'application/json', 'If-Match': row.etag}), body: '{}'});
        body = await response.json(); result = scheduleWriteResult(response, body, row.id, row.rev);
      } catch { /* Unknown, never replay. */ }
      this.report(result === 'saved' ? `Re-affirmed ${id}; it is now owned by this account.`
        : result === 'conflict' ? `Schedule ${id} changed elsewhere; nothing was re-affirmed. Refresh and review.`
          : result === 'refused' ? `Re-affirming ${id} was refused (HTTP ${response.status}).`
            : `Re-affirming ${id} has an unknown outcome. Refresh to see whether it was applied.`, result !== 'saved');
    } finally { await this.release(); }
  }
}
