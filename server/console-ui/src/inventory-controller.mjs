// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {PAGE_SIZE, emptyFilters, filterQuery, pageQuery, checkedPage} from './inventory-model.mjs';

export class InventoryController {
  constructor({later = setTimeout, cancel = clearTimeout} = {}) {
    this.state = {ready: false, filters: emptyFilters(), filtersOpen: false, menu: '', offset: 0, total: 0,
      rows: [], now: 0, loading: false, readOk: false, error: '', selected: new Set(), matchQuery: null, matchIds: null,
      images: [], imagesOk: false, credentials: [], credentialsOk: false, policy: null, policyOk: false,
      jobs: [], schedules: [], rowBusy: new Set(), actionBusy: new Set(), bulkBusy: false, csvBusy: false, roleAvailable: false, activityLabel: 'Activity'};
    this.listeners = new Set(); this.generation = 0; this.read = null; this.selectionRead = null;
    this.later = (callback, delay) => later(callback, delay); this.cancel = timer => cancel(timer);
    this.timer = null; this.disposed = false; this.actions = new Map();
  }
  subscribe = listener => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  snapshot = () => this.state;
  update(patch) {
    if (this.disposed) return;
    this.state = {...this.state, ...patch};
    this.listeners.forEach(listener => listener());
  }
  connect(services) { this.services = services; this.update({ready: true}); }
  report(message, failed = false) { this.services?.report?.(message, failed); }
  selectedIds() { return [...this.state.selected]; }
  onAction(id, action) { this.actions.set(id, action); }
  async action(id, event) {
    const handler = this.actions.get(id);
    if (!handler || this.state.actionBusy.has(id) || (id === 'import-csv' && (this.state.csvBusy || this.state.bulkBusy || this.state.rowBusy.size))
      || (id.endsWith('-selected') && (this.state.bulkBusy || this.state.rowBusy.size))) return;
    const busy = new Set(this.state.actionBusy); busy.add(id); this.update({actionBusy: busy});
    try {
      const result = handler.call(event.currentTarget, event);
      this.update({menu: ''});
      await result;
    }
    catch { this.report('The action response is unavailable. Check the current state before trying again.', true); }
    finally { const busy = new Set(this.state.actionBusy); busy.delete(id); this.update({actionBusy: busy}); }
  }
  invalidate() {
    this.generation++; this.read?.abort(); this.read = null;
    if (this.timer !== null) this.cancel(this.timer);
    this.timer = null;
    this.cancelSelection();
    this.update({loading: false, matchQuery: null, matchIds: null});
  }
  hide() { this.invalidate(); this.update({menu: ''}); }
  dispose() { this.invalidate(); this.disposed = true; this.listeners.clear(); }
  setFilter(key, value, debounce = true) {
    if (!(key in emptyFilters())) return;
    this.invalidate();
    this.update({filters: {...this.state.filters, [key]: value}, offset: 0});
    if (debounce) this.timer = this.later(() => { this.timer = null; this.refresh(); }, 250);
    else return this.refresh();
  }
  resetFilters() {
    this.invalidate(); this.update({filters: emptyFilters(), offset: 0});
    return this.refresh();
  }
  page(direction) {
    const offset = this.state.offset + direction * PAGE_SIZE;
    if (this.state.loading || offset < 0 || offset >= this.state.total) return;
    this.update({offset}); return this.refresh();
  }
  async json(path, signal) {
    try {
      const response = await this.services.fetch(path, {signal});
      if (!response.ok) return {ok: false, status: response.status};
      return {ok: true, body: await response.json(), status: response.status};
    } catch (error) { return {ok: false, status: null, error}; }
  }
  async refresh() {
    if (!this.services || this.disposed) return;
    const mine = ++this.generation;
    this.read?.abort();
    const reader = this.read = new AbortController();
    const query = filterQuery(this.state.filters), offset = this.state.offset;
    const policyTicket = this.services.beginPolicyRead?.();
    const credentialTicket = this.services.beginCredentialRead?.();
    const imageTicket = this.services.beginImageRead?.();
    const scheduleTicket = this.services.beginScheduleRead?.();
    this.update({loading: true});
    const paths = ['/api/v1/devices?' + pageQuery(this.state.filters, offset), '/api/v1/images',
      '/api/v1/credentials', '/api/v1/peer-policy', '/api/v1/onboard/jobs', '/api/v1/schedules'];
    const [devices, images, credentials, policy, jobs, schedules] = await Promise.all(paths.map(path => this.json(path, reader.signal)));
    if (mine !== this.generation || this.disposed) return;
    const records = (result, name) => result.ok && Array.isArray(result.body?.[name])
      && result.body[name].every(row => row && typeof row.id === 'string' && row.id)
      && new Set(result.body[name].map(row => row.id)).size === result.body[name].length;
    const imagesOk = records(images, 'images'), credentialsOk = records(credentials, 'profiles');
    const policyOk = policy.ok && Number.isSafeInteger(policy.body?.revision) && policy.body.revision >= 0
      && Array.isArray(policy.body?.quarantine_assignments)
      && policy.body.quarantine_assignments.every(id => typeof id === 'string' && id);
    const patch = {loading: false, imagesOk: !!imagesOk, credentialsOk: !!credentialsOk,
      images: imagesOk ? images.body.images : this.state.images,
      credentials: credentialsOk ? credentials.body.profiles : this.state.credentials,
      policy: policyOk ? policy.body : this.state.policy, policyOk: !!policyOk,
      jobs: records(jobs, 'jobs') ? jobs.body.jobs : this.state.jobs,
      schedules: records(schedules, 'schedules') ? schedules.body.schedules : this.state.schedules};
    if (this.services.acceptCredentials) Object.assign(patch, this.services.acceptCredentials(credentials, credentialTicket));
    if (this.services.acceptImages) Object.assign(patch, this.services.acceptImages(images, imageTicket));
    if (this.services.acceptSchedules) Object.assign(patch, this.services.acceptSchedules(schedules, scheduleTicket));
    try {
      if (!devices.ok) throw new Error('Device target preview unavailable' + (devices.status ? ` (${devices.status})` : '') + '.');
      const body = checkedPage(devices.body, offset, PAGE_SIZE);
      if (!Number.isFinite(body.now) || body.now < 0) throw new Error('Device observation time is unavailable.');
      if (!body.devices.length && offset > 0 && body.total > 0) {
        this.update({offset: 0}); return this.refresh();
      }
      Object.assign(patch, {rows: body.devices, total: body.total, offset: body.offset, now: body.now,
        readOk: true, error: '', warning: (body.target_warnings || []).join(' · '), matchQuery: query,
        matchIds: offset === 0 && body.devices.length === body.total ? body.devices.map(row => row.device_id) : null});
    } catch (error) {
      Object.assign(patch, {rows: [], total: 0, offset: 0, now: 0, readOk: false, error: error.message,
        warning: 'Target preview unavailable — filters are not confirmed.', matchQuery: null, matchIds: null});
    }
    this.read = null;
    // Publish all bodies together, once. A delayed catalog/credential body from
    // a superseded read cannot overwrite the adapter's action prerequisites.
    this.update(patch);
    this.services.publish?.(this.state, policyTicket);
    this.services?.selectionChanged?.(this.selectedIds());
  }
  changeSelection(selected) {
    this.cancelSelection(); this.update({selected});
    this.services?.selectionChanged?.(this.selectedIds());
  }
  toggle(id) {
    const selected = new Set(this.state.selected);
    if (selected.has(id)) selected.delete(id); else selected.add(id);
    this.changeSelection(selected);
  }
  togglePage() {
    const selected = new Set(this.state.selected), rows = this.state.rows;
    const clear = rows.every(row => selected.has(row.device_id));
    rows.forEach(row => clear ? selected.delete(row.device_id) : selected.add(row.device_id));
    this.changeSelection(selected);
  }
  clearSelection() { this.changeSelection(new Set()); }
  removeSelection(ids) { this.changeSelection(new Set(this.selectedIds().filter(id => !ids.includes(id)))); }
  cancelSelection() {
    this.selectionRead?.abort(); this.selectionRead = null;
    if (this.state.selectionBusy) this.update({selectionBusy: false});
  }
  async selectAll() {
    const base = filterQuery(this.state.filters);
    if (this.state.selectionBusy || this.state.bulkBusy || this.state.matchQuery !== base || this.state.total <= 0) return;
    const reader = this.selectionRead = new AbortController();
    const current = () => this.selectionRead === reader && filterQuery(this.state.filters) === base && !this.disposed;
    this.update({selectionBusy: true});
    try {
      let offset = 0, total = null, revision = null;
      const ids = new Set();
      while (total === null || offset < total) {
        const result = await this.json('/api/v1/devices?' + pageQuery(this.state.filters, offset, 1000), reader.signal);
        if (!current()) return;
        if (!result.ok) throw new Error('Unavailable');
        const body = checkedPage(result.body, offset, 1000);
        if (total !== null && (body.total !== total || body.revision !== revision)) throw new Error('Changed device list');
        total = body.total; revision = body.revision;
        if (!body.devices.length && offset < total) throw new Error('Incomplete device list');
        for (const row of body.devices) {
          if (ids.has(row.device_id)) throw new Error('Duplicate device');
          ids.add(row.device_id);
        }
        offset += body.devices.length;
      }
      if (!current()) return;
      this.update({selected: new Set([...this.state.selected, ...ids]), matchIds: [...ids]});
      this.services.selectionChanged?.(this.selectedIds());
      this.report(`Selected ${ids.size} matching device${ids.size === 1 ? '' : 's'}. Previous selections are kept.`);
    } catch {
      if (current()) this.report('Could not select all matching devices. Your selection is unchanged. Try again.', true);
    } finally {
      if (this.selectionRead === reader) { this.selectionRead = null; this.update({selectionBusy: false}); }
    }
  }
  claimRow(id) {
    if (this.disposed || this.state.rowBusy.has(id) || this.state.bulkBusy) return false;
    this.cancelSelection();
    const rowBusy = new Set(this.state.rowBusy); rowBusy.add(id); this.update({rowBusy});
    return true;
  }
  releaseRow(id) {
    const rowBusy = new Set(this.state.rowBusy); rowBusy.delete(id); this.update({rowBusy});
  }
  async edit(id, kind, value) {
    if (this.state.rowBusy.has(id) || this.state.bulkBusy) return;
    if (kind === 'credential' && !this.state.credentialsOk) return;
    if (!['credential', 'platform', 'quarantine'].includes(kind)) return;
    const policy = this.state.policy;
    if (kind === 'quarantine') {
      if (!this.state.policyOk || !Number.isSafeInteger(policy?.revision)) return;
      const action = value ? 'Quarantine' : 'Release';
      if (!this.services.confirm(`${action} ${id}?\n\nChanges peer and server access for all images. Existing device-to-device transfers may continue. Device software is unchanged.`)) return;
    }
    if (!this.claimRow(id)) return;
    const label = kind === 'credential' ? 'Credential' : kind === 'platform' ? 'Agent install' : (value ? 'Quarantine' : 'Release');
    try {
      const response = kind === 'quarantine' ? await this.services.fetch('/api/v1/peer-policy/quarantine/' + encodeURIComponent(id), {
        method: 'PUT', headers: this.services.headers({'Content-Type': 'application/json', 'If-Match': `"iris-peer-policy-${policy.revision}"`}),
        body: JSON.stringify({quarantined: value, if_revision: policy.revision})})
        : await this.services.post('/api/v1/devices/' + encodeURIComponent(id) + '/' + kind,
          kind === 'credential' ? {credential_profile_id: value} : {platform: value});
      const body = await response.json();
      if (!response.ok) this.report(`${label} update refused for ${id}: ${body?.error || body?.title || response.status}.`, true);
      else if (body?.ok !== true || (kind === 'quarantine' && (body.quarantined !== value || !Number.isSafeInteger(body.revision)))) {
        this.report(`${label} update outcome is unknown for ${id}. Refresh before trying again.`, true);
      } else this.report(`${label}${kind === 'quarantine' ? ' intent saved' : ' updated'} for ${id}.`);
    } catch { this.report(`${label} update outcome is unknown for ${id}. Refresh before trying again.`, true); }
    finally {
      // Fresh read supersedes any earlier body, including a poll started before
      // the write. Never replay the mutation when its result was lost.
      this.releaseRow(id);
      if (this.services.isVisible?.() !== false) await this.refresh();
    }
  }
}
