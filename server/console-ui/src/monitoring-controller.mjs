// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {bounds, clampSelection, deploymentRows, queries, ranges, validRows} from './monitoring-model.mjs';

const pane = range => ({range, selection: null, category: '', query: '', action: '', result: '', page: 0,
  rows: [], buckets: [], domain: null, bucketSeconds: 0, loaded: false, error: '', busy: false,
  olderPages: 0, olderBusy: false, exhausted: false, interacting: false, nextCursor: null, queryNow: null});

const validCursor = value => value === null || (typeof value === 'string' && value.length > 0 && value.length <= 256);

export class MonitoringController {
  constructor({now = () => Date.now() / 1000} = {}) {
    this.now = now;
    this.state = {ready: false, active: 'audit', audit: pane('24h'), deploylogs: pane('7d'), detail: null};
    this.listeners = new Set();
    this.generations = {audit: 0, deploylogs: 0, detail: 0};
    this.reads = {};
    this.disposed = false;
  }
  subscribe = listener => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  snapshot = () => this.state;
  update(patch) {
    if (this.disposed) return;
    this.state = {...this.state, ...patch};
    this.listeners.forEach(listener => listener());
  }
  patch(kind, patch) { this.update({[kind]: {...this.state[kind], ...patch}}); }
  connect(services) { this.services = services; this.update({ready: true}); }
  invalidate(kind) { this.generations[kind]++; this.reads[kind]?.abort(); }
  current(kind, generation) { return !this.disposed && this.generations[kind] === generation; }
  select(kind) {
    const active = kind === 'deploylogs' ? kind : 'audit';
    if (active !== this.state.active) {
      this.invalidate(this.state.active);
      this.patch(this.state.active, {busy: false, olderBusy: false, interacting: false});
      this.closeDetail();
      this.update({active});
    }
  }
  hide() {
    for (const kind of ['audit', 'deploylogs']) {
      this.invalidate(kind);
      this.patch(kind, {busy: false, olderBusy: false, interacting: false});
    }
    this.closeDetail();
  }
  setRange(kind, range) {
    if (!Object.hasOwn(ranges, range)) return;
    this.resetQuery(kind, {range, selection: null});
    return this.refresh(kind);
  }
  setCategory(category) {
    this.resetQuery('audit', {category});
    return this.refresh('audit');
  }
  resetQuery(kind, patch) {
    this.invalidate(kind);
    this.patch(kind, {...patch, page: 0, rows: [], buckets: [], domain: null, loaded: false,
      error: '', olderPages: 0, olderBusy: false, exhausted: false, interacting: false, nextCursor: null, queryNow: null});
  }
  setSelection(kind, selection) {
    this.resetQuery(kind, {selection: selection
      ? clampSelection(selection.start, selection.end, bounds(this.state[kind].range, this.now())) : null});
    return this.refresh(kind);
  }
  setInteracting(kind, value) {
    if (value) this.invalidate(kind);
    this.patch(kind, {interacting: value, busy: false, olderBusy: false});
  }
  filter(patch) { this.patch('deploylogs', {...patch, page: 0}); }
  page(delta) {
    const {page, pages} = deploymentRows(this.state.deploylogs);
    this.patch('deploylogs', {page: Math.max(0, Math.min(page + delta, pages - 1))});
  }
  async json(url, signal) {
    const response = await this.services.fetch(url, {signal});
    if (!response.ok) throw Object.assign(new Error('HTTP ' + response.status), {status: response.status});
    return response.json();
  }
  async refresh(kind = this.state.active, fromPoll = false) {
    const state = this.state[kind];
    if (!this.state.ready || state.interacting || (fromPoll && state.busy)) return;
    const retainPages = kind === 'audit' && fromPoll && (state.olderPages > 0 || state.olderBusy);
    // Older-page requests own the audit query until they finish; polling
    // must neither abort them nor silently replace the expanded table.
    if (state.olderBusy && fromPoll) return;
    this.invalidate(kind);
    const generation = this.generations[kind], controller = this.reads[kind] = new AbortController();
    const now = Math.floor(this.now()), urls = queries(kind, state, now);
    this.patch(kind, {busy: true, olderBusy: false});
    try {
      const [histogram, listing] = await Promise.all([
        this.json(urls.histogram, controller.signal),
        retainPages ? null : this.json(urls.list, controller.signal),
      ]);
      if (!this.current(kind, generation)) return;
      const rows = listing?.[kind === 'audit' ? 'events' : 'logs'];
      if ((!retainPages && (!validRows(rows, kind) || (kind === 'audit' && !validCursor(listing.next_cursor))))
        || !histogram || !Array.isArray(histogram.buckets)
        || histogram.buckets.length > 200 || histogram.buckets.some(bucket => !bucket
          || !Number.isFinite(bucket.start) || !Number.isFinite(bucket.count) || bucket.count < 0)
        || (histogram.now != null && !Number.isFinite(histogram.now))) throw new Error('Invalid monitoring response');
      const domain = state.selection
        ? {since: state.selection.start, until: state.selection.end}
        : bounds(state.range, histogram.now ?? now);
      const bucketSeconds = histogram.bucket_seconds ?? ((domain.until - domain.since) / (histogram.buckets.length || 1));
      if (!Number.isFinite(bucketSeconds) || bucketSeconds <= 0) throw new Error('Invalid histogram interval');
      this.patch(kind, {buckets: histogram.buckets, domain, bucketSeconds, loaded: true, busy: false, error: '',
        ...(retainPages ? {} : {rows, olderPages: 0, queryNow: now, nextCursor: listing.next_cursor ?? null,
          exhausted: !rows.length || (kind === 'audit' && listing.next_cursor === null)})});
    } catch (error) {
      if (!this.current(kind, generation) || error?.name === 'AbortError') return;
      this.patch(kind, {busy: false, error: `${kind === 'audit' ? 'Audit trail' : 'Deployment logs'} could not be refreshed. Try Refresh.`});
    }
  }
  async older() {
    const state = this.state.audit;
    if (!state.loaded || state.olderBusy || state.busy || state.exhausted || !state.rows.length || !state.nextCursor) return;
    this.invalidate('audit');
    const generation = this.generations.audit, controller = this.reads.audit = new AbortController();
    this.patch('audit', {olderBusy: true});
    try {
      const data = await this.json(queries('audit', state, state.queryNow, state.nextCursor).list, controller.signal);
      if (!this.current('audit', generation)) return;
      if (!validRows(data?.events, 'audit') || !validCursor(data.next_cursor)
        || data.next_cursor === state.nextCursor) throw new Error('Invalid older page');
      this.patch('audit', {rows: [...state.rows, ...data.events], olderPages: state.olderPages + 1,
        olderBusy: false, nextCursor: data.next_cursor, exhausted: !data.events.length || data.next_cursor === null, error: ''});
    } catch (error) {
      if (!this.current('audit', generation) || error?.name === 'AbortError') return;
      this.patch('audit', {olderBusy: false, ...(error.status === 409 ? {exhausted: true} : {}),
        error: error.status === 409 ? 'The audit log changed. Select Refresh to load events again.'
          : 'Older audit events could not be loaded. Try Load older.'});
    }
  }
  async openDetail(file) {
    this.invalidate('detail');
    const generation = this.generations.detail, controller = this.reads.detail = new AbortController();
    this.update({detail: {file, generation, text: `Loading ${file}…`}});
    try {
      const response = await this.services.fetch('/api/v1/deploy-logs/' + encodeURIComponent(file), {signal: controller.signal});
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const text = await response.text();
      if (this.current('detail', generation)) this.update({detail: {file, generation, text}});
    } catch (error) {
      if (this.current('detail', generation) && error?.name !== 'AbortError') {
        this.update({detail: {file, generation, text: 'Log unavailable. Close this panel and try again.'}});
      }
    }
  }
  closeDetail() { this.invalidate('detail'); this.update({detail: null}); }
  dispose() {
    this.disposed = true;
    Object.values(this.reads).forEach(controller => controller.abort());
    this.listeners.clear();
  }
}
