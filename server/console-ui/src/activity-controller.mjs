// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {active, actionLabel, activityRows, appendLines, MAX_LOGS, submissionMessage, validListing} from './activity-model.mjs';

class UnknownOutcome extends Error {
  constructor() { super('Request outcome is unknown. Refresh Activity before trying again.'); }
}

export class ActivityController {
  constructor({setTimer = (fn, delay) => setTimeout(fn, delay), clearTimer = id => clearTimeout(id),
    queuePaint = fn => typeof requestAnimationFrame === 'function' ? requestAnimationFrame(fn) : queueMicrotask(fn)} = {}) {
    this.state = {open: false, generation: 0, jobs: [], scope: null, now: null, loaded: false,
      busy: false, starting: false, error: '', message: '', logs: [], selected: null, selection: 0, busyJobs: []};
    this.listeners = new Set(); this.entries = new Map(); this.mutations = new Set();
    this.setTimer = setTimer; this.clearTimer = clearTimer; this.queuePaint = queuePaint;
    this.readGeneration = 0; this.viewGeneration = 0; this.visible = false; this.disposed = false;
  }
  subscribe = listener => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  snapshot = () => this.state;
  patch(patch) {
    if (this.disposed) return;
    this.state = {...this.state, ...patch};
    this.listeners.forEach(listener => listener());
  }
  connect(services) { this.services = services; }
  report() {
    this.services?.reportCount?.(activityRows(this.state).filter(active).length, this.state.error);
  }
  stopTimer() { if (this.timer != null) this.clearTimer(this.timer); this.timer = null; }
  invalidateRead() { this.readGeneration++; this.read?.abort(); this.stopTimer(); this.patch({busy: false}); }
  schedule() {
    this.stopTimer();
    if (!this.visible || this.disposed || this.sessionLost || this.state.starting || this.state.busy) return;
    if (!this.state.error && !activityRows(this.state).some(active)) return;
    this.timer = this.setTimer(() => { this.timer = null; this.refresh(true); }, 2000);
  }
  async setVisible(visible) {
    if (visible === this.visible || this.disposed) return;
    this.visible = visible;
    if (!visible) {
      this.invalidateRead();
      for (const entry of this.entries.values()) {
        if (!entry.stream) continue;
        this.stopStream(entry); entry.paused = true;
        appendLines(entry, 'Log paused while this view was hidden. Reopen it to follow the job.');
      }
      this.publishLogs();
    } else if (!this.state.starting) return this.refresh();
  }
  async open() {
    if (!this.services || !this.visible || this.disposed) return;
    this.services.show?.();
    if (!this.state.open) this.viewGeneration++;
    this.patch({open: true, generation: this.viewGeneration,
      ...(this.state.starting ? {} : {scope: null, message: ''})});
    if (!this.state.starting) return this.refresh();
  }
  close(restoreFocus = true) {
    if (!this.state.open) return;
    this.restoreFocus = restoreFocus; this.viewGeneration++;
    this.invalidateRead(); this.clearStreams();
    this.patch({open: false, logs: [], selected: null});
    this.schedule();
  }
  async refresh(background = false) {
    if (!this.services || !this.visible || this.disposed || this.sessionLost || this.state.starting
      || (background && this.state.busy)) return;
    this.invalidateRead(); const generation = this.readGeneration;
    const controller = this.read = new AbortController();
    const current = () => !this.disposed && this.visible && generation === this.readGeneration;
    const hadActive = activityRows(this.state).some(active);
    this.patch({busy: true});
    try {
      const response = await this.services.fetch('/api/v1/onboard/jobs', {signal: controller.signal}, background);
      if (!current()) return;
      if (response.status === 401) {
        this.sessionLost = true; this.clearStreams();
        this.patch({error: 'Session expired. Sign in again.', logs: [], selected: null}); return;
      }
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const body = await response.json();
      if (!current()) return;
      if (!validListing(body)) throw new Error('Invalid job listing');
      this.patch({jobs: body.jobs, now: body.now ?? null, loaded: true, error: ''});
      for (const entry of this.entries.values()) {
        const job = body.jobs.find(job => job.id === entry.job.id);
        if (job) entry.job = job;
      }
      this.publishLogs();
      if (hadActive && !activityRows(this.state).some(active)) this.refreshDevices();
    } catch {
      if (current()) this.patch({error: 'Activity unavailable. Showing the last known jobs; retrying.'});
    } finally {
      if (current()) { this.patch({busy: false}); this.report(); this.schedule(); }
    }
  }
  refreshDevices() { Promise.resolve().then(() => this.services?.refreshDevices?.()).catch(() => {}); }
  stopStream(entry) { entry.stream?.close(); entry.stream = null; }
  clearStreams() { this.entries.forEach(entry => this.stopStream(entry)); this.entries.clear(); }
  publishLogs() {
    this.patch({logs: [...this.entries.values()].map(entry => ({id: entry.job.id, job: entry.job,
      text: entry.lines.join('\n'), truncated: !!entry.truncated, paused: !!entry.paused, terminal: !!entry.terminal}))});
  }
  paint() {
    if (this.paintPending) return;
    this.paintPending = true;
    this.queuePaint(() => { this.paintPending = false; if (!this.disposed) this.publishLogs(); });
  }
  openLog(id) {
    if (!this.state.open || !this.visible || this.disposed) return;
    const job = activityRows(this.state).find(job => job.id === id);
    if (!job) return;
    const old = this.entries.get(id);
    this.patch({selected: id, selection: this.state.selection + 1});
    if (old?.stream) return;
    if (old) { this.stopStream(old); this.entries.delete(id); }
    while (this.entries.size >= MAX_LOGS) {
      const first = this.entries.keys().next().value;
      this.stopStream(this.entries.get(first)); this.entries.delete(first);
    }
    const entry = {job, lines: [], terminal: !active(job), paused: false};
    this.entries.set(id, entry);
    if (job.state === 'queued') appendLines(entry, 'Queued: waiting for an available slot.');
    try {
      const stream = entry.stream = this.services.eventSource('/api/v1/onboard/jobs/' + encodeURIComponent(id) + '/stream');
      const current = () => !this.disposed && this.state.open && this.visible
        && this.entries.get(id) === entry && entry.stream === stream;
      stream.onmessage = event => {
        if (!current()) return;
        if (entry.job.state === 'queued') entry.job = {...entry.job, state: 'running'};
        appendLines(entry, event.data); this.paint();
      };
      stream.addEventListener('end', event => {
        if (!current()) return;
        const outcomes = {done: 'completed', error: 'failed', cancelled: 'cancelled'};
        if (Object.hasOwn(outcomes, event.data)) {
          const line = `${actionLabel(entry.job.action)} ${outcomes[event.data]}.`;
          if (entry.lines.at(-1) !== line) appendLines(entry, line);
          entry.terminal = true; entry.job = {...entry.job, state: event.data};
        } else {
          entry.paused = true;
          appendLines(entry, event.data === 'idle' ? 'Log paused. Reopen it to follow the job.'
            : 'Log ended with an unknown result. Refresh Activity.');
        }
        this.stopStream(entry); this.publishLogs(); this.refreshDevices(); this.refresh(true);
      });
      stream.onerror = () => {
        if (!current()) return;
        appendLines(entry, 'Log connection closed. Reopen it to follow the job.');
        entry.paused = true; this.stopStream(entry); this.publishLogs();
      };
    } catch {
      entry.paused = true; appendLines(entry, 'Log connection unavailable. Reopen it to try again.');
    }
    this.publishLogs();
  }
  async post(url, payload, validate) {
    let response, body;
    try { response = await this.services.post(url, payload); body = await response.json(); }
    catch { throw new UnknownOutcome(); }
    if (!response.ok) {
      if (response.status >= 400 && response.status < 500 && typeof body?.error === 'string') throw new Error(body.error);
      throw new UnknownOutcome();
    }
    if (!validate(body)) throw new UnknownOutcome();
    return body;
  }
  lock(ids) {
    if (ids.some(id => this.mutations.has(id))) return false;
    ids.forEach(id => this.mutations.add(id)); this.patch({busyJobs: [...this.mutations]}); return true;
  }
  unlock(ids) { ids.forEach(id => this.mutations.delete(id)); this.patch({busyJobs: [...this.mutations]}); }
  async cancelQueued() {
    const ids = activityRows(this.state).filter(job => job.state === 'queued').map(job => job.id);
    if (!this.state.open || !ids.length || !this.lock(ids)) return;
    const generation = this.viewGeneration;
    const current = () => !this.disposed && this.state.open && generation === this.viewGeneration;
    try {
      if (!await this.services.confirm(`Cancel ${ids.length} queued job(s) in this list? Running jobs continue.`) || !current()) return;
      const body = await this.post('/api/v1/onboard/cancel-queued', {job_ids: ids}, data => Number.isInteger(data?.cancelled)
        && data.cancelled >= 0 && data.cancelled <= ids.length);
      if (current()) this.patch({message: `Cancelled ${body.cancelled} queued job(s).`});
      this.refresh();
    } catch (error) { if (current()) this.patch({message: error.message}); }
    finally { this.unlock(ids); }
  }
  async abort(id) {
    const entry = this.entries.get(id);
    if (!this.state.open || !entry || entry.terminal || !active(entry.job) || !this.lock([id])) return;
    const generation = this.viewGeneration;
    const current = () => !this.disposed && this.state.open && generation === this.viewGeneration && this.entries.get(id) === entry;
    try {
      if (!await this.services.confirm(`Abort ${entry.job.action || 'job'} for ${entry.job.device_id}?\n\n`
        + 'A running job may leave the device partially configured. Onboard again or undeploy to clean up.') || !current()) return;
      if (entry.job.state === 'queued') {
        const body = await this.post('/api/v1/onboard/cancel-queued', {job_ids: [id]}, data => data?.cancelled === 0 || data?.cancelled === 1);
        if (!current()) return;
        if (body.cancelled === 1) { appendLines(entry, '[cancelled while queued]'); this.publishLogs(); this.refresh(); return; }
        // Only an explicit zero permits a second, different action: it won a
        // running slot before cancellation. An unknown result never does.
      }
      if (!current()) return;
      await this.post('/api/v1/onboard/jobs/' + encodeURIComponent(id) + '/abort', {}, data => data?.aborted === true);
      if (current()) { appendLines(entry, '[abort requested]'); this.publishLogs(); }
      this.refresh();
    } catch (error) {
      if (current()) { appendLines(entry, error.message); this.publishLogs(); }
    } finally { this.unlock([id]); }
  }
  async start(action, ids, options = {}) {
    if (!this.visible || this.disposed || this.startLock || !['onboard', 'undeploy'].includes(action)) return;
    ids = [...new Set(ids)];
    if (!ids.length || ids.some(id => typeof id !== 'string' || !id)) return;
    this.startLock = true; const generation = this.viewGeneration;
    try {
      if (action === 'undeploy' && !await this.services.confirm(`Undeploy ${ids.length} device(s)?` + (options.force
        ? '\n\nForce cleanup skips record and device identity checks. Removes IRIS agent files and services, plus IRIS-marked VirtualPortGroups and related NAT settings on routers. Keeps unrelated networking. Retires the old record on success.'
        : '\n\nRemoves the IRIS agent and resources listed as IRIS-owned.')
        + '\n\nKeeps staged images in device storage. Does not stop running jobs.')) return;
      if (!this.visible || this.disposed || generation !== this.viewGeneration) return;
      this.invalidateRead(); this.clearStreams(); this.services.show?.(); this.viewGeneration++;
      this.patch({open: true, generation: this.viewGeneration, starting: true, scope: [],
        logs: [], selected: null, message: 'Starting…', error: ''});
      const accepted = [], refused = [], unknown = [];
      await Promise.all(ids.map(async id => {
        try {
          const body = await this.post(`/api/v1/devices/${encodeURIComponent(id)}/${action}`, options,
            data => typeof data?.job_id === 'string' && !!data.job_id);
          accepted.push(body.job_id);
        } catch (error) {
          if (error instanceof UnknownOutcome) unknown.push(id);
          else refused.push(`${id}: ${error.message}`);
        }
      }));
      if (this.disposed) return;
      const message = submissionMessage(action, accepted.length, refused, unknown);
      this.patch({scope: accepted, starting: false, message});
      this.services.outcome?.(message, !!(refused.length || unknown.length));
      await this.refresh();
    } finally { this.startLock = false; this.patch({starting: false}); this.schedule(); }
  }
  dispose() {
    this.invalidateRead(); this.clearStreams(); this.disposed = true; this.listeners.clear();
  }
}
