// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {formatSize, publishedJobText} from './image-model.mjs';

export class ImagesController {
  constructor({later = setTimeout, cancel = clearTimeout} = {}) {
    this.state = {ready: false, images: [], catalogLoaded: false, attentionOnly: false, importable: [], skipped: [],
      importAvailable: false, importing: [], uploads: [], deleting: [], details: null, status: '', catalogError: ''};
    this.listeners = new Set();
    this.timers = new Set();
    // Browser timers require Window (or no receiver), not this controller.
    this.later = (callback, delay) => later(callback, delay);
    this.cancel = timer => cancel(timer);
    this.generations = {images: 0, importable: 0};
    this.reads = {};
    this.serial = 0;
    this.disposed = false;
  }
  subscribe = listener => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  snapshot = () => this.state;
  update(patch) {
    if (this.disposed) return;
    this.state = {...this.state, ...patch};
    this.listeners.forEach(listener => listener());
  }
  connect(services) { this.services = services; this.update({ready: true}); }
  setAttention(value) { this.update({attentionOnly: !!value}); }
  schedule(callback, delay) {
    if (this.disposed) return;
    const timer = this.later(() => { this.timers.delete(timer); if (!this.disposed) callback(); }, delay);
    this.timers.add(timer);
  }
  dispose() {
    this.disposed = true;
    Object.values(this.reads).forEach(controller => controller.abort());
    this.timers.forEach(timer => this.cancel(timer));
    this.timers.clear();
    this.listeners.clear();
  }
  async refresh(kind = 'images') {
    const mine = ++this.generations[kind];
    this.reads[kind]?.abort();
    const controller = this.reads[kind] = new AbortController();
    try {
      const response = await this.services.fetch(`/api/v1/images${kind === 'images' ? '' : '/importable'}`, {signal: controller.signal});
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const data = await response.json();
      if (mine !== this.generations[kind] || this.disposed) return;
      if (kind === 'images') {
        if (!Array.isArray(data.images) || data.images.some(row => !row || typeof row.id !== 'string'
          || ['filename', 'sha256'].some(key => row[key] != null && typeof row[key] !== 'string'))) throw new Error('Invalid catalog');
        this.update({images: [...data.images].sort((a, b) => (b.published_at || 0) - (a.published_at || 0)), catalogLoaded: true, catalogError: ''});
      } else {
        if (!Array.isArray(data.importable) || !Array.isArray(data.skipped || [])
          || [...data.importable, ...(data.skipped || [])].some(row => !row || typeof row.path !== 'string'
            || ['filename', 'reason'].some(key => row[key] != null && typeof row[key] !== 'string'))) throw new Error('Invalid import list');
        this.update({importable: data.importable, skipped: data.skipped || [], importAvailable: true});
      }
    } catch (error) {
      if (mine !== this.generations[kind] || error?.name === 'AbortError' || this.disposed) return;
      if (kind === 'importable') this.update({importAvailable: false});
      else this.update({catalogError: 'Catalog could not be refreshed. Retrying automatically.'});
      // The shared transport announces connectivity failures. Keep the last
      // known catalog without inventing an empty or healthy result.
    }
  }
  refreshLists() { return Promise.all([this.refresh(), this.refresh('importable')]); }
  async remove(id) {
    if (this.state.deleting.includes(id)) return;
    if (!this.services.confirm(`Delete image ${id}? This removes it from the catalog and stops seeding.`)) return;
    this.update({deleting: [...this.state.deleting, id]});
    try {
      const response = await this.services.fetch('/api/v1/images/' + encodeURIComponent(id), {method: 'DELETE', headers: this.services.headers()});
      if (response.status === 409) {
        const body = await response.json();
        this.services.alert(`Cannot delete: assigned to ${(body.assigned || []).join(', ')}. Reassign those devices first.`);
      } else if (!response.ok) {
        this.update({status: `Delete failed (${response.status}). Refresh the catalog before trying again.`});
      } else await this.refreshLists();
    } catch { this.update({status: 'Delete response unavailable. Refresh the catalog before trying again.'}); }
    finally { this.update({deleting: this.state.deleting.filter(value => value !== id)}); }
  }
  openDetails(id) {
    const image = this.state.images.find(item => item.id === id);
    if (image) this.update({details: {image, generation: ++this.serial, busy: false, override: false, confirmText: '', error: ''}});
  }
  closeDetails() { this.update({details: null}); }
  editConfirmation(confirmText) {
    if (this.state.details) this.update({details: {...this.state.details, confirmText}});
  }
  async release(override) {
    const details = this.state.details;
    if (!details || details.busy || !details.image.quarantined) return;
    if (override && (!details.override || details.confirmText !== details.image.filename)) return;
    const same = () => this.state.details?.generation === details.generation;
    const updateDetails = patch => { if (same()) this.update({details: {...this.state.details, ...patch}}); };
    updateDetails({busy: true, error: ''});
    try {
      const response = await this.services.post('/api/v1/images/' + encodeURIComponent(details.image.id) + '/release-quarantine',
        {override: !!override, confirm_text: override ? details.confirmText : ''});
      const body = await response.json().catch(() => ({}));
      if (response.ok) {
        await Promise.all([this.refresh(), this.services.refreshDevices().catch(() => {})]);
        // Refresh first: a filtered row may disappear. Focus restoration then
        // uses the filter control instead of a now-detached details button.
        if (same()) this.closeDetails();
      } else if (response.status === 409 && body?.error === 'quarantine_still_mismatched') {
        updateDetails({override: true});
      } else updateDetails({error: typeof body?.error === 'string' && body.error || `Release failed (${response.status}).`});
    } catch { updateDetails({error: 'Release response unavailable. Refresh before trying again.'}); }
    finally { updateDetails({busy: false}); }
  }
  updateUpload(id, patch) {
    this.update({uploads: this.state.uploads.map(row => row.id === id ? {...row, ...patch} : row)});
  }
  dismissUpload(id) { this.update({uploads: this.state.uploads.filter(row => row.id !== id)}); }
  async upload(file) {
    if (!file || !this.state.ready) return;
    const id = ++this.serial;
    this.update({uploads: [...this.state.uploads, {id, name: file.name, percent: 0, text: '0%', error: false, done: false}]});
    const fail = text => this.updateUpload(id, {text, error: true, done: true});
    if (file.size > 4 * 1024 * 1024 * 1024) {
      fail(`too large: ${formatSize(file.size)} (max 4 GB) — not uploaded`); return;
    }
    try {
      const job = await this.services.upload(file, percent => {
        const bounded = Math.max(0, Math.min(100, percent));
        this.updateUpload(id, {percent: bounded, text: Math.round(bounded) + '%'});
      });
      this.updateUpload(id, {percent: 100, text: 'publishing…'});
      this.pollJob(job.job_id, {
        progress: text => this.updateUpload(id, {text}),
        failed: fail,
        done: text => {
          this.updateUpload(id, {percent: 100, text, done: true});
          this.schedule(() => this.dismissUpload(id), 8000);
        },
      });
    } catch (error) { fail(error.message || 'upload error'); }
  }
  async importFile(path) {
    if (!this.state.ready || this.state.importing.includes(path)) return;
    this.update({importing: [...this.state.importing, path], status: 'Importing…'});
    const finish = text => this.update({status: text, importing: this.state.importing.filter(value => value !== path)});
    try {
      const response = await this.services.post('/api/v1/images/import', {path});
      const body = await response.json().catch(() => ({}));
      if (!response.ok) { finish('Import failed: ' + (body.error || response.status)); await this.refresh('importable'); return; }
      this.pollJob(body.job_id, {progress: text => this.update({status: text}), done: finish, failed: finish});
    } catch { finish('Import response unavailable. Refresh before trying again.'); }
  }
  pollJob(jobId, ui) {
    if (typeof jobId !== 'string' || !jobId) { ui.failed('Publish response did not identify a job. Refresh before trying again.'); return; }
    const poll = async () => {
      if (this.disposed) return;
      try {
        const response = await this.services.fetch('/api/v1/images/jobs/' + encodeURIComponent(jobId));
        if (this.disposed) return;
        if (!response.ok) { ui.failed(`Publish status unavailable (${response.status}). Refresh before trying again.`); return; }
        const job = await response.json();
        if (this.disposed) return;
        if (job.state === 'done') { ui.done(publishedJobText(job)); await this.refreshLists(); }
        else if (job.state === 'error') { ui.failed('Publish failed: ' + job.message); await this.refresh('importable'); }
        else {
          ui.progress(job.state === 'verifying' ? 'checking Cisco Bulk Hash…' : 'Publishing ' + (job.filename || '') + '…');
          this.schedule(poll, 1000);
        }
      } catch { ui.progress('Publish status unavailable; retrying…'); this.schedule(poll, 1000); }
    };
    poll();
  }
}
