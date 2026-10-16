// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {checkedPage} from './inventory-model.mjs';
import {checkedIds, assignmentPreview, checkedCatalog, pickerRows, removalConfirmation, assignmentResult, bulkCredentialResult} from './assignments-model.mjs';

export class AssignmentsController {
  constructor() {
    this.state = {open: false, type: 'images', ids: [], row: false, expect: new Map(), chosen: [], order: [], images: [], imagesOk: false,
      credentials: [], credentialsOk: false, choice: '', ready: false, loading: false, busy: false, externalBusy: false,
      message: '', failed: false, results: [], different: false};
    this.listeners = new Set(); this.generation = 0; this.operation = false; this.imageGeneration = 0;
  }
  snapshot = () => this.state;
  subscribe = listener => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  update(patch) { this.state = {...this.state, ...patch}; this.listeners.forEach(listener => listener()); }
  connect(services) { this.services = services; }
  report(message, failed = false) { this.services?.report?.(message, failed); }
  visible() { return this.services?.isVisible?.() !== false; }
  prerequisites(inventory) {
    this.update({credentials: inventory.credentials, credentialsOk: inventory.credentialsOk,
      externalBusy: inventory.bulkBusy || inventory.rowBusy.size > 0});
  }
  beginImageRead() { return ++this.imageGeneration; }
  acceptImages(result, ticket) {
    if (ticket === this.imageGeneration) {
      let images = this.state.images, imagesOk = false;
      try { if (result.ok) { images = checkedCatalog(result.body); imagesOk = true; } } catch { /* retained, unavailable */ }
      // Preserve the full catalog projection for Inventory's other consumers.
      this.imageProjection = imagesOk ? result.body.images : this.imageProjection || [];
      this.update({images, imagesOk});
    }
    return {images: this.imageProjection || [], imagesOk: this.state.imagesOk};
  }
  close() {
    this.generation++; this.reader?.abort(); this.reader = null;
    this.update({open: false, loading: false});
  }
  hide() { this.close(); }
  start(type, ids, row = false) {
    if (this.operation || this.state.externalBusy) { this.report('Another device action is still running. Wait before opening this dialog.', true); return false; }
    try { ids = checkedIds(ids); if (!ids.length) throw new Error('No devices selected.'); }
    catch { this.report('Select valid devices before opening this dialog.', true); return false; }
    this.close();
    this.update({open: true, type, ids, row, expect: new Map(), chosen: [], order: [], choice: '',
      ready: false, busy: false, message: '', failed: false, results: [], different: false});
    return true;
  }
  async openImages(ids, row = false) {
    if (!this.state.imagesOk) { this.report('Image list unavailable; not opening the picker. Refresh Inventory and try again.', true); return; }
    if (this.start('images', ids, row)) await this.review();
  }
  openCredentials(ids) {
    if (!this.state.credentialsOk) { this.report('Credential list unavailable; not opening the picker. Refresh profiles and try again.', true); return; }
    if (this.start('credentials', ids)) this.update({ready: true});
  }
  async json(path, signal) {
    const response = await this.services.fetch(path, {signal});
    if (!response.ok) throw new Error(`Read unavailable (HTTP ${response.status}).`);
    return response.json();
  }
  async deviceRecords(ids, signal) {
    const records = new Map(), seen = new Set(), targets = new Set(ids);
    let offset = 0, total = null, revision = null;
    while (total === null || offset < total) {
      const body = checkedPage(await this.json('/api/v1/devices?limit=1000&offset=' + offset, signal), offset, 1000);
      if (signal.aborted) throw new Error('Read cancelled');
      if (total !== null && (total !== body.total || revision !== body.revision)) throw new Error('Inventory changed during the preview. Review again.');
      total = body.total; revision = body.revision;
      if (!body.devices.length && offset < total) throw new Error('Incomplete device preview. Review again.');
      for (const device of body.devices) {
        if (seen.has(device.device_id)) throw new Error('Duplicate device in preview. Review again.');
        seen.add(device.device_id);
        if (targets.has(device.device_id)) records.set(device.device_id, device);
      }
      if (records.size === targets.size) break;
      offset += body.devices.length;
    }
    if (records.size !== ids.length) throw new Error('Some reviewed devices are missing. Refresh Inventory and review the selection.');
    return records;
  }
  async review() {
    if (!this.state.open || this.state.type !== 'images' || this.operation) return;
    const generation = ++this.generation, ids = this.state.ids.slice();
    const imageTicket = this.beginImageRead();
    this.reader?.abort(); const reader = this.reader = new AbortController();
    this.update({loading: true, ready: false, message: '', failed: false, results: []});
    try {
      const [catalog, records] = await Promise.all([this.json('/api/v1/images', reader.signal), this.deviceRecords(ids, reader.signal)]);
      if (generation !== this.generation) return;
      const accepted = this.acceptImages({ok: true, body: catalog}, imageTicket);
      this.services.publishImages?.(accepted);
      if (!accepted.imagesOk) throw new Error('Image catalog unavailable.');
      const preview = assignmentPreview(ids, records);
      this.update({...preview, original: preview.chosen.slice(), ready: true,
        order: [...preview.chosen, ...this.state.images.map(row => row.id).filter(id => !preview.chosen.includes(id))]});
    } catch (error) {
      if (generation === this.generation) this.update({ready: false, message: 'Assignment preview unavailable. ' + error.message, failed: true});
    } finally {
      // Promise.all may reject before the other read finishes. Stop its page
      // walk too, so a failed catalog cannot leave hidden background requests.
      reader.abort();
      if (generation === this.generation) { this.reader = null; this.update({loading: false}); }
    }
  }
  toggleImage(id) {
    const row = pickerRows(this.state).find(row => row.id === id);
    if (!row || row.disabled) return;
    const chosen = new Set(this.state.chosen); row.checked ? chosen.delete(id) : chosen.add(id);
    this.update({chosen: this.state.order.filter(id => chosen.has(id))});
  }
  chooseCredential(value) { if (!this.operation) this.update({choice: value}); }
  claim() {
    const state = this.state;
    const claimed = state.row ? this.services.claimRow(state.ids[0]) : this.services.claimBulk(state.ids);
    if (!claimed) this.update({message: 'Another device action is still running. Wait before applying.', failed: true});
    return claimed;
  }
  async refreshInventory() { if (this.visible()) { try { await this.services.refreshInventory(); } catch { /* independent read status */ } } }
  async applyImages() {
    const state = this.state;
    if (!state.open || state.type !== 'images' || this.operation || !state.ready || !state.imagesOk) return;
    const chosen = checkedIds(state.chosen, 10), ids = state.ids.slice(), expect = new Map(state.expect), row = state.row;
    // Each ID must have a captured expectation, including an explicit empty set.
    if (ids.some(id => !expect.has(id))) { this.update({ready: false, message: 'Incomplete assignment preview. Review again.', failed: true}); return; }
    const confirmation = removalConfirmation(state);
    if (confirmation && !this.services.confirm(confirmation)) return;
    if (!this.claim()) return;
    this.operation = true;
    const generation = this.generation;
    this.update({busy: true, message: 'Applying… Closing this dialog does not cancel the requests.', failed: false, results: []});
    const results = new Map(); let cursor = 0;
    try {
      // A fixed worker bound avoids flooding the server for a large selection.
      const worker = async () => {
        while (cursor < ids.length) {
          const id = ids[cursor++]; let result;
          try {
            const response = await this.services.post('/api/v1/devices/' + encodeURIComponent(id) + '/assign',
              {image_ids: chosen, expect_image_ids: expect.get(id)});
            const body = await response.json().catch(() => null);
            result = assignmentResult(response, body, chosen);
          } catch { result = {kind: 'unknown', reason: 'Response unavailable; review before trying again'}; }
          results.set(id, {id, ...result});
          if (generation === this.generation) this.update({results: ids.filter(id => results.has(id)).map(id => results.get(id))});
        }
      };
      await Promise.all(Array.from({length: Math.min(4, ids.length)}, worker));
    } finally {
      const ordered = ids.map(id => results.get(id) || {id, kind: 'unknown', reason: 'Response unavailable'});
      const failed = ordered.filter(result => result.kind !== 'saved');
      const message = `Assigned ${chosen.length} image(s) to ${ids.length - failed.length}/${ids.length} device(s).`
        + (failed.length ? ' ' + failed.map(result => `${result.id}: ${result.kind} (${result.reason})`).join('; ')
          + '. Review current assignments before applying again.' : '');
      this.operation = false; this.update({busy: false});
      row ? this.services.releaseRow(ids[0]) : this.services.releaseBulk();
      if (generation === this.generation) {
        this.update({ready: false, message, failed: !!failed.length, results: ordered});
        if (!failed.length) this.close();
      }
      this.report(message, !!failed.length); await this.refreshInventory();
    }
  }
  async applyCredential() {
    const state = this.state;
    if (!state.open || state.type !== 'credentials' || this.operation || !state.ready) return;
    const ids = state.ids.slice(), choice = state.choice;
    if (!choice) { this.update({message: 'Choose a credential profile, or no credential to clear.', failed: true}); return; }
    const id = choice.startsWith('profile:') ? choice.slice(8) : '';
    if (!state.credentialsOk || (choice !== 'clear' && (!id || !state.credentials.some(row => row.id === id)))) {
      this.update({message: 'Credential list unavailable or profile missing. Refresh profiles before applying.', failed: true}); return;
    }
    if (!id && !this.services.confirm(`Clear the credential on ${ids.length} reviewed device(s)?\n\nOnboard and undeploy will be unavailable until you assign another profile. The credential profiles are kept.`)) return;
    if (!this.claim()) return;
    const generation = this.generation; this.operation = true;
    this.update({busy: true, message: 'Applying… Closing this dialog does not cancel the request.', failed: false});
    let result;
    try {
      const response = await this.services.post('/api/v1/devices/bulk-credential', {device_ids: ids, credential_profile_id: id});
      result = bulkCredentialResult(response, await response.json().catch(() => null), ids);
    } catch { result = {unknown: true, failed: [], applied: null}; }
    finally {
      const failed = result.unknown || result.failed.length > 0;
      const message = result.unknown ? 'Credential update outcome is unknown. Refresh Inventory before trying again.'
        : `${id ? 'Assigned ' + id + ' to' : 'Cleared credential on'} ${result.applied}/${ids.length} device(s).`
          + (result.failed.length ? ' Refused: ' + result.failed.map(([id, reason]) => `${id} (${reason})`).join('; ') : '');
      this.operation = false; this.update({busy: false}); this.services.releaseBulk();
      if (generation === this.generation) {
        this.update({message, failed, ready: false});
        if (!failed) this.close();
      }
      this.report(message, failed); await this.refreshInventory();
    }
  }
}
