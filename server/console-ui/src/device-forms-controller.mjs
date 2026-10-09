// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {emptyDevice, emptyCredential, managementInstallOptions, deviceBody, credentialBody, credentialProfiles} from './device-forms-model.mjs';

export class DeviceFormsController {
  constructor() {
    this.state = {deviceOpen: false, device: emptyDevice(), deviceBusy: false, deviceMessage: '', deviceFailed: false,
      options: [], optionHint: '', optionsLoading: false, credentialsOpen: false, credential: emptyCredential(),
      editing: false, credentialBusy: false, credentialMessage: '', credentialFailed: false, credentialReviewRequired: false,
      profiles: [], credentialsOk: false, credentialsLoading: false};
    this.listeners = new Set(); this.deviceSession = 0; this.credentialSession = 0;
    this.optionGeneration = 0; this.credentialGeneration = 0;
  }
  snapshot = () => this.state;
  subscribe = listener => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  update(patch) { this.state = {...this.state, ...patch}; this.listeners.forEach(listener => listener()); }
  connect(services) { this.services = services; }
  report(message, failed) { this.services?.report?.(message, failed); }
  visible() { return this.services?.isVisible?.() !== false; }
  async refreshInventory() { if (this.visible()) { try { await this.services?.refreshInventory?.(); } catch { /* independent read status */ } } }
  toggleDevice() {
    if (this.state.deviceOpen) return this.closeDevice();
    this.deviceSession++; this.update({deviceOpen: true, deviceMessage: '', deviceFailed: false});
    return this.refreshOptions();
  }
  closeDevice() {
    this.deviceSession++; this.cancelOptions(); this.update({deviceOpen: false});
  }
  setDevice(key, value) {
    if (this.state.deviceBusy || !(key in this.state.device)) return;
    this.update({device: {...this.state.device, [key]: value}});
    if (key === 'model' || key === 'management') return this.refreshOptions();
  }
  cancelOptions() { this.optionGeneration++; this.optionReader?.abort(); this.optionReader = null; this.update({optionsLoading: false}); }
  async refreshOptions() {
    this.cancelOptions();
    if (!this.state.deviceOpen || !this.visible()) return;
    const mine = this.optionGeneration, {management, model} = this.state.device;
    const allowed = managementInstallOptions(management);
    const render = (modelOptions, hint = '') => {
      const options = allowed.filter(value => modelOptions === null || modelOptions.includes(value));
      const platform = options.includes(this.state.device.platform) ? this.state.device.platform
        : allowed.length === 1 ? options[0] || '' : '';
      this.update({options, device: {...this.state.device, platform}, optionHint: allowed.length && !options.length
        ? 'This model and management type have no compatible agent install. Check either value.' : hint, optionsLoading: false});
    };
    render(null);
    if (!model || !allowed.length) return;
    const reader = this.optionReader = new AbortController(); this.update({optionsLoading: true});
    try {
      const response = await this.services.fetch('/api/v1/install-options?model=' + encodeURIComponent(model), {signal: reader.signal});
      if (!response.ok) throw new Error('Unavailable');
      const body = await response.json();
      if (mine !== this.optionGeneration) return;
      if (body?.options !== null && (!Array.isArray(body?.options) || body.options.some(value => typeof value !== 'string'))) throw new Error('Invalid options');
      render(body.options, body.options === null ? 'Unrecognized model. Confirm agent support before onboarding.' : '');
    } catch {
      if (mine === this.optionGeneration) render(null, 'Model compatibility could not be checked. It will be validated when saved.');
    } finally { if (mine === this.optionGeneration) this.optionReader = null; }
  }
  async saveDevice() {
    if (!this.state.deviceOpen || this.state.deviceBusy) return;
    let body;
    try {
      body = deviceBody(this.state.device);
      if (!this.state.options.includes(body.platform)) throw new Error(this.state.optionHint || 'Choose an agent install for this device.');
      if (body.credential_profile_id && (!this.state.credentialsOk || !this.state.profiles.some(row => row.id === body.credential_profile_id))) {
        throw new Error('Credential unavailable. Refresh profiles or choose no credential.');
      }
    } catch (error) { this.update({deviceMessage: error.message, deviceFailed: true}); return; }
    if (this.services.claimDevice?.(body.device_id) === false) {
      this.update({deviceMessage: 'Another device action is still running. Wait for it before saving.', deviceFailed: true}); return;
    }
    const session = this.deviceSession;
    this.update({deviceBusy: true, deviceMessage: 'Saving device… Closing this form does not cancel the request.', deviceFailed: false});
    let message, failed = true;
    try {
      const response = await this.services.post('/api/v1/devices', body);
      if (response.status >= 500) throw new Error('Unknown result');
      const result = await response.json();
      if (!response.ok) message = `Device save refused: ${result?.error || result?.title || response.status}.`;
      else if (result?.device?.device_id !== body.device_id) throw new Error('Unknown result');
      else { message = `Device ${body.device_id} saved.`; failed = false; }
    } catch { message = `Save outcome is unknown for ${body.device_id}. Refresh Inventory before trying again.`; }
    finally {
      this.services.releaseDevice?.(body.device_id);
      this.update({deviceBusy: false});
      if (session === this.deviceSession) {
        this.update({deviceMessage: message, deviceFailed: failed});
        if (!failed) { this.closeDevice(); this.update({device: emptyDevice()}); }
      }
      this.report(message, failed); await this.refreshInventory();
    }
  }
  beginCredentialRead() { return ++this.credentialGeneration; }
  credentialSnapshot() { return {credentials: this.state.profiles, credentialsOk: this.state.credentialsOk}; }
  acceptCredentials(result, ticket) {
    if (ticket !== this.credentialGeneration || this.state.credentialBusy) return this.credentialSnapshot();
    let profiles = this.state.profiles, ok = false;
    try { if (result.ok) { profiles = credentialProfiles(result.body); ok = true; } } catch { /* retain evidence, unavailable */ }
    this.update({profiles, credentialsOk: ok, credentialsLoading: false});
    this.services?.publishCredentials?.(this.credentialSnapshot());
    return this.credentialSnapshot();
  }
  invalidateCredentials() {
    this.beginCredentialRead(); this.credentialReader?.abort(); this.credentialReader = null;
    this.update({credentialsOk: false, credentialsLoading: false});
    this.services?.publishCredentials?.(this.credentialSnapshot());
  }
  async refreshCredentials(review = false) {
    if (!this.visible() || this.state.credentialBusy || review && !this.state.credentialsOpen) return false;
    this.credentialReader?.abort();
    const reader = this.credentialReader = new AbortController(), ticket = this.beginCredentialRead(), session = this.credentialSession;
    this.update({credentialsLoading: true});
    let result;
    try { const response = await this.services.fetch('/api/v1/credentials', {signal: reader.signal});
      const ok = response.ok && (!review || response.status === 200);
      result = {ok, body: ok ? await response.json() : null}; }
    catch { result = {ok: false}; }
    const snapshot = this.acceptCredentials(result, ticket);
    const current = ticket === this.credentialGeneration && reader === this.credentialReader &&
      session === this.credentialSession && this.visible() && this.state.credentialsOpen;
    if (review && current && snapshot.credentialsOk) {
      this.update({credentialReviewRequired: false, credentialFailed: false,
        credentialMessage: 'Current profiles loaded. Review the profile, then re-enter its secrets before saving.'});
    }
    if (reader === this.credentialReader) { this.credentialReader = null; this.update({credentialsLoading: false}); }
    return current && snapshot.credentialsOk;
  }
  toggleCredentials() {
    if (this.state.credentialsOpen) return this.closeCredentials();
    this.credentialSession++; this.update({credentialsOpen: true}); return this.refreshCredentials();
  }
  clearSecrets() { this.update({credential: {...this.state.credential, password: '', confirm: '', enable: ''}}); }
  closeCredentials() { this.credentialSession++; this.clearSecrets(); this.update({credentialsOpen: false}); }
  hide() {
    this.cancelOptions(); this.closeCredentials();
    this.credentialReader?.abort(); this.credentialReader = null;
    this.beginCredentialRead(); this.update({credentialsLoading: false});
  }
  resume() { if (this.state.deviceOpen) return this.refreshOptions(); }
  setCredential(key, value) {
    if (this.state.credentialBusy || this.state.credentialReviewRequired || !(key in this.state.credential) || (key === 'id' && this.state.editing)) return;
    this.update({credential: {...this.state.credential, [key]: value}});
  }
  newCredential() {
    if (this.state.credentialBusy || this.state.credentialReviewRequired) return;
    this.credentialSession++; this.update({credential: emptyCredential(), editing: false, credentialMessage: '', credentialFailed: false});
  }
  editCredential(id) {
    if (this.state.credentialBusy || this.state.credentialReviewRequired || !this.state.credentialsOk) return;
    const profile = this.state.profiles.find(row => row.id === id);
    if (!profile) return;
    this.credentialSession++;
    this.update({credential: {...emptyCredential(), id, name: profile.name, user: profile.device_user}, editing: true,
      credentialMessage: `Editing "${id}". Re-enter the device password to save changes.`, credentialFailed: false});
  }
  async saveCredential() {
    if (!this.state.credentialsOpen || this.state.credentialBusy || this.state.credentialReviewRequired) return;
    let body;
    try { body = credentialBody(this.state.credential); }
    catch (error) { this.update({credentialMessage: error.message, credentialFailed: true}); return; }
    return this.mutateCredential('save', body.id, body);
  }
  async deleteCredential(id) {
    if (this.state.credentialBusy || this.state.credentialReviewRequired || !this.state.credentialsOk || !this.state.profiles.some(row => row.id === id)) return;
    if (!this.services.confirm(`Delete credential profile ${id}? Devices assigned to it will need another profile.`)) return;
    return this.mutateCredential('delete', id);
  }
  async mutateCredential(action, id, body) {
    if (this.state.credentialBusy || this.state.credentialReviewRequired) return;
    const session = this.credentialSession;
    this.update({credentialBusy: true, credentialMessage: action === 'save' ? 'Saving profile…' : 'Deleting profile…', credentialFailed: false});
    this.invalidateCredentials();
    let message, failed = true, unknown = false;
    try {
      const response = action === 'save' ? await this.services.post('/api/v1/credentials', body)
        : await this.services.fetch('/api/v1/credentials/' + encodeURIComponent(id), {method: 'DELETE', headers: this.services.headers()});
      // The BFF can lose the upstream response after forwarding this write.
      // A 5xx is not proof that the stored profile remained unchanged.
      if (response.status >= 500) throw new Error('Unknown result');
      const result = await response.json();
      // Do not echo a server error on this secret-bearing route: a proxy or
      // validation failure might have reflected submitted credential values.
      if (!response.ok) message = `Profile ${action} refused (HTTP ${response.status}). Check the profile details and try again.`;
      else if (action === 'save' ? result?.profile?.id !== id : typeof result?.deleted !== 'boolean') throw new Error('Unknown result');
      else { message = action === 'save' ? `Profile ${id} saved.` : result.deleted ? `Profile ${id} deleted.` : `Profile ${id} was already absent.`; failed = false; }
    } catch { unknown = true; message = `Profile ${action} outcome is unknown. Choose Refresh profiles and review the current profile before trying again.`; }
    finally {
      this.invalidateCredentials(); this.update({credentialBusy: false, ...(unknown ? {
        credentialReviewRequired: true, credentialMessage: message, credentialFailed: true,
      } : {})});
      if (session === this.credentialSession) {
        this.update({credentialMessage: message, credentialFailed: failed});
        if (action === 'save' && !failed) this.update({credential: emptyCredential(), editing: false});
        if (!failed && action === 'delete' && this.state.credential.id === id) this.update({credential: emptyCredential(), editing: false});
      }
      if (unknown || !failed) this.clearSecrets();
      this.report(message, failed);
      if (this.visible()) { await this.refreshCredentials(); await this.refreshInventory(); }
    }
  }
}
