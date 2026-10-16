// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {requestId} from './certificates-model.mjs';
import {certificateUrl, certificateStatus, uncertainRevocation, uncertainReenrollment, revocationConfirmed,
  reenrollmentConfirmed, certificateActionSuperseded, certificateMessage, revocationConfirmation, reenrollmentConfirmation,
  revocationRefusal} from './device-certificate-model.mjs';

const uncertain = pending => pending?.action === 'reenroll' ? uncertainReenrollment : uncertainRevocation;
const confirmed = (value, pending) => pending.action === 'reenroll'
  ? reenrollmentConfirmed(value, pending) : revocationConfirmed(value, pending);

// Kept outside the transient drawer: closing a panel never retries a write or
// releases an uncertain result for a different certificate on the same device.
export class DeviceCertificateController {
  constructor(publish) {
    this.publish = publish;
    this.pending = new Map();
    this.observed = new Map();
    this.generation = 0;
    this.state = null;
  }
  connect(services) { this.services = services; }
  update(patch) { if (this.state) { this.state = {...this.state, ...patch}; this.publish(this.state); } }
  current(id, generation) { return this.state?.id === id && generation === this.generation; }
  invalidate() { this.generation++; this.reader?.abort(); this.reader = null; }
  open(id) {
    this.invalidate();
    const pending = this.pending.get(id);
    this.state = {id, status: null, loading: false, blocked: !!pending, busy: pending?.kind === 'pending',
      message: pending ? pending.kind === 'pending' ? 'Certificate request is still pending.' : uncertain(pending) : '', failed: !!pending};
    this.publish(this.state);
    return this.refresh();
  }
  close() { this.invalidate(); this.state = null; }
  acceptStatus(value) {
    const previous = this.observed.get(value.device_id);
    if (previous && (value.revision < previous.revision
        || value.revision === previous.revision && (value.identity_sha256 !== previous.identity_sha256 || value.state !== previous.state
          || value.request_id !== previous.request_id || value.recovery_request_id !== previous.recovery_request_id)
        || value.identity_sha256 === previous.identity_sha256 && previous.state !== 'active' && value.state === 'active')) return false;
    this.observed.set(value.device_id, value); return true;
  }
  canAct(action) {
    return !!this.state?.status && !this.state.loading && !this.state.blocked && !this.state.busy
      && this.state.status.state === (action === 'reenroll' ? 'revoked' : 'active') && this.state.status.peer_tls_required === true;
  }
  canRevoke() { return this.canAct('revoke'); }
  canReenroll() { return this.canAct('reenroll'); }
  async refresh() {
    if (!this.state || this.state.loading || this.state.busy) return;
    const {id} = this.state, generation = this.generation, reader = this.reader = new AbortController();
    this.update({loading: true, status: null});
    try {
      const response = await this.services.fetch(certificateUrl(id), {signal: reader.signal, cache: 'no-store'});
      const value = await response.json();
      if (!this.current(id, generation) || this.reader !== reader) return;
      if (!response.ok || !certificateStatus(value, id) || !this.acceptStatus(value)) throw Error('Unavailable status');
      const pending = this.pending.get(id);
      const superseded = pending?.kind === 'unknown' && certificateActionSuperseded(value, pending)
        && !confirmed(value, pending);
      if (pending?.kind === 'unknown' && confirmed(value, pending)) this.pending.delete(id);
      else if (superseded) this.pending.delete(id);
      const blocked = this.pending.has(id);
      this.update({status: value, blocked, failed: blocked,
        message: blocked ? uncertain(pending) : superseded
          ? 'The device now has a different certificate identity. The earlier request is no longer current. Review this status before continuing.'
          : certificateMessage(value)});
    } catch {
      if (this.current(id, generation) && this.reader === reader) this.update({status: null, failed: true,
        message: this.pending.has(id) ? uncertain(this.pending.get(id)) + ' Status is unavailable.'
          : this.observed.get(id)?.state === 'reenrollment-required' ? 'Fresh onboarding was approved. Current status is unavailable; check status again.'
          : this.observed.get(id)?.state === 'revoked' ? 'Revocation was saved. Current status is unavailable; check status again.'
          : 'Device certificate status is unavailable. Check status to try again.'});
    } finally {
      if (this.current(id, generation) && this.reader === reader) { this.reader = null; this.update({loading: false}); }
    }
  }
  revoke() { return this.act('revoke'); }
  reenroll() { return this.act('reenroll'); }
  async act(action) {
    if (!['revoke', 'reenroll'].includes(action) || !this.canAct(action)) return;
    const {id, status: before} = this.state, generation = this.generation;
    // Lock before confirmation, including asynchronous confirmation services.
    const pending = {kind: 'pending', action, identity: before.identity_sha256, revision: before.revision};
    this.pending.set(id, pending); this.update({busy: true, blocked: true, message: '', failed: false});
    let sent = false, outcome = 'cancelled', message = '';
    try {
      const confirmation = action === 'reenroll' ? reenrollmentConfirmation : revocationConfirmation;
      if (!await this.services.confirm(confirmation(id)) || !this.current(id, generation)) return;
      const request = this.services.uuid();
      if (!requestId(request) || request.length !== 36) throw Error('Request identity unavailable');
      pending.request = request;
      const payload = {expected_revision: before.revision, expected_identity_sha256: before.identity_sha256, request_id: request};
      this.update({message: action === 'reenroll' ? 'Approving fresh onboarding…' : 'Saving revocation…'}); sent = true;
      const response = await this.services.post(certificateUrl(id) + '/' + action, payload);
      const value = await response.json();
      if (response.ok && certificateStatus(value, id) && confirmed(value, pending)
          && (action === 'reenroll' || value.request_id === request) && this.acceptStatus(value)) {
        outcome = 'saved'; message = certificateMessage(value);
      } else if (!response.ok && response.status >= 400 && response.status < 500) {
        outcome = 'refused'; message = revocationRefusal(response.status, action, value);
      } else { outcome = 'unknown'; message = uncertain(pending); }
    } catch {
      outcome = sent ? 'unknown' : 'unavailable';
      message = sent ? uncertain(pending) : 'Could not confirm this request. Check status before trying again.';
    } finally {
      if (outcome === 'unknown') pending.kind = 'unknown';
      else this.pending.delete(id);
      if (this.state?.id === id) {
        // Invalidate any read from before the write completed, including one
        // started after close/reopen. The POST itself is never aborted.
        this.invalidate();
        this.update({busy: false, loading: false, blocked: outcome === 'unknown', status: null,
          message, failed: ['unknown', 'refused', 'unavailable'].includes(outcome)});
        if (outcome === 'saved') await this.refresh();
        else if (outcome === 'cancelled' && generation + 1 === this.generation) this.update({status: before});
      }
    }
  }
}
