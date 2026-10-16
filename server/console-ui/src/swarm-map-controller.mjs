// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {POLL_SECONDS, validSnapshot, validRevision, validDirective, intervalReply, reportsReply,
  matchingPull, participantRows, peerKey} from './swarm-map-model.mjs';

const emptyActions = () => ({interval: {busy: false, unknown: false, message: '', draft: '60'},
  pull: {busy: false, unknown: false, message: '', request: null}});

export class SwarmMapController {
  constructor(config = {}, services = {}) {
    this.config = {pull: config.pull === true, swarmUrl: config.swarmUrl === '/api/v1/swarm' ? '/api/v1/swarm' : '/swarm',
      eventsUrlTemplate: typeof config.eventsUrlTemplate === 'string' ? config.eventsUrlTemplate : ''};
    this.services = services;
    this.state = {data: null, now: 0, lastUpdated: null, loading: false, loadFailed: false, backoff: POLL_SECONDS,
      paused: false, hostPaused: !!services.embedded, documentHidden: !!services.documentHidden, selected: null,
      actions: {}, reports: [], reportMessage: '', reportsLoading: false, sessionReady: false, sessionError: false};
    this.listeners = new Set(); this.running = false; this.epoch = 0; this.generation = 0; this.reportGeneration = 0;
    this.sessionGeneration = 0; this.csrf = null; this.pollTimer = null; this.tickTimer = null; this.reportTimer = null;
    this.clock = 0; this.serverFloor = 0; this.serverClockAt = null;
  }
  subscribe = listener => {this.listeners.add(listener); return () => this.listeners.delete(listener);};
  snapshot = () => this.state;
  update(patch) {this.state = {...this.state, ...patch}; this.listeners.forEach(listener => listener());}
  now() {this.clock = Math.max(this.clock, this.services.now() / 1000); return this.clock;}
  advanceServerClock(observed = null) {
    const local = this.now();
    if (this.serverClockAt !== null) this.serverFloor += Math.max(0, local - this.serverClockAt);
    if (observed !== null) this.serverFloor = Math.max(this.serverFloor, observed);
    if (this.serverClockAt !== null || observed !== null) this.serverClockAt = local;
    return this.serverFloor;
  }
  actionsFor(deviceId) {return Object.hasOwn(this.state.actions, deviceId) ? this.state.actions[deviceId] : emptyActions();}
  action(deviceId, family, patch) {
    const prior = this.actionsFor(deviceId);
    this.update({actions: {...this.state.actions, [deviceId]: {...prior, [family]: {...prior[family], ...patch}}}});
  }
  selectedPeer() {return participantRows(this.state.data).find(peer => peerKey(peer) === this.state.selected) || null;}
  controlsVisible() {return this.running && !this.state.paused && !this.state.hostPaused && !this.state.documentHidden;}
  activePeer() {
    const peer = this.controlsVisible() && this.config.pull && this.state.sessionReady ? this.selectedPeer() : null;
    return peer?.tracker?.principal_type === 'device' ? peer : null;
  }
  context() {const peer = this.activePeer(); return peer?.device_id ? {peer, key: this.state.selected, epoch: this.epoch} : null;}
  current(context) {return !!context && this.epoch === context.epoch && this.state.selected === context.key
    && this.activePeer()?.device_id === context.peer.device_id;}
  canInterval() {const peer = this.activePeer(), action = this.actionsFor(peer?.device_id).interval; return !!peer?.device_id && !action.busy && !action.unknown;}
  canPull() {const peer = this.activePeer(), action = this.actionsFor(peer?.device_id).pull; return !!peer?.device_id && !action.busy && !action.unknown && !action.request;}
  canReviewInterval() {const peer = this.activePeer(); return !!peer?.device_id && !this.actionsFor(peer.device_id).interval.busy;}
  canReviewPull() {const peer = this.activePeer(); return !!peer?.device_id && !this.actionsFor(peer.device_id).pull.busy;}
  clearTimer(name) {if (this[name] !== null) this.services.clearTimeout(this[name]); this[name] = null;}
  cancelReads() {
    this.epoch++; this.generation++; this.reportGeneration++; this.sessionGeneration++;
    for (const name of ['reader', 'reportReader', 'sessionReader']) {this[name]?.abort(); this[name] = null;}
    this.sessionPromise = null;
    for (const name of ['pollTimer', 'tickTimer', 'reportTimer']) this.clearTimer(name);
    this.update({loading: false, reportsLoading: false});
  }
  async start() {
    if (this.running) return;
    this.running = true; return this.resume();
  }
  stop() {this.running = false; this.cancelReads();}
  async resume() {
    const epoch = this.epoch;
    this.tick();
    if (!this.controlsVisible()) return;
    await Promise.all([this.ensureSession(), this.poll()]);
    if (epoch === this.epoch && this.activePeer()) await this.readReports(false);
  }
  setHostPaused(value) {this.setVisibility('hostPaused', !!value);}
  setDocumentHidden(value) {this.setVisibility('documentHidden', !!value);}
  togglePause() {this.setVisibility('paused', !this.state.paused);}
  setVisibility(key, value) {
    if (this.state[key] === value) return;
    this.cancelReads(); this.update({[key]: value}); void this.resume();
  }
  tick() {
    this.clearTimer('tickTimer');
    if (!this.running || this.state.documentHidden || this.state.hostPaused) return;
    this.update({now: this.advanceServerClock()});
    this.tickTimer = this.services.setTimeout(() => this.tick(), 1000);
  }
  async request(url, options) {
    const epoch = this.epoch, sessionGeneration = this.sessionGeneration;
    const reply = await this.services.fetch(url, options);
    if (reply.status === 401 && epoch === this.epoch && sessionGeneration === this.sessionGeneration) {
      this.csrf = null; this.update({sessionReady: false, sessionError: true});
    }
    return reply;
  }
  async ensureSession() {
    if (!this.config.pull || !this.controlsVisible() || this.state.sessionReady) return;
    if (this.sessionPromise) return this.sessionPromise;
    const reader = new AbortController(), generation = ++this.sessionGeneration;
    this.sessionReader = reader;
    const promise = (async () => {
      try {
        const reply = await this.request('/api/v1/session', {cache: 'no-store', signal: reader.signal});
        const body = reply.status === 200 ? await reply.json() : null;
        if (generation !== this.sessionGeneration || !this.controlsVisible()) return;
        if (typeof body?.csrf !== 'string' || !body.csrf || body.csrf.length > 4096) throw Error();
        this.csrf = body.csrf; this.update({sessionReady: true, sessionError: false});
      } catch {
        if (generation === this.sessionGeneration) {this.csrf = null; this.update({sessionReady: false, sessionError: true});}
      } finally {if (generation === this.sessionGeneration) {this.sessionReader = null; this.sessionPromise = null;}}
    })();
    this.sessionPromise = promise; return promise;
  }
  async poll() {
    if (!this.controlsVisible()) return false;
    this.clearTimer('pollTimer'); this.reader?.abort();
    const reader = new AbortController(), generation = ++this.generation;
    this.reader = reader; this.update({loading: true});
    try {
      const reply = await this.request(this.config.swarmUrl, {cache: 'no-store', signal: reader.signal, headers: {'X-IRIS-Poll': '1'}});
      const data = reply.status === 200 ? await reply.json() : null;
      if (generation !== this.generation || !this.controlsVisible()) return false;
      if (!validSnapshot(data)) throw Error();
      const priorPeer = this.selectedPeer();
      this.advanceServerClock(data.now);
      this.update({data, now: this.serverFloor, lastUpdated: this.now(), loadFailed: false, backoff: POLL_SECONDS});
      if (priorPeer && !this.selectedPeer()) {this.epoch++; this.reportGeneration++; this.reportReader?.abort(); this.clearTimer('reportTimer'); this.update({reports: [], reportMessage: '', reportsLoading: false});}
      return true;
    } catch {
      if (generation === this.generation && this.controlsVisible()) {
        this.epoch++; this.reportGeneration++; this.reportReader?.abort(); this.clearTimer('reportTimer');
        this.update({data: null, loadFailed: true, backoff: Math.min(30, this.state.backoff * 2), reports: [], reportMessage: '', reportsLoading: false});
      }
      return false;
    } finally {
      if (generation === this.generation) {
        this.reader = null; this.update({loading: false});
        if (this.controlsVisible()) this.pollTimer = this.services.setTimeout(() => this.poll(), this.state.backoff * 1000);
      }
    }
  }
  select(key) {
    this.epoch++; this.reportGeneration++; this.reportReader?.abort(); this.clearTimer('reportTimer');
    this.update({selected: key, reports: [], reportMessage: '', reportsLoading: false});
    const peer = this.selectedPeer();
    if (peer?.device_id && !Object.hasOwn(this.state.actions, peer.device_id)) {
      this.action(peer.device_id, 'interval', {draft: peer.peer_telemetry?.requested_interval_s === 10 ? '10' : '60'});
    }
    if (this.activePeer()) return this.readReports(false);
  }
  close() {return this.select(null);}
  setIntervalDraft(value) {
    if (!this.canInterval() || !['10', '60'].includes(String(value))) return;
    this.action(this.activePeer().device_id, 'interval', {draft: String(value), message: ''});
  }
  async saveInterval() {
    if (!this.canInterval()) return;
    const context = this.context(), peer = context.peer, interval = Number(this.actionsFor(peer.device_id).interval.draft);
    if (![10, 60].includes(interval)) return;
    let dispatched = false;
    this.action(peer.device_id, 'interval', {busy: true, message: 'Checking interval…'});
    try {
      const policyReply = await this.request('/api/v1/peer-policy', {cache: 'no-store'});
      const policy = policyReply.status === 200 ? await policyReply.json() : null;
      if (!validRevision(policy?.revision)) throw Error('Current policy is unavailable. Review the current interval before trying again.');
      if (!this.current(context)) return;
      const headers = {'Content-Type': 'application/json', 'X-CSRF-Token': this.csrf, 'If-Match': `"iris-peer-policy-${policy.revision}"`};
      const url = '/api/v1/devices/' + encodeURIComponent(peer.device_id) + '/peer-telemetry', body = {interval_s: interval};
      const response = await this.request(url + '?dry_run=1', {method: 'POST', headers, body: JSON.stringify(body)});
      const preview = await response.json().catch(() => null);
      if (response.status !== 200 || !intervalReply(preview, peer, interval, policy.revision, true)
        || typeof preview.requires_confirmation !== 'boolean' || !(preview.confirm_token === null || typeof preview.confirm_token === 'string')
        || preview.requires_confirmation && !preview.confirm_token) {
        throw Error(response.status === 412 ? 'Policy changed. Review the current interval before trying again.'
          : preview?.code === 'peer_telemetry_unsupported' ? 'Update the device agent and wait for its next heartbeat.'
          : 'Interval preview did not match this device and request. Review the current interval.');
      }
      if (!this.current(context)) return;
      if (preview.requires_confirmation && !this.services.confirm(`Set peer telemetry for ${peer.device_id} to ${interval} seconds? Policy revision ${policy.revision} will become ${preview.revision}. Faster reporting uses more telemetry bandwidth.`)) {
        this.action(peer.device_id, 'interval', {message: 'Interval change cancelled. No update was sent.'}); return;
      }
      if (!this.current(context)) return;
      if (preview.confirm_token) body.confirm_token = preview.confirm_token;
      dispatched = true; this.action(peer.device_id, 'interval', {message: 'Saving interval…'});
      const reply = await this.request(url, {method: 'POST', headers, body: JSON.stringify(body)});
      const result = await reply.json();
      if (reply.status !== 200 || !intervalReply(result, peer, interval, policy.revision, false)) throw Error();
      this.action(peer.device_id, 'interval', {message: 'Saved. Waiting for the device to apply its signed policy. The reported interval shows when it takes effect.'});
    } catch (error) {
      this.action(peer.device_id, 'interval', {unknown: true, message: dispatched
        ? 'Save outcome is not confirmed. Review the current interval before trying again.'
        : error.message || 'Interval check failed. Review the current interval.'});
    } finally {
      const action = this.actionsFor(peer.device_id).interval;
      this.action(peer.device_id, 'interval', {busy: false, ...(!dispatched && !action.unknown && action.message === 'Checking interval…'
        ? {message: 'Interval check stopped. Save again when ready.'} : {})});
    }
  }
  async reviewInterval() {
    if (!this.canReviewInterval()) return;
    const context = this.context(), peer = context.peer;
    this.action(peer.device_id, 'interval', {busy: true});
    try {
      const reply = await this.request('/api/v1/devices/' + encodeURIComponent(peer.device_id) + '/effective-qos', {cache: 'no-store'});
      const body = await reply.json(), interval = body.qos?.peer_telemetry_interval_s?.value;
      if (reply.status !== 200 || body.device_id !== peer.device_id || !validRevision(body.revision)
        || body.degraded !== false || body.fail_closed !== false || ![10, 60].includes(interval)) throw Error();
      if (!this.current(context)) return;
      this.action(peer.device_id, 'interval', {unknown: false, draft: String(interval),
        message: `Current requested interval: ${interval} seconds (policy ${body.revision}). Device application is shown separately.`});
    } catch {if (this.current(context)) this.action(peer.device_id, 'interval', {message: 'Current interval could not be reviewed. Try Review current interval again.'});}
    finally {this.action(peer.device_id, 'interval', {busy: false});}
  }
  async readReports(explicit) {
    const context = this.context(); if (!context) return false;
    const peer = context.peer, generation = ++this.reportGeneration, reader = new AbortController();
    this.reportReader?.abort(); this.reportReader = reader; this.update({reportsLoading: true});
    try {
      const reply = await this.request('/api/v1/devices/' + encodeURIComponent(peer.device_id) + '/reports', {cache: 'no-store', signal: reader.signal});
      const body = await reply.json();
      if (!this.current(context) || generation !== this.reportGeneration) return false;
      if (reply.status !== 200 || !reportsReply(body, peer.device_id)) throw Error();
      this.update({reports: body.reports, reportMessage: body.reports.length ? '' : 'No full report received yet.'});
      const request = this.actionsFor(peer.device_id).pull.request;
      if (matchingPull(body.reports, request)) {
        this.action(peer.device_id, 'pull', {request: body.pending_request, unknown: false,
          message: `Matching report received for request ${request.request_id}.` + (body.pending_request ? ` Request ${body.pending_request.request_id} is still pending.` : '')});
        this.clearTimer('reportTimer'); return true;
      }
      if (explicit) {
        this.action(peer.device_id, 'pull', {unknown: false, request: body.pending_request,
          message: body.pending_request ? `Existing report request ${body.pending_request.request_id} is pending. No matching completion is confirmed.`
            : 'No pending request. The previous pull has no matching report in the current history. You can request a new report.'});
      } else if (body.pending_request && !request && !this.actionsFor(peer.device_id).pull.unknown) {
        this.action(peer.device_id, 'pull', {request: body.pending_request,
          message: `Existing report request ${body.pending_request.request_id} is pending. Use Review report request.`});
      }
      return false;
    } catch {
      if (this.current(context) && generation === this.reportGeneration) {
        this.update({reports: [], reportMessage: 'Historical participation unavailable.'});
        if (explicit) this.action(peer.device_id, 'pull', {message: 'Report request could not be reviewed. Try Review report request again.'});
      }
      return false;
    } finally {if (generation === this.reportGeneration) {this.reportReader = null; this.update({reportsLoading: false});}}
  }
  async requestPull() {
    if (!this.canPull()) return;
    const context = this.context(), peer = context.peer;
    this.clearTimer('reportTimer'); this.reportGeneration++; this.reportReader?.abort();
    this.action(peer.device_id, 'pull', {busy: true, message: 'Request pending…'});
    try {
      const reply = await this.request('/api/v1/devices/' + encodeURIComponent(peer.device_id) + '/request-report',
        {method: 'POST', headers: {'X-CSRF-Token': this.csrf}});
      const body = await reply.json();
      if (reply.status !== 200 || body.ok !== true || body.device_id !== peer.device_id || !validDirective(body)) throw Error();
      const request = {request_id: body.request_id, requested_at: body.requested_at, expires_at: body.expires_at};
      this.action(peer.device_id, 'pull', {request, message: `Report request ${request.request_id} accepted. Waiting for its matching report.`});
      if (this.current(context)) this.scheduleReports(context, this.now() + 30);
    } catch {
      this.action(peer.device_id, 'pull', {unknown: true, message: 'Report request outcome is not confirmed. Use Review report request before trying again.'});
    } finally {this.action(peer.device_id, 'pull', {busy: false});}
  }
  scheduleReports(context, until) {
    this.clearTimer('reportTimer');
    if (!this.current(context)) return;
    if (this.now() >= until) {
      const request = this.actionsFor(context.peer.device_id).pull.request;
      if (request) this.action(context.peer.device_id, 'pull', {message: `Still waiting for request ${request.request_id}. Use Review report request.`});
      return;
    }
    this.reportTimer = this.services.setTimeout(async () => {
      this.reportTimer = null;
      if (!this.current(context)) return;
      const matched = await this.readReports(false);
      if (!matched) this.scheduleReports(context, until);
    }, 2000);
  }
  async reviewPull() {
    if (!this.canReviewPull()) return;
    const peer = this.activePeer(); this.clearTimer('reportTimer');
    this.action(peer.device_id, 'pull', {busy: true});
    try {return await this.readReports(true);} finally {this.action(peer.device_id, 'pull', {busy: false});}
  }
}
