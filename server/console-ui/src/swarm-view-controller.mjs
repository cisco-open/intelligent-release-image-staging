// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {swarmSummary} from './swarm-view-model.mjs';

export class SwarmViewController {
  constructor() {
    this.state = {started: false, loading: false, summary: null, error: false};
    this.services = {}; this.listeners = new Set(); this.generation = 0; this.frame = null;
  }
  snapshot = () => this.state;
  subscribe = listener => {this.listeners.add(listener); return () => this.listeners.delete(listener);};
  update(patch) {this.state = {...this.state, ...patch}; this.listeners.forEach(listener => listener());}
  connect(services) {this.services = services;}
  visible() {return this.services.visible?.() === true;}
  attachFrame(frame) {this.frame = frame;}
  syncVisibility() {
    if (this.frame?.contentWindow) {
      this.frame.contentWindow.postMessage(this.visible() ? 'MAP_RESUME' : 'MAP_PAUSE', this.services.origin);
    }
    if (!this.visible()) {
      this.generation++; this.reader?.abort(); this.reader = null;
      this.update({loading: false, summary: null, error: false});
    }
  }
  async refresh() {
    if (!this.visible()) return false;
    this.reader?.abort(); const reader = new AbortController(), generation = ++this.generation;
    this.reader = reader; this.update({started: true, loading: true});
    try {
      const reply = await this.services.fetch('/api/v1/swarm', {signal: reader.signal, cache: 'no-store'});
      const summary = reply.status === 200 ? swarmSummary(await reply.json()) : null;
      if (generation !== this.generation || !this.visible()) return false;
      if (!summary) throw Error();
      this.update({summary, error: false}); return true;
    } catch {
      if (generation === this.generation && this.visible()) this.update({summary: null, error: true});
      return false;
    } finally {
      if (generation === this.generation) {this.reader = null; this.update({loading: false});}
    }
  }
}
