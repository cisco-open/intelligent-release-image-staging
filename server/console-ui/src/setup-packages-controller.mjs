// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {setupStatus, setupURL, verificationURL, firstIncomplete, incompleteCount, setupSteps} from './setup-packages-model.mjs';
import {verificationSettings} from './image-verification-model.mjs';

export class SetupPackagesController {
  constructor() {
    this.state = {mode: null, status: null, configured: null, loading: false, message: '', step: 0, navigating: false, dismissed: false, attention: 0};
    this.services = {}; this.listeners = new Set(); this.generation = 0; this.navigation = 0; this.annotationGeneration = 0;
  }
  subscribe = listener => {this.listeners.add(listener); return () => this.listeners.delete(listener);};
  snapshot = () => this.state;
  update(changes) {this.state = {...this.state, ...changes}; this.listeners.forEach(listener => listener());}
  connect(services) {
    this.services = services;
    try {this.update({dismissed: Boolean(services.storage?.getItem('iris_setup_nudge_dismissed'))});} catch { /* Storage can be unavailable; keep the page usable. */ }
  }
  visible() {return Boolean(this.state.mode && this.services.visible?.(this.state.mode));}
  annotation(configured) {
    this.annotationGeneration++;
    this.update({configured: typeof configured === 'boolean' ? configured : null});
  }
  dismiss() {
    this.update({dismissed: true});
    try {this.services.storage?.setItem('iris_setup_nudge_dismissed', '1');} catch { /* Dismiss for this document even if storage is disabled. */ }
  }
  hide() {
    this.generation++; this.navigation++; this.abort?.abort(); this.abort = null;
    this.update({loading: false, navigating: false, status: null, configured: null});
  }
  select(mode) {
    if (!['wizard', 'setup', 'packages'].includes(mode)) {this.hide(); this.update({mode: null}); return;}
    const changed = mode !== this.state.mode;
    this.hide(); this.update({mode, step: changed && mode === 'wizard' ? 0 : this.state.step, message: ''});
    return this.refresh({initial: mode === 'wizard' && changed});
  }
  chooseStep(step) {
    if (!this.visible() || this.state.mode !== 'wizard' || !Number.isInteger(step) || step < 0 || step >= setupSteps.length) return;
    this.navigation++; this.update({step, navigating: false});
  }
  skip() {
    if (!this.visible() || this.state.mode !== 'wizard') return;
    if (this.state.step === setupSteps.length - 1) this.services.navigate?.('#overview');
    else this.chooseStep(this.state.step + 1);
  }
  async next() {
    if (!this.visible() || this.state.mode !== 'wizard' || this.state.navigating) return;
    const mine = ++this.navigation, step = this.state.step;
    this.update({navigating: true}); await this.refresh();
    if (mine !== this.navigation || !this.visible() || this.state.mode !== 'wizard' || this.state.step !== step) return;
    this.update({navigating: false}); this.skip();
  }
  async refresh({initial = false} = {}) {
    if (!this.visible()) return false;
    this.abort?.abort(); const abort = new AbortController(); this.abort = abort;
    const mine = ++this.generation, navigation = this.navigation, annotation = this.annotationGeneration, mode = this.state.mode;
    this.update({loading: true, status: null, configured: null, message: 'Checking setup status…'});
    const read = async (url, validate) => {
      try {const reply = await this.services.fetch(url, {signal: abort.signal}); if (reply.status !== 200) return null; return validate(await reply.json());} catch {return null;}
    };
    const [status, verification] = await Promise.all([read(setupURL, setupStatus), mode === 'packages' ? null : read(verificationURL, verificationSettings)]);
    if (mine !== this.generation || mode !== this.state.mode || !this.visible() || abort.signal.aborted) return false;
    this.abort = null;
    const changes = {status, loading: false, attention: incompleteCount(status), message: status ? '' : 'Setup status cannot be determined. Re-check when the server is available.'};
    if (annotation === this.annotationGeneration) changes.configured = verification ? verification.mode !== 'off' : null;
    if (initial && navigation === this.navigation) changes.step = firstIncomplete(status);
    this.update(changes); return Boolean(status);
  }
}
