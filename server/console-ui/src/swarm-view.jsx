// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {SwarmViewController} from './swarm-view-controller.mjs';

function SwarmView({controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot), summary = state.summary;
  return <>
    <div className="page-header"><h2 className="page-title">Swarm</h2></div>
    <p className="muted" id="swarm-summary" role="status" aria-live="polite">
      {state.error ? 'Swarm data unavailable.' : summary
        ? `${summary.entries} image-peer entries. A device can appear under more than one image.` : 'Loading swarm data…'}
      {summary?.seederUnavailable && ' Seeder telemetry unavailable; tracker peers are still listed.'}
    </p>
    <p className="legacy-warning" id="legacy-peer-warning" hidden={!summary?.legacy} role="status" aria-live="polite">
      {summary?.legacy ? `${summary.legacy} unattributed image-peer entries cannot be individually quarantined until personalized torrent refresh.` : ''}
    </p>
    {state.started && <iframe id="swarm-frame" className="swarm-frame" title="Live swarm map" src="/swarmmap"
      ref={frame => controller.attachFrame(frame)} onLoad={() => controller.syncVisibility()} />}
    <p><a className="btn ghost" id="swarm-open" href="/swarmmap" target="_blank" rel="noopener noreferrer">Open the swarm map full-screen ↗</a></p>
  </>;
}

export function mountSwarmView() {
  const root = document.getElementById('iris-swarm-root'); if (!root) throw Error('Swarm mount point missing');
  const controller = new SwarmViewController(); window.irisSwarmView = controller;
  createRoot(root).render(<SwarmView controller={controller} />); return controller;
}
