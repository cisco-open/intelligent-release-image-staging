// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useEffect, useRef, useState} from 'react';
import {createRoot} from 'react-dom/client';
import {attentionCards, fleetCards, rolloutPercent} from './overview-model.mjs';

const icons = {positive: 'i-check-circle', negative: 'i-octagon-x',
  warning: 'i-triangle-warn', severe: 'i-diamond-severe', inactive: 'i-minus-circle'};
const layouts = {docker: 'Docker · one host', 'docker-split': 'Docker · separate hosts',
  kubernetes: 'Kubernetes', 'single-container': 'Single container', unknown: 'Layout not reported'};

function Deployment({data}) {
  const available = data && !data.unavailable;
  const context = available ? [data.instance && `Instance: ${data.instance}`,
    data.namespace && `Namespace: ${data.namespace}`].filter(Boolean).join(' · ') : '';
  const note = !data ? 'Reading deployment information…' : data.unavailable
    ? 'Deployment information could not be refreshed. Retrying automatically.' : data.note || '';
  return <section className="deployment-panel" aria-labelledby="deployment-heading">
    <div className="deployment-heading">
      <h3 id="deployment-heading">Deployment</h3>
      <span id="deployment-layout" className="deployment-layout">{!data ? 'Loading…'
        : data.unavailable ? 'Unavailable' : layouts[data.layout] || layouts.unknown}</span>
      <span id="deployment-observed" className="muted">{available ? Number.isFinite(data.observed_at)
        ? `Observed ${new Date(data.observed_at * 1000).toLocaleTimeString()}` : 'Observation time unavailable' : ''}</span>
    </div>
    <p id="deployment-context" className="muted" hidden={!context}>{context}</p>
    <div className="table-scroll" id="deployment-table" hidden={!available || !data.components.length}
      tabIndex={0} role="region" aria-label="IRIS containers and pods">
      <table className="tbl deployment-table" aria-label="IRIS containers and pods">
        <thead><tr><th scope="col">Component</th><th scope="col">Host / node</th><th scope="col">Environment</th><th scope="col">State</th></tr></thead>
        <tbody id="deployment-rows">{available && data.components.map((item, index) => <tr key={`${item.role}:${item.name}:${index}`}>
          <td>{item.role === 'server' ? 'Tracker / distribution' : item.role === 'console' ? 'Console' : 'Component'}
            <small>{item.kind === 'pod' ? 'Pod: ' : item.kind === 'container' ? 'Container: ' : 'Runtime: '}{item.name || 'Not reported'}</small></td>
          <td>{item.host || 'Not reported'}{item.address && <small>{item.kind === 'pod' ? 'Pod IP: ' : 'Host address: '}{item.address}</small>}</td>
          <td>{[item.os, item.architecture].filter(Boolean).join(' · ') || (item.kind === 'pod' ? 'Pod container' : 'Container')}
            {(item.image || item.kernel) && <small>{[item.image && `Image: ${item.image}`, item.kernel && `Kernel: ${item.kernel}`].filter(Boolean).join(' · ')}</small>}</td>
          <td>{item.state || 'Not reported'}</td>
        </tr>)}</tbody>
      </table>
    </div>
    <p id="deployment-note" className="muted" role="status" hidden={!note}>{note}</p>
  </section>;
}

function Attention({data}) {
  if (!data) return null;
  return attentionCards(data).map(card => {
    const actionable = card.kind === 'devices' || card.kind === 'images';
    const Tag = actionable ? 'button' : 'div';
    return <Tag key={card.kind} className={`attention-card is-${card.level}`}
      type={actionable ? 'button' : undefined} data-attn={actionable ? card.kind : undefined}
      onClick={actionable ? () => window.dispatchEvent(new CustomEvent('iris:overview-action', {detail: {kind: card.kind}})) : undefined}>
      <svg aria-hidden="true"><use href={`#${icons[card.level] || icons.inactive}`} /></svg>
      <span className="attention-text">{card.count !== undefined && <span className="attention-count">{card.count}</span>}
        <span className="attention-label">{card.label}</span><span className="attention-hint">{card.hint}</span></span>
    </Tag>;
  });
}

function RolloutProgress({row}) {
  const bar = useRef(null);
  const percent = rolloutPercent(row);
  // A CSS property assignment is allowed by the Console's strict style CSP.
  useEffect(() => { bar.current.style.width = `${percent}%`; }, [percent]);
  return <div className="pbar" role="progressbar" aria-valuemin={0} aria-valuemax={100}
    aria-valuenow={percent} aria-label={`${row.image_id} staged`}><span ref={bar} data-pct={percent} /></div>;
}

function Overview() {
  const [state, setState] = useState({});
  useEffect(() => {
    const update = event => setState(previous => ({...previous, ...event.detail}));
    window.addEventListener('iris:overview-state', update);
    return () => window.removeEventListener('iris:overview-state', update);
  }, []);
  const {deployment, attention, overview, telemetry} = state;
  const telemetryClass = telemetry?.state === 'ok' ? 'badge-ok'
    : telemetry?.state === 'degraded' ? 'badge-cancelled' : 'badge-queued';
  return <>
    <div className="page-header"><h2 className="page-title">Network Overview{' '}
      <span id="telemetry-health" className={`badge ${telemetryClass}`} title={telemetry?.detail || ''}
        hidden={!telemetry}>{telemetry && `Telemetry export: ${telemetry.state}`}</span></h2></div>
    <Deployment data={deployment} />
    <div className="ov-band"><h3>Needs attention</h3><div className="attention-cards" id="ov-attention"><Attention data={attention} /></div></div>
    <div className="ov-band"><h3>Fleet totals</h3><div className="cards" id="ov-cards">
      {overview && fleetCards(overview).map(card => <div className="card" key={card.label}>
        <div className="lbl">{card.label}</div><div className="num">{card.number}</div>
        {card.sub && <div className="sub">{card.sub}</div>}
      </div>)}
    </div><h3>Rollout</h3>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Image rollout">
        <table className="tbl" id="ov-rollout"><thead><tr><th scope="col">Image</th><th scope="col">Assigned</th><th scope="col">Staged</th><th scope="col">Progress</th></tr></thead>
          <tbody id="ov-rows">{(overview?.rollout || []).map(row => <tr key={row.image_id}>
            <td className="machine">{row.image_id}</td><td>{row.assigned}</td><td>{row.staged}</td><td><RolloutProgress row={row} /></td>
          </tr>)}</tbody>
        </table>
      </div>
    </div>
  </>;
}

export function mountOverview() {
  const root = document.getElementById('iris-overview-root');
  if (root) createRoot(root).render(<Overview />);
}
