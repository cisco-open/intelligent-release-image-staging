// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {Component, Fragment, useEffect, useLayoutEffect, useRef, useState, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {SwarmMapController} from './swarm-map-controller.mjs';
import {eventsLink, peerKey, peerName, peerModel, peerCaption, peerRowLabel, otherImage, imageState, peerTlsLabel, peerStatus, freshServerPeer, freshPeerEdges, edgeLabel, rate, age, filteredPeers, sortedPeers} from './swarm-map-model.mjs';
import {graphCenter, position, transferPath, spokeLine, initialView, zoomView, panView, viewTransform} from './swarm-map-graph.mjs';
import './swarm-map.css';

const shown = value => value === null || value === undefined ? '—' : String(value);
const yesNo = value => value === true ? 'yes' : value === false ? 'no' : 'not directly reported';
function Rows({rows}) {return <dl>{rows.map(([label, value], index) => <Fragment key={index}><dt>{label}</dt><dd>{shown(value)}</dd></Fragment>)}</dl>;}
function Section({title, rows, children}) {return <section><h3>{title}</h3>{rows && <Rows rows={rows} />}{children}</section>;}

function PeerDetails({peer: p, data, now}) {
  const tracker = p.tracker || {}, observation = p.server_observation?.peer, device = p.device_observation, report = p.latest_report, policy = p.peer_policy, enforcement = p.peer_enforcement;
  const deviceRows = otherImage(p, device) ? [['Status', 'Latest device observation is for another image'], ['Image', device.image_id]]
    : device ? [...(device.image_id ? [['Image', device.image_id]] : []), ['State', device.obs_state || 'observed'], ['Counts as current', device.valid === true ? 'yes' : 'no'], ['Age', device.age_s == null ? '—' : device.age_s + 's'], ['Receive rate', rate(device.receive_bps)]] : [['Status', 'unavailable']];
  deviceRows.push(['Requested interval', p.peer_telemetry?.requested_interval_s == null ? 'unavailable' : p.peer_telemetry.requested_interval_s + 's'], ['Reported interval', p.peer_telemetry?.effective_interval_s == null ? 'No fresh interval reported' : p.peer_telemetry.effective_interval_s + 's']);
  const reportRows = otherImage(p, report) ? [['Status', 'Latest device report is for another image'], ['Image', report.image_id]]
    : report ? [...(report.image_id ? [['Image', report.image_id]] : []), ['Schema', report.schema || 'v1'], ['Event', report.event || '—'], ['Content SHA-256', report.content_sha256_state || 'not reported'], ['Device copy verification', report.ios_copy_verify_state || 'not reported'], ['Report id', report.report_id || '—'], ['Received', age(report.received_at, now)]] : [['Status', 'unavailable']];
  const imageIds = [...new Set([...(p.staged_image_ids || []), ...(p.errored_image_ids || []), ...(p.current_image_id ? [p.current_image_id] : [])])];
  const image = data?.images.find(row => row.info_hash === p._hash);
  const transfers = freshPeerEdges(data, now, p._hash).filter(edge => edge.source_device_id === p.device_id || edge.target_device_id === p.device_id);
  const connectionRows = transfers.map(edge => [edge.source_device_id + ' → ' + edge.target_device_id, rate(edge.bytes_per_second) + ' · ' + age(edge.received_at, now) + ' · reported by ' + edge.reporter_device_id + (edge.identity_basis === 'tracker_endpoint' ? ' · tracker endpoint match' : ' · unique tracker address match')]);
  if (image?.peer_edges_truncated) connectionRows.push(['Coverage', 'Some peer observations were truncated']);
  if (image?.unattributed_peer_connections) connectionRows.push(['Unmatched observations', image.unattributed_peer_connections + ' connections in this swarm have no unique device match']);
  return <div id="peer-details"><h2>{peerName(p)}</h2>
    {tracker.principal_type === 'legacy' && <p className="warn">Warning: no per-device quarantine is available; identity is not inferred from IP.</p>}
    {peerModel(p) && <p className="sub">Model: {peerModel(p)}</p>}{p.ip && <p className="sub">Announce IP: {p.ip}</p>}
    <Section title="Tracker" rows={[
      ['Image', p._img || p._hash || 'unknown'], ['Role', tracker.role || 'unknown'], ['Last seen', age(tracker.last_seen, now)],
    ]} />
    <Section title="Server observation" rows={observation ? [['Measured server → peer', rate(observation.send_bps)], ...(observation.aggregated_connections ? [['Note', observation.aggregated_connections + ' connections from this address, summed']] : []), ['Observed', age(observation.observed_at ?? data?.server?.server_observation?.observed_at, now)]] : [['Status', 'unavailable']]} />
    <Section title="Device observation" rows={deviceRows} />
    <Section title="Device-to-device transfers" rows={connectionRows.length ? connectionRows : [['Status', 'No fresh matched transfers reported']]} />
    <Section title="Torrent TLS" rows={[
      ['Daemon policy', peerTlsLabel(p, now)], ['Configured', p.peer_tls?.configured_mode || 'unknown'], ['Reported', age(p.peer_tls?.reported_at, now)],
    ]} /><p className="sub">Last reported daemon policy; negotiated connection encryption is not measured here.</p>
    <Section title="Image staging" rows={imageIds.length ? imageIds.map(id => [id, imageState(p, id)]) : [['Status', 'no image staging state reported']]} /><p className="sub">All image states last reported by this device.</p>
    <Section title="Latest report" rows={reportRows} />
    <Section title="Policy intent" rows={policy ? [['Decision', policy.decision || 'not directly reported'], ['Quarantined intent', yesNo(policy.quarantined)], ['Fail closed', yesNo(policy.fail_closed)]] : [['Status', 'not directly reported']]} />
    <Section title="Enforcement" rows={enforcement ? [['State', enforcement.state || 'not directly reported'], ['Blocked', enforcement.blocked === false ? 'no / not globally applied' : yesNo(enforcement.blocked)], ...(enforcement.conflict ? [['Conflict', enforcement.conflict.reason || 'reported'], ['Global block applied', yesNo(enforcement.conflict.global_block_applied)]] : [])] : [['Status', 'not directly reported']]} />
  </div>;
}
function HubDetails({data, now}) {
  const observation = data.server?.server_observation || {}, global = observation.global || {};
  return <div id="hub-details"><h2>{data.server?.host || 'Origin server'}</h2><Section title="Server observation" rows={[
    ['RPC', observation.rpc_up === true ? 'up' : 'unavailable'], ['Observed', age(observation.observed_at, now)], ['Upload rate', rate(global.send_bps)], ['Download rate', rate(global.receive_bps)], ['Connections', global.connections],
  ]} /><Section title="Torrent TLS" rows={[
    ['Daemon policy', peerTlsLabel({peer_tls: observation.peer_tls}, now)], ['Observed', age(observation.peer_tls?.reported_at, now)],
  ]} /><p className="sub">Daemon policy; negotiated connection encryption is not measured here.</p></div>;
}
function HistoricalReports({reports, message, loading}) {
  const report = reports.at(-1);
  return <div id="repbox" aria-busy={loading || undefined}>{message && <p role="status">{message}</p>}{report ? <Section title="Historical participation">
    {report.peers?.length ? <table><thead><tr><th>Evidence</th><th>Participant</th></tr></thead><tbody>{report.peers.map((row, index) => <tr key={index}><td>Historical participation / observed by this device</td><td>{typeof row === 'object' ? shown(row.ip || 'unknown participant') : row}</td></tr>)}</tbody></table> : <p>No participant rows in this report.</p>}
    <p className="sub">Image: {report.image_id || 'not reported'} · {report.schema || 'v1'} report; participation only, not bytes or transfer direction.</p>
  </Section> : !message && <p>{loading ? 'Loading historical participation…' : 'No full report received yet.'}</p>}</div>;
}

function Graph({peers, data, now, imageHash, view, setView, open}) {
  const pointer = useRef(null), [panning, setPanning] = useState(false), dense = peers.length > 40;
  const nodes = peers.map((peer, index) => ({peer, key: peerKey(peer), ...position(index)}));
  const byDevice = new Map();
  for (const node of nodes) if (node.peer.tracker.principal_type === 'device') byDevice.set(JSON.stringify([node.peer._hash, node.peer.device_id]), node);
  const activate = (event, key) => {if (event.type === 'click' || event.key === 'Enter' || event.key === ' ') {event.preventDefault(); open(key, event.currentTarget);}};
  const endPan = event => {pointer.current = null; setPanning(false); try {event.currentTarget.releasePointerCapture(event.pointerId);} catch { /* Capture may already have ended. */ }};
  return <svg id="svg" className={panning ? 'panning' : undefined} viewBox="0 0 1000 650" aria-label="Swarm topology"
    onPointerDown={event => {if (event.button !== 0 || event.target.closest('.node,.peer-transfer')) return; pointer.current = {x: event.clientX, y: event.clientY, view}; setPanning(true); event.currentTarget.setPointerCapture(event.pointerId);}}
    onPointerMove={event => {if (!pointer.current) return; setView(panView(pointer.current.view, {x: event.clientX - pointer.current.x, y: event.clientY - pointer.current.y}, event.currentTarget.getBoundingClientRect()));}}
    onPointerUp={endPan} onPointerCancel={endPan} onLostPointerCapture={() => {pointer.current = null; setPanning(false);}}>
    <defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10z" fill="#52A62B" /></marker><marker id="peer-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10z" fill="#4EA1FF" /></marker></defs>
    <g id="scene" transform={viewTransform(view)}>
      {freshPeerEdges(data, now, imageHash).map((edge, index) => {
        const source = byDevice.get(JSON.stringify([edge._hash, edge.source_device_id])), target = byDevice.get(JSON.stringify([edge._hash, edge.target_device_id]));
        if (!source || !target) return null;
        const path = transferPath(source, target); if (!path) return null;
        const label = edgeLabel(edge, now);
        return <path key={JSON.stringify([edge._hash, edge.source_device_id, edge.target_device_id, edge.reporter_device_id, index])} d={path} className="edge peer-transfer" markerEnd="url(#peer-arrow)" role="button" tabIndex={0} aria-label={label} data-received-at={edge.received_at} data-valid-for-s={Math.min(120, edge.valid_for_s ?? 120)} onClick={event => activate(event, target.key)} onKeyDown={event => activate(event, target.key)}><title>{label}</title></path>;
      })}
      {nodes.map(node => {
        const measured = freshServerPeer(node.peer, data, now);
        return <g key={node.key + '-spoke'}><line {...spokeLine(node)} className={measured ? 'edge measured' : 'edge'} markerEnd={measured ? 'url(#arrow)' : undefined} />{measured && !dense && <text x={(graphCenter.x + node.x) / 2} y={(graphCenter.y + node.y) / 2} className="small edge-rate">{rate(measured.send_bps)}</text>}</g>;
      })}
      <g className="node" role="button" tabIndex={0} aria-label="Open origin server observations" onClick={event => activate(event, 'hub')} onKeyDown={event => activate(event, 'hub')}><circle cx={graphCenter.x} cy={graphCenter.y} r="34" fill="#302815" stroke="#CC8604" /><text x={graphCenter.x} y={graphCenter.y + 5} className="label">ORIGIN</text></g>
      {nodes.map(node => <g key={node.key} className="node" role="button" tabIndex={0} aria-label={'Open ' + peerCaption(node.peer) + ' details'} onClick={event => activate(event, node.key)} onKeyDown={event => activate(event, node.key)}>
        <circle cx={node.x} cy={node.y} r="25" fill="#14213A" stroke={node.peer.tracker.role === 'seeder' ? '#CC8604' : '#4EA1FF'} /><text x={node.x} y={node.y + 4} className="label">{node.peer.tracker.role === 'seeder' ? 'SEED' : 'DL'}</text>
        {!dense && <><text x={node.x} y={node.y + 43} className="small">{peerName(node.peer)}</text>{peerModel(node.peer) && <text x={node.x} y={node.y + 56} className="small">{peerModel(node.peer)}</text>}</>}
      </g>)}
    </g>
  </svg>;
}

export function SwarmMap({controller: c, config}) {
  const s = useSyncExternalStore(c.subscribe, c.snapshot);
  const [imageHash, setImageHash] = useState('all'), [query, setQuery] = useState(''), [attention, setAttention] = useState('');
  const [sort, setSort] = useState({column: 'name', direction: 1}), [view, setView] = useState(initialView);
  const drawer = useRef(null), opener = useRef(null), focused = useRef(null), wasOpen = useRef(false), images = useRef([]), lastPeer = useRef(null);
  const openDrawer = s.selected !== null;
  if (s.data) images.current = s.data.images;
  const peer = c.selectedPeer(); if (peer) lastPeer.current = peer;
  const controlPeer = peer || (lastPeer.current && peerKey(lastPeer.current) === s.selected ? lastPeer.current : null);
  const isDevice = controlPeer?.tracker.principal_type === 'device' && Boolean(controlPeer.device_id);
  const actions = isDevice ? c.actionsFor(controlPeer.device_id) : null;
  const eventsUrl = peer ? eventsLink(config.eventsUrlTemplate, peer) : null;
  useEffect(() => {if (s.data && imageHash !== 'all' && !s.data.images.some(row => row.info_hash === imageHash)) setImageHash('all');}, [s.data, imageHash]);
  useEffect(() => {
    const visibility = () => c.setDocumentHidden(document.hidden);
    const message = event => {if (event.origin === location.origin && event.source === window.parent && (event.data === 'MAP_PAUSE' || event.data === 'MAP_RESUME')) c.setHostPaused(event.data === 'MAP_PAUSE');};
    document.addEventListener('visibilitychange', visibility); window.addEventListener('message', message); c.start();
    if (window.parent !== window) window.parent.postMessage('MAP_READY', location.origin);
    return () => {document.removeEventListener('visibilitychange', visibility); window.removeEventListener('message', message); c.stop();};
  }, [c]);
  useLayoutEffect(() => {
    if (openDrawer && !wasOpen.current) drawer.current?.querySelector('#close')?.focus();
    if (!openDrawer && wasOpen.current) {if (opener.current?.isConnected) opener.current.focus(); else document.getElementById('imgsel')?.focus();}
    wasOpen.current = openDrawer;
  }, [openDrawer]);
  useLayoutEffect(() => {
    const node = focused.current;
    if (!openDrawer || !node || (!node.disabled && node.isConnected) || (document.activeElement !== document.body && document.activeElement !== node)) return;
    const id = ['peer-interval', 'save-peer-interval', 'review-peer-interval'].includes(node.id) ? 'peer-interval-status' : 'pullstatus';
    (drawer.current?.querySelector('#' + id) || drawer.current?.querySelector('#close'))?.focus();
  }, [s, openDrawer]);
  const open = (key, node) => {opener.current = node; c.select(key);};
  const drawerKey = event => {
    if (event.key === 'Escape') {event.preventDefault(); c.close(); return;}
    if (event.key !== 'Tab') return;
    const nodes = [...drawer.current.querySelectorAll('button,[href],input,select,[tabindex]:not([tabindex="-1"])')].filter(node => !node.disabled && !node.hidden && node.getClientRects().length);
    const first = nodes[0], last = nodes.at(-1);
    if (event.shiftKey && (document.activeElement === first || !nodes.includes(document.activeElement))) {event.preventDefault(); last?.focus();}
    else if (!event.shiftKey && (document.activeElement === last || !nodes.includes(document.activeElement))) {event.preventDefault(); first?.focus();}
  };
  const peers = filteredPeers(s.data, {imageHash, query, attention}, s.now), sorted = sortedPeers(peers, sort, s.now);
  const suffix = s.lastUpdated === null ? '' : ' Updated ' + Math.max(0, Math.round(Date.now() / 1000 - s.lastUpdated)) + 's ago';
  const stateText = s.paused || s.hostPaused || s.documentHidden ? 'Paused.' + suffix : s.data ? (s.data.server?.server_observation?.rpc_up === false ? 'RPC unavailable; tracker peers may remain.' : 'Live.') + suffix : s.loading && !s.loadFailed ? 'Initial loading…' : 'Unavailable/retrying in ' + s.backoff + 's.';
  const emptyText = !s.data ? s.loadFailed ? 'Swarm data unavailable — retrying.' : 'Initial loading…' : query || attention || imageHash !== 'all' ? 'No participants match the current filter.' : 'No active tracker participants.';
  const sortButton = (column, label) => <th aria-sort={sort.column === column ? sort.direction > 0 ? 'ascending' : 'descending' : undefined}><button className="sortbtn" data-sort={column} onClick={() => setSort(current => ({column, direction: current.column === column ? -current.direction : 1}))}>{label}</button></th>;
  return <><header inert={openDrawer || undefined} aria-hidden={openDrawer || undefined}><div><h1>IRIS Swarm Map</h1><div className="sub">Live tracker participation and explicitly sourced observations</div></div><div className="spacer" />
    <label className="map-control"><span className="control-label">Image</span><select id="imgsel" aria-label="Image filter" value={imageHash} onChange={event => setImageHash(event.target.value)}><option value="all">All images</option>{images.current.map(row => <option key={row.info_hash} value={row.info_hash}>{row.image || row.info_hash}</option>)}</select></label>
    <label className="map-control"><span className="control-label">Find participant</span><input id="peerfind" type="search" placeholder="Find device, model, or IP" value={query} onChange={event => setQuery(event.target.value)} /></label>
    <label className="map-control"><span className="control-label">Status</span><select id="attention" aria-label="Attention filter" title="Needs attention includes stale or unavailable telemetry, errors, quarantine intent or unattributed peers. Finished staging alone is not flagged." value={attention} onChange={event => setAttention(event.target.value)}><option value="">All states</option><option value="attention">Needs attention</option></select></label>
    <span className="zoomctl"><button id="zoom-out" title="Zoom out" aria-label="Zoom out" onClick={() => setView(current => zoomView(current, current.zoom / 1.25))}>−</button><button id="zoom-in" title="Zoom in" aria-label="Zoom in" onClick={() => setView(current => zoomView(current, current.zoom * 1.25))}>+</button><button id="fit" title="Reset pan and zoom" aria-label="Reset pan and zoom" onClick={() => setView(initialView())}>fit</button></span>
    <button id="pause" onClick={() => c.togglePause()}>{s.paused ? 'Resume' : 'Pause'}</button><span id="state" role="status" aria-live="polite">{stateText}</span>
  </header><main id="wrap" inert={openDrawer || undefined} aria-hidden={openDrawer || undefined}>
    <Graph peers={peers} data={s.data} now={s.now} imageHash={imageHash} view={view} setView={setView} open={open} />
    <div id="empty" role="status" aria-live="polite" hidden={peers.length > 0}>{emptyText}</div>
    <div className="legend"><span><b>Gray spoke</b> = tracker participation/layout only; not a measured transfer path.</span><span><b className="g">Green arrow</b> = fresh measured server → peer send rate.</span><span><b className="p">Blue arrow</b> = device-reported peer transfer. Select a device for speed and age.</span><span><b>Images</b> = as last reported by the device; a new assignment shows up after its next heartbeat.</span></div>
    <div id="peerwrap" tabIndex={0} role="region" aria-label="Tracker participant table"><table id="peertable"><caption>Current filtered tracker participants</caption><thead><tr>{sortButton('name', 'Participant')}<th>Image</th>{sortButton('model', 'Model')}{sortButton('role', 'Tracker role')}{sortButton('status', 'Status')}</tr></thead><tbody>{sorted.map(row => <tr key={peerKey(row)}><td><button onClick={event => open(peerKey(row), event.currentTarget)}>{peerRowLabel(row)}</button></td><td>{row._img || row._hash || '—'}</td><td>{peerModel(row) || '—'}</td><td>{row.tracker?.role || 'unknown'}</td><td>{peerStatus(row, s.now)}</td></tr>)}</tbody></table></div>
  </main><aside id="drawer" ref={drawer} className={openDrawer ? 'open' : undefined} hidden={!openDrawer} role="dialog" aria-modal="true" aria-label="Participant details" aria-hidden={!openDrawer} onKeyDown={drawerKey} onFocusCapture={event => {focused.current = event.target;}}>
    <button id="close" onClick={() => c.close()}>Close</button>
    {s.selected === 'hub' ? s.data ? <HubDetails data={s.data} now={s.now} /> : <div id="hub-details">Swarm data unavailable.</div> : peer ? <PeerDetails peer={peer} data={s.data} now={s.now} /> : <div id="peer-details">{s.data ? 'Participant no longer present in the latest tracker snapshot.' : 'Swarm data unavailable.'}</div>}
    {eventsUrl && <div className="drawer-actions"><a id="events-link" className="map-button" href={eventsUrl} target="_blank" rel="noopener noreferrer">Events</a></div>}
    {s.selected !== 'hub' && config.pull && isDevice && actions ? <>
      <Section title="Peer telemetry"><label className="drawer-field" htmlFor="peer-interval">Reporting interval<select id="peer-interval" value={actions.interval.draft} disabled={!c.canInterval()} onChange={event => c.setIntervalDraft(event.target.value)}><option value="60">60 seconds (default)</option><option value="10" disabled={controlPeer.peer_telemetry?.supported !== true}>10 seconds</option></select></label>
        <div className="drawer-actions"><button id="save-peer-interval" disabled={!c.canInterval()} onClick={() => c.saveInterval()}>Save interval</button><button id="review-peer-interval" disabled={!c.canReviewInterval()} onClick={() => c.reviewInterval()}>Review current interval</button></div>
        <p className="sub">Applies to this device. Faster reporting uses more telemetry bandwidth. Resource limits and pause settings take precedence.</p>{controlPeer.peer_telemetry?.supported !== true && <p className="sub">Update the device agent to enable 10-second reporting.</p>}
        <p id="peer-interval-status" role="status" aria-live="polite" tabIndex={-1}>{actions.interval.message}</p>
      </Section><div className="drawer-actions"><button id="pullbtn" disabled={!c.canPull()} onClick={() => c.requestPull()}>Pull fresh data from device</button><button id="review-pull" disabled={!c.canReviewPull()} onClick={() => c.reviewPull()}>Review report request</button></div>
      <p id="pullstatus" role="status" aria-live="polite" tabIndex={-1}>{actions.pull.message}</p><HistoricalReports reports={s.reports} message={s.reportMessage} loading={s.reportsLoading} />
    </> : s.selected && s.selected !== 'hub' && <p className="sub">{controlPeer?.device_id ? 'Fresh report pull is unavailable.' : 'No device identity; fresh report pull is unavailable.'}</p>}
    {config.pull && s.sessionError && <p className="warn" role="status">Session unavailable. Sign in again, then reload the map.</p>}
  </aside></>;
}
class MapBoundary extends Component {
  state = {failed: false};
  static getDerivedStateFromError() {return {failed: true};}
  render() {return this.state.failed ? <p className="map-error" role="alert">The Swarm map could not be displayed. Reload to retry.</p> : this.props.children;}
}
export function mountSwarmMap() {
  const root = document.getElementById('iris-swarm-map-root'); if (!root) throw Error('Swarm map mount point missing');
  const config = window.IRIS_MAP_CFG || {swarmUrl: '/swarm', pull: false};
  const controller = new SwarmMapController(config, {fetch: window.fetch.bind(window), now: () => Date.now(), confirm: message => window.confirm(message), setTimeout: window.setTimeout.bind(window), clearTimeout: window.clearTimeout.bind(window), embedded: window.parent !== window, documentHidden: document.hidden});
  window.irisSwarmMap = controller;
  createRoot(root).render(<MapBoundary><SwarmMap controller={controller} config={controller.config} /></MapBoundary>);
  return controller;
}
mountSwarmMap();
