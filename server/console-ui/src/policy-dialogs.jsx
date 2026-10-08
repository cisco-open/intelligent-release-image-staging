// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useLayoutEffect, useRef} from 'react';
import {policyDiagnostics} from './policy-model.mjs';
import {roleQosFields, rateHint} from './policy-definitions-model.mjs';

const countLabels = [['policy-roles-defined', 'Roles defined'], ['policy-roles-restricted', 'Restricted roles'],
  ['policy-role-drift', 'Role drift'], ['policy-outbox', 'Unacknowledged operations']];
const deliveryLabels = [['policy-issued-revision', 'Highest issued revision'], ['policy-instr-stamp-missing', 'Devices missing an instruction stamp'],
  ['policy-pointer-skew', 'Devices reporting pointer skew'], ['policy-instruction-observed', 'Server observation time']];
const custodyLabels = [['instruction-key-state', 'Custody state'], ['instruction-cert-days', 'Signing certificate remaining'],
  ['instruction-keylist-age', 'Key list age'], ['instruction-root-ceremony', 'Root ceremony'], ['instruction-root-quorum', 'Root quorum'], ['instruction-key-actions', 'Required action']];
const Counts = ({labels, cells}) => <dl className="policy-counts">{labels.map(([id, label]) => <div key={id}><dt>{label}</dt><dd id={id}>{cells[id]}</dd></div>)}</dl>;
const CountList = ({id, rows}) => <ul className="policy-members" id={id}>{rows.map(row => <li key={row.label} className={row.count === undefined ? 'muted' : undefined}>
  {row.count === undefined ? row.label : <><span className="machine">{row.label}</span>: {row.count}</>}</li>)}</ul>;

export function PolicyDialogs({controller, state, disabled}) {
  const wrapper = useRef(null), opener = useRef(null), previous = useRef(null), lastFocus = useRef(null), file = useRef(null);
  const {dialog, editor, form, preview, busy, committing} = state;
  const closeId = dialog === 'editor' ? 'role-def-modal-x' : 'policy-advanced-x';
  useLayoutEffect(() => {
    if (dialog && dialog !== previous.current) {
      if (!previous.current) opener.current = document.activeElement;
      document.getElementById(dialog === 'editor' ? editor.name ? 'rd-restricted' : 'rd-name' : 'policy-advanced-close')?.focus();
    } else if (!dialog && previous.current && controller.visible()) {
      if (opener.current?.isConnected && !opener.current.disabled && opener.current.getClientRects().length) opener.current.focus();
      else document.getElementById('policy-advanced-open')?.focus();
    }
    previous.current = dialog;
  }, [dialog, editor?.name, controller]);
  useLayoutEffect(() => {
    if (dialog === 'editor' && preview && !busy && document.activeElement?.id === 'role-def-modal-x') {
      document.getElementById('role-def-preview')?.scrollIntoView({block: 'nearest'});
      document.getElementById('role-def-save')?.focus({preventScroll: true});
    }
    const lost = lastFocus.current && (!lastFocus.current.isConnected || lastFocus.current.disabled || !lastFocus.current.getClientRects().length);
    if (dialog && controller.visible() && lost && (document.activeElement === document.body || document.activeElement === lastFocus.current)) document.getElementById(closeId)?.focus();
  }, [dialog, busy, disabled, preview, state.definitions, closeId, controller]);
  useLayoutEffect(() => {
    if (!dialog) return;
    const keys = event => {
      if (event.key === 'Escape') {event.preventDefault(); event.stopPropagation(); controller.close();}
      if (event.key !== 'Tab') return;
      const modal = wrapper.current.querySelector('[role="dialog"]:not([hidden])');
      if (!modal) return;
      const nodes = [...modal.querySelectorAll('button:not(:disabled),input:not(:disabled),select:not(:disabled),summary,[tabindex="0"]')].filter(node => node.getClientRects().length);
      const first = nodes[0], last = nodes.at(-1);
      if (!modal.contains(document.activeElement)) {event.preventDefault(); (event.shiftKey ? last : first)?.focus();}
      else if (event.shiftKey && document.activeElement === first) {event.preventDefault(); last?.focus();}
      else if (!event.shiftKey && document.activeElement === last) {event.preventDefault(); first?.focus();}
    };
    document.addEventListener('keydown', keys, true); return () => document.removeEventListener('keydown', keys, true);
  }, [dialog, controller]);
  const diag = policyDiagnostics(state.policy, state.policyOk, controller.services?.formatDate || (value => new Date(value * 1000).toLocaleString()));
  const field = (name, id, label, props = {}) => <label className="field" htmlFor={id}><span className="field-label">{label}</span>
    <input id={id} value={form[name]} disabled={committing} autoComplete="off" spellCheck={false} onChange={event => controller.field(name, event.target.value)} {...props} /></label>;
  const qosFields = rate => roleQosFields.filter(([, , kind]) => (kind === 'rate') === rate).map(([key, label, kind]) => <label className="field" key={key} htmlFor={'rd-qos-' + key}>
    <span className="field-label">{label}{kind !== 'bool' && <> <span className="muted">{kind === 'rate' ? 'bytes/s' : kind}</span></>}</span>
    {kind === 'bool' ? <select id={'rd-qos-' + key} data-qos={key} value={form.qos[key]} disabled={committing} onChange={event => controller.field(key, event.target.value, true)}>
      <option value="">Inherit</option><option value="true">Yes</option><option value="false">No</option></select>
      : <input id={'rd-qos-' + key} data-qos={key} inputMode="numeric" placeholder="inherit" autoComplete="off" value={form.qos[key]} disabled={committing} onChange={event => controller.field(key, event.target.value, true)} />}
    {kind === 'rate' && <span className="muted rate-hint" data-rate-hint={key}>{rateHint(form.qos[key].trim())}</span>}
  </label>);
  const start = action => {document.getElementById(closeId)?.focus(); action();};
  return <div ref={wrapper} onFocusCapture={event => {lastFocus.current = event.target;}}>
    <div id="policy-advanced-modal" className="modal-backdrop" hidden={dialog !== 'advanced'} role="dialog" aria-modal="true" aria-labelledby="policy-advanced-title">
      <div className="modal modal-wide"><div className="modal-head"><span id="policy-advanced-title">Advanced policies</span>
        <button className="btn ghost icon-only" type="button" id="policy-advanced-x" aria-label="Close" onClick={() => controller.close()}>✕</button></div>
        <div className="modal-body">
          <details className="policy-panel" id="peer-policy-panel" open>
            <summary>Peer access and roles <span className="muted" id="peer-policy-summary">{diag.summary}</span></summary>
            <div className="policy-panel-body">
              <Counts labels={countLabels} cells={diag.cells} />
              <p className="muted">Role members in peer policy</p><CountList id="policy-role-members" rows={diag.members} />
              <p id="policy-origin-qos">{diag.origin}</p><p id="policy-mutual-origin">{diag.mutual}</p>
              <h3>Role definitions</h3>
              <p className="muted">Roles a device can be set to, with their peer access and speed limits. Rates are bytes per second (0 = unlimited); a blank field inherits the global default. Import replaces every definition with the file, using the roles API CSV format.</p>
              <div className="role-def-actions">
                <button className="btn" type="button" id="role-def-new" disabled={disabled} onClick={() => controller.open()}>New role…</button>
                <button className="btn ghost" type="button" id="role-def-import" disabled={disabled || state.reviewRequired} onClick={() => file.current?.click()}>Import CSV…</button>
                <button className="btn ghost" type="button" id="role-def-export" disabled={busy || state.downloading || !!controller.capability()} onClick={() => start(() => controller.exportCsv())}>Export CSV</button>
                <input type="file" id="role-def-file" ref={file} accept=".csv,text/csv" hidden onChange={event => {const selected = event.target.files[0]; event.target.value = ''; start(() => controller.importFile(selected));}} />
                <button className="btn ghost" type="button" disabled={busy} onClick={() => start(() => controller.refresh(true))}>Refresh policies</button>
              </div>
              <div className="table-scroll" role="region" aria-label="Role definitions table" tabIndex={0}>
                <table className="tbl dense role-def-table" aria-label="Role definitions"><thead><tr>{['Role', 'Restricted', 'Peer roles', 'Origin', 'Networks', 'QoS overrides', 'Actions'].map(label => <th key={label}>{label}</th>)}</tr></thead>
                  <tbody id="role-def-rows">{!state.definitionsOk ? <tr><td colSpan={7} className="muted">{state.readError || 'Role definitions unavailable.'}</td></tr>
                    : !Object.keys(state.definitions).length ? <tr><td colSpan={7} className="muted">No roles defined. Choose New role, or import a roles CSV.</td></tr>
                      : Object.keys(state.definitions).sort().map(name => {const d = state.definitions[name], peers = (d.peers || []).filter(peer => peer !== name); return <tr key={name}>
                        <td className="machine">{name}</td><td>{d.restricted ? 'yes' : 'no'}</td><td className="machine">{peers.join(', ') || <span className="muted">only itself</span>}</td>
                        <td>{d.origin === false ? 'no' : 'yes'}</td><td className="machine">{d.nets?.join(', ') || '—'}</td>
                        <td className="qos">{Object.keys(d.qos || {}).length ? Object.entries(d.qos).map(([key, value]) => <span key={key} className="machine qos-chip">{key}={String(value)}</span>) : <span className="muted">inherit</span>}</td>
                        <td><button className="linkish role-def-edit" type="button" data-role={name} disabled={disabled} onClick={() => controller.open(name)}>Edit</button> · <button className="linkish danger-link role-def-delete" type="button" data-role={name} disabled={disabled || state.reviewRequired} onClick={() => start(() => controller.delete(name))}>Delete</button></td>
                      </tr>;})}</tbody></table>
              </div>
              <p className={'role-message' + (state.failed ? ' err' : '')} id="role-def-status" role="status" aria-live="polite">{state.message}</p>
              <p className="muted" role="status">{state.downloadMessage}</p>
              <details className="policy-diagnostics"><summary>Instruction delivery and key custody</summary>
                <h3>Instruction delivery</h3><Counts labels={deliveryLabels} cells={diag.instruction.cells} />
                <p className="muted">Reported applied policy revisions — agent-asserted</p><CountList id="policy-applied-revisions" rows={diag.instruction.applied} />
                <p className="muted">Primary instruction states — mixed evidence; old reports remain in the fleet denominator</p><CountList id="policy-instruction-states" rows={diag.instruction.states} />
                <h3>Instruction key custody</h3><Counts labels={custodyLabels} cells={diag.instruction.cells} />
                <ul className="policy-members" aria-label="Evidence sources">
                  <li><strong>Server-observed:</strong> report age, origin and tracker observations, durable revocation and key custody, and missing instruction stamps.</li>
                  <li><strong>Device-authored:</strong> announce upload and download counters reported by the transfer client.</li>
                  <li><strong>Agent-asserted:</strong> instruction identity and state, applied options, QoS drift, and pointer skew.</li>
                </ul>
                <p className="muted"><code>violation = 0 does not mean compliant</code>. Application is the latest report, not verified compliance or proof of current device state.</p>
                <p className="muted">Device role assignments appear in Inventory. Drift counts differences from peer policy. An explicit ACL assignment shadows a role. Global QoS defaults and tracker <code>qos_state</code> remain available through the API.</p>
              </details>
            </div>
          </details>
        </div><div className="modal-foot"><button className="btn ghost" type="button" id="policy-advanced-close" onClick={() => controller.close()}>Close</button></div>
      </div>
    </div>
    <div id="role-def-modal" className="modal-backdrop" hidden={dialog !== 'editor'} role="dialog" aria-modal="true" aria-labelledby="role-def-modal-title" aria-describedby="role-def-modal-help">
      <form className="modal modal-wide role-def-modal" onSubmit={event => {event.preventDefault(); start(() => controller.save());}}>
        <div className="modal-head"><span id="role-def-modal-title">{editor?.name ? 'Edit role ' + editor.name : 'New role'}</span>
          <button className="btn ghost icon-only" type="button" id="role-def-modal-x" aria-label="Close" onClick={() => controller.close()}>✕</button></div>
        <div className="modal-body">
          <p id="role-def-modal-help">Choose sharing permissions, then preview before saving. Both roles must allow sharing.</p>
          <div className="role-def-grid">
            {field('name', 'rd-name', <>Role name <span className="muted">a–z, 0–9, . _ - (max 32)</span></>, {maxLength: 32, placeholder: 'e.g. boat', disabled: !!editor?.name || committing})}
            {field('peers', 'rd-peers', <>Can share with these roles <span className="muted">comma separated; same role always allowed</span></>, {placeholder: 'e.g. fiber', disabled: !form.restricted || committing})}
            <label className="check-row"><input type="checkbox" id="rd-restricted" checked={form.restricted} disabled={committing} onChange={event => controller.field('restricted', event.target.checked)} /> Limit sharing to these roles</label>
            <label className="check-row"><input type="checkbox" id="rd-origin" checked={form.origin} disabled={!form.restricted || committing} onChange={event => controller.field('origin', event.target.checked)} /> Allow the distribution server</label>
          </div>
          <p className="muted">Without a sharing limit, this role allows all roles and the distribution server. Other roles still need to allow it.</p>
          <details id="role-editor-advanced" key={editor?.key} className="policy-diagnostics">
            <summary>Advanced — speed limits and agent settings</summary><div className="role-def-grid">
              {field('nets', 'rd-nets', <>Networks <span className="muted">IPv4 prefixes, comma separated</span></>, {placeholder: 'e.g. 10.20.0.0/16'})}
              <label className="field" htmlFor="rd-on-stale"><span className="field-label">When instructions expire</span>
                <select id="rd-on-stale" value={form.onStale} disabled={committing} onChange={event => controller.field('onStale', event.target.value)}>
                  <option value="">Inherit (keep for restricted, defaults otherwise)</option><option value="keep">Keep the last verified QoS</option><option value="defaults">Fall back to defaults</option>
                </select></label></div>
            <h4>Speed limits <span className="muted">bytes per second · 0 = unlimited · otherwise at least 8192 · blank = inherit</span></h4><div className="role-def-grid" id="rd-rates">{qosFields(true)}</div>
            <h4>Swarm and agent cadence <span className="muted">blank = inherit</span></h4><div className="role-def-grid" id="rd-swarm">{qosFields(false)}</div>
          </details>
          {controller.capability() && <p className="err" role="status">{controller.capability()}</p>}
          <p className="role-preview" id="role-def-preview" aria-live="polite" hidden={!preview}>{preview?.text}</p>
          <p className="role-message" id="role-def-msg" role="status" aria-live="polite">{state.formMessage}</p>
          {(editor?.stale || state.reviewRequired) && <button className="btn ghost" type="button" disabled={busy || state.loading} onClick={() => start(() => controller.reloadEditor())}>Reload current definition</button>}
        </div><div className="modal-foot"><button className="btn ghost" type="button" id="role-def-cancel" onClick={() => controller.close()}>Cancel</button>
          <button className="btn" type="submit" id="role-def-save" disabled={busy || state.externalBusy || !!controller.capability() || editor?.stale || state.reviewRequired}>{busy ? 'Working…' : preview ? 'Save role' : 'Preview change'}</button></div>
      </form>
    </div>
  </div>;
}
