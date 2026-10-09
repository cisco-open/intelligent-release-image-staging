// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useEffect, useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {originReasons, originStates} from './origin-enforcement-model.mjs';

const number = value => Number.isSafeInteger(value) && value >= 0 ? value : 'Unavailable';
export function OriginEnforcement({controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const {value, form, preview, busy, committing, ready} = state;
  const heading = useRef(null), apply = useRef(null), wasBusy = useRef(false);
  useEffect(() => {
    const timer = setInterval(() => {if (!controller.state.loading && !controller.state.busy) controller.refresh();}, 5000);
    return () => clearInterval(timer);
  }, [controller]);
  useLayoutEffect(() => {
    if (wasBusy.current && !busy && controller.visible() && document.activeElement === heading.current
      && preview && !preview.body.blockers.length) apply.current?.focus({preventScroll: true});
    wasBusy.current = busy;
  }, [busy, preview, controller]);
  const start = action => {heading.current?.focus({preventScroll: true}); action();};
  const warning = controller.warning(), disabled = busy || state.externalBusy || !!warning || !ready || state.reviewRequired;
  const checked = ready ? value : null;
  return <section className="origin-enforcement" aria-labelledby="origin-enforcement-title">
    <h3 id="origin-enforcement-title" ref={heading} tabIndex={-1}>Distribution access</h3>
    <p className="muted">Review which devices the distribution service should block. Each approval covers the exact reviewed addresses and policy.</p>
    <dl className="policy-counts">
      <div><dt>Requested mode</dt><dd>{checked ? checked.mode === 'enforce' ? 'Enforce reviewed restrictions' : 'Review only' : 'Unavailable'}</dd></div>
      <div><dt>Application status</dt><dd id="origin-application-state" role="status">{checked ? originStates[checked.state] : 'Status unavailable'}</dd></div>
      <div><dt>Approved devices</dt><dd>{number(checked?.approved_device_count)}</dd></div>
      <div><dt>Applied devices</dt><dd>{number(checked?.applied_device_count)}</dd></div>
    </dl>
    {checked?.last_verified_at && <p className="muted">Last verified by the transfer service: {new Date(checked.last_verified_at * 1000).toLocaleString()}.</p>}
    {checked?.reason && <p className="policy-warning">{originReasons[checked.reason]}</p>}
    <form onSubmit={event => {event.preventDefault(); start(() => controller.save());}}>
      <div className="origin-enforcement-fields">
        <label className="field" htmlFor="origin-mode"><span className="field-label">Mode</span>
          <select id="origin-mode" value={form.mode} disabled={committing} onChange={event => controller.field('mode', event.target.value)}>
            <option value="preflight">Review only</option><option value="enforce">Enforce reviewed restrictions</option>
          </select></label>
        {[['max_new_ips', 'New address limit'], ['max_new_devices', 'New device limit']].map(([key, label]) => <label className="field" key={key} htmlFor={'origin-' + key}>
          <span className="field-label">{label}</span><input id={'origin-' + key} inputMode="numeric" value={form[key]} autoComplete="off"
            disabled={committing} onChange={event => controller.field(key, event.target.value)} aria-describedby="origin-limit-help" /></label>)}
      </div>
      <p className="muted" id="origin-limit-help">Limits apply to new blocks in this review, from 0 to 1000. Previously approved blocks also appear in the preview.</p>
      {preview && <div className="origin-enforcement-preview" id="origin-preview" role="region" aria-label="Distribution access preview">
        <h4>{preview.request.mode === 'enforce' ? 'Review distribution restrictions' : 'Release reviewed distribution restrictions'}</h4>
        <dl className="policy-counts">
          <div><dt>New devices</dt><dd>{number(preview.body.new_device_count)}</dd></div>
          <div><dt>New addresses</dt><dd>{number(preview.body.new_ip_count)}</dd></div>
          <div><dt>Retained addresses</dt><dd>{number(preview.body.retained_ip_count)}</dd></div>
          <div><dt>Total reviewed devices</dt><dd>{number(preview.body.proposed_device_count)}</dd></div>
          <div><dt>Total reviewed addresses</dt><dd>{number(preview.body.proposed_ip_count)}</dd></div>
        </dl>
        <p>{preview.request.mode === 'enforce' ? 'Applying can disconnect existing transfers from these addresses.' : 'Applying releases origin-only blocks. Quarantine and other peer-policy restrictions remain.'}</p>
        {!!preview.body.blockers.length && <ul aria-label="Checks to resolve">{preview.body.blockers.map((code, index) => <li key={code + index}>{originReasons[code]}</li>)}</ul>}
      </div>}
      {warning && <p className="policy-warning">{warning}</p>}
      {state.reviewRequired && <p className="policy-warning" role="alert">The last change may have been saved. Choose Refresh status and review the current settings before trying again.</p>}
      <p className={state.failed ? 'err' : 'muted'} id="origin-message" role="status" aria-live="polite">{state.message}</p>
      <div className="role-def-actions">
        <button className="btn" type="submit" id="origin-apply" ref={apply} disabled={disabled || !!preview?.body.blockers.length}>
          {busy ? committing ? 'Saving…' : 'Reviewing…' : preview ? 'Apply reviewed change' : 'Preview change'}</button>
        {preview && <button className="btn ghost" type="button" disabled={committing} onClick={() => start(() => controller.cancel())}>Cancel review</button>}
        <button className="btn ghost" type="button" id="origin-refresh" disabled={busy || state.loading}
          onClick={() => start(() => controller.refresh(true))}>{state.loading ? 'Refreshing…' : 'Refresh status'}</button>
      </div>
    </form>
    <p className="muted">Address-based blocking cannot separate allowed and denied devices behind the same shared address. Use distinct addresses for those devices.</p>
  </section>;
}
