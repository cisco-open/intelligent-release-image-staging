// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {originApplicationConfirmed, originModeLabel, originNextAction, originReasons, originStates} from './origin-enforcement-model.mjs';

const number = value => Number.isSafeInteger(value) && value >= 0 ? value : 'Unavailable';
export function OriginEnforcement({controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const {value, form, preview, busy, committing, ready} = state;
  const heading = useRef(null), apply = useRef(null), wasBusy = useRef(false);
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
    <p className="muted">Apply the saved access rules to transfers from the distribution server. Preview the affected devices and addresses before you approve any blocks.</p>
    <p className="muted" id="origin-refresh-help">The status below is from your last read. Choose Refresh status to check current application.</p>
    <dl className="origin-current" aria-label="Saved distribution settings and confirmed effect">
      <div><dt>Saved mode</dt><dd id="origin-saved-mode">{checked ? originModeLabel(checked.mode) : 'Unavailable'}</dd></div>
      <div><dt>Transfer-service status at last refresh</dt><dd id="origin-application-state" role="status">{checked ? originStates[checked.state] : 'Status unavailable'}</dd></div>
      <div><dt>Approved for blocking</dt><dd id="origin-approved-counts">{checked ? <>{number(checked.approved_device_count)} devices · {number(checked.approved_ip_count)} addresses</> : 'Unavailable'}</dd></div>
      <div><dt>Confirmed at last refresh</dt><dd id="origin-confirmed-counts">{originApplicationConfirmed(checked)
        ? <>{number(checked.applied_device_count)} devices · {number(checked.applied_ip_count)} addresses</> : 'Not confirmed'}</dd></div>
    </dl>
    {checked?.last_verified_at && <p className="muted">Last confirmed by the transfer service: {new Date(checked.last_verified_at * 1000).toLocaleString()}.</p>}
    {checked?.reason && <p className="policy-warning">{originReasons[checked.reason]}</p>}
    {!preview && !busy && !state.reviewRequired && <p className="origin-next"><strong>Next step</strong> {originNextAction(checked, ready, false)}</p>}
    <form onSubmit={event => {event.preventDefault(); start(() => controller.save());}}>
      <div className="origin-change-heading"><h4>Change distribution access</h4><span className="muted">{preview ? 'Preview ready for review' : state.dirty ? 'Draft changes, not saved' : 'Preview before applying'}</span></div>
      <div className="origin-enforcement-fields">
        <label className="field" htmlFor="origin-mode"><span className="field-label">Requested mode</span>
          <select id="origin-mode" value={form.mode} disabled={committing} onChange={event => controller.field('mode', event.target.value)}>
            <option value="preflight">Preview only</option><option value="enforce">Enforce reviewed blocks</option>
          </select></label>
        {[['max_new_ips', 'New address limit'], ['max_new_devices', 'New device limit']].map(([key, label]) => <label className="field" key={key} htmlFor={'origin-' + key}>
          <span className="field-label">{label}</span><input id={'origin-' + key} inputMode="numeric" value={form[key]} autoComplete="off"
            disabled={committing} onChange={event => controller.field(key, event.target.value)} aria-describedby="origin-limit-help" /></label>)}
      </div>
      <p className="muted" id="origin-limit-help">{form.mode === 'enforce'
        ? 'Maximum new blocks you will approve in this change, from 0 to 1000. The preview also includes previously approved blocks.'
        : 'New-block limits apply only when enforcing reviewed blocks.'}</p>
      {preview && <div className="origin-enforcement-preview" id="origin-preview" role="region" aria-label="Distribution access preview">
        <h4>{preview.request.mode === 'enforce' ? 'Proposed blocks' : 'Withdraw approval for reviewed blocks'}</h4>
        <p className="muted">{originModeLabel(preview.request.mode)}. This is a preview, not a saved change.</p>
        {preview.request.mode === 'enforce' && <dl className="policy-counts">
          <div><dt>New devices to block</dt><dd>{number(preview.body.new_device_count)}</dd></div>
          <div><dt>New addresses to block</dt><dd>{number(preview.body.new_ip_count)}</dd></div>
          <div><dt>Address blocks to keep</dt><dd>{number(preview.body.retained_ip_count)}</dd></div>
          <div><dt>Total devices to block</dt><dd>{number(preview.body.proposed_device_count)}</dd></div>
          <div><dt>Total addresses to block</dt><dd>{number(preview.body.proposed_ip_count)}</dd></div>
        </dl>}
        <p>{preview.request.mode === 'enforce' ? 'Applying can disconnect existing distribution transfers from these addresses.' : 'Applying withdraws approval for the reviewed distribution blocks and asks the transfer service to remove them. No new blocks are approved. Quarantine and other sharing restrictions remain.'}</p>
        {!!preview.body.blockers.length && <ul aria-label="Checks to resolve">{preview.body.blockers.map((code, index) => <li key={code + index}>{originReasons[code]}</li>)}</ul>}
      </div>}
      {warning && <p className="policy-warning">{warning}</p>}
      {state.reviewRequired && <p className="policy-warning" role="alert">The last change may have been saved. {originNextAction(checked, ready, true)}</p>}
      <p className={state.failed ? 'err' : 'muted'} id="origin-message" role="status" aria-live="polite">{state.message}</p>
      <div className="role-def-actions">
        <button className="btn" type="submit" id="origin-apply" ref={apply} disabled={disabled || !!preview?.body.blockers.length}>
          {busy ? committing ? 'Saving…' : 'Reviewing…' : preview ? 'Apply reviewed change' : 'Preview change'}</button>
        {preview && <button className="btn ghost" type="button" disabled={committing} onClick={() => start(() => controller.cancel())}>Cancel review</button>}
        <button className="btn ghost" type="button" id="origin-refresh" disabled={busy || state.loading}
          onClick={() => controller.review()}>{state.loading ? 'Refreshing…' : 'Refresh status'}</button>
      </div>
    </form>
    <p className="muted">Blocks apply to IP addresses. Devices allowed and denied access need different addresses; a shared address cannot be blocked for only one device.</p>
  </section>;
}
