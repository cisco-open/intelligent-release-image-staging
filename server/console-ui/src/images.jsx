// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useEffect, useLayoutEffect, useRef, useState, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {ImagesController} from './images-controller.mjs';
import {formatDate, formatSize, imageVerdicts, verificationDetail} from './image-model.mjs';

const icons = {positive: 'i-check-circle', negative: 'i-octagon-x', warning: 'i-triangle-warn', inactive: 'i-minus-circle'};

function Verdict({image}) {
  return imageVerdicts(image.hash_verification, image.quarantined).map(verdict => <span key={verdict.label}
    className={`status-pill is-${verdict.level}`} title={verdict.label === 'Deferred by Cisco' ? verdict.label : undefined}>
    <svg aria-hidden="true"><use href={`#${icons[verdict.level]}`} /></svg>{verdict.label}
  </span>);
}

function UploadRow({row, controller}) {
  const bar = useRef(null);
  useEffect(() => { bar.current.style.width = `${row.percent}%`; }, [row.percent]);
  return <div className="upload-row">
    <span className="up-name" title={row.name}>{row.name}</span>
    <div className="progress" role="progressbar" aria-valuemin={0} aria-valuemax={100}
      aria-valuenow={Math.round(row.percent)} aria-label={`${row.name} upload progress`}><div className="bar" ref={bar} /></div>
    <span className={`up-state muted${row.error ? ' err' : ''}`} role="status" aria-live="polite">{row.text}</span>
    <button type="button" className="linkish up-dismiss" title="Dismiss" aria-label={`Dismiss ${row.name}`}
      hidden={!row.done} onClick={() => controller.dismissUpload(row.id)}>×</button>
  </div>;
}

function Images({controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const [drag, setDrag] = useState(false);
  const file = useRef(null), close = useRef(null), opener = useRef(null), wasOpen = useRef(false);
  const details = state.details, image = details?.image || {};
  const images = state.attentionOnly ? state.images.filter(item => !!item.quarantined) : state.images;
  const visible = () => !document.getElementById('view-images')?.hidden;
  useLayoutEffect(() => {
    if (visible() && details) close.current?.focus();
    else if (visible() && wasOpen.current) {
      if (opener.current?.isConnected) opener.current.focus();
      else document.getElementById('images-filter-attention')?.focus();
    }
    wasOpen.current = !!details;
  }, [details?.generation]);
  useEffect(() => {
    const escape = event => { if (event.key === 'Escape' && visible() && controller.snapshot().details) controller.closeDetails(); };
    document.addEventListener('keydown', escape);
    return () => document.removeEventListener('keydown', escape);
  }, [controller]);
  const upload = files => Array.from(files || []).forEach(value => controller.upload(value));
  return <>
    <div className="page-header"><h2 className="page-title">Images</h2></div>
    <div className="images-intake">
      <div className="card"><h3>Publish</h3>
        <div className={`upload${drag ? ' drag' : ''}`} id="drop"
          onDragEnter={event => { event.preventDefault(); setDrag(true); }}
          onDragOver={event => { event.preventDefault(); setDrag(true); }}
          onDragLeave={event => { event.preventDefault(); setDrag(false); }}
          onDrop={event => { event.preventDefault(); setDrag(false); upload(event.dataTransfer.files); }}>
          <input ref={file} type="file" id="file" accept=".bin,.iso,.tar,.rpm" multiple hidden disabled={!state.ready}
            onChange={event => { upload(event.target.files); event.target.value = ''; }} />
          <p><button className="btn" id="pick" disabled={!state.ready} onClick={() => file.current.click()}>Choose files</button> or drag images here</p>
          <div id="uploads">{state.uploads.map(row => <UploadRow key={row.id} row={row} controller={controller} />)}</div>
          <p className="muted" id="status" role="status" aria-live="polite">{state.status}</p>
          {state.importing.length > 0 && <p className="muted" role="status">{state.importing.length} import job(s) in progress.</p>}
        </div>
        <p className="muted">Images copied onto the server under{' '}
          <span className="machine">/opt/images</span> — including any subdirectory — are offered for import below without uploading.
          Files ending in <span className="machine">.bin</span>, <span className="machine">.iso</span>,{' '}
          <span className="machine">.tar</span> or <span className="machine">.rpm</span> are scanned.
          Set <span className="machine">IMAGES_ROOT</span> to scan a different directory.</p>
      </div>
      <div className="card" id="import-panel" hidden={!state.importAvailable || (!state.importable.length && !state.skipped.length)}>
        <h3>Import from disk</h3>
        <p className="muted">Images already present on this server that are not in the catalog. They are published where they are — nothing is copied.</p>
        <div className="table-scroll" tabIndex={0} role="region" aria-label="Images available for import">
          <table className="tbl" id="importable"><thead><tr><th scope="col">File</th><th scope="col">Size</th><th scope="col">Path</th><th scope="col">Actions</th></tr></thead>
            <tbody id="import-rows">
              {state.importable.map(item => <tr key={item.path}><td className="machine">{item.filename}</td><td className="machine">{formatSize(item.size)}</td>
                <td className="muted machine">{item.path}</td><td><button className="linkish do-import" data-path={item.path}
                  disabled={!state.ready || state.importing.includes(item.path)} onClick={() => controller.importFile(item.path)}>import</button></td></tr>)}
              {state.skipped.map(item => <tr className="muted" key={`skipped:${item.path}`}><td className="machine">{item.filename}</td><td className="machine">{formatSize(item.size)}</td>
                <td className="muted machine">{item.path}</td><td>{item.reason}</td></tr>)}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    <div className="images-catalog"><h3>Catalog</h3>
      <p className="muted" role="status" hidden={!state.catalogError}>{state.catalogError}</p>
      <div className="toolbar"><span className="muted push" id="images-count">{state.catalogLoaded
        ? `${state.attentionOnly ? `${images.length} of ` : ''}${state.images.length} ${state.images.length === 1 ? 'image' : 'images'}`
        : state.catalogError ? 'Unavailable' : 'Loading…'}</span>
        <label className="muted"><input type="checkbox" id="images-filter-attention" checked={state.attentionOnly}
          onChange={event => controller.setAttention(event.target.checked)} /> Needs attention only</label></div>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Image catalog">
        <table className="tbl" id="images"><thead><tr><th scope="col">File</th><th scope="col">Verification</th><th scope="col">Image ID</th><th scope="col">Size</th><th scope="col">SHA-256</th><th scope="col">Published</th><th scope="col">Actions</th></tr></thead>
          <tbody id="rows">{images.length ? images.map(item => <tr key={item.id} data-id={item.id}>
            <td className="machine">{item.filename || '—'}</td><td><Verdict image={item} /></td><td className="machine">{item.id}</td>
            <td className="machine">{formatSize(item.size)}</td><td className="machine">{(item.sha256 || '').slice(0, 16)}…</td><td className="machine">{formatDate(item.published_at)}</td>
            <td><button className="linkish img-info" title="Image details" aria-label={`Image details for ${item.id}`}
              onClick={event => { opener.current = event.currentTarget; controller.openDetails(item.id); }}>ⓘ</button>{' '}
              <button className="linkish danger-link del-img" disabled={state.deleting.includes(item.id)} onClick={() => controller.remove(item.id)}>delete</button></td>
          </tr>) : <tr><td colSpan={7} className="muted">{state.catalogLoaded ? 'No images match.'
            : state.catalogError ? 'Catalog unavailable.' : 'Loading images…'}</td></tr>}</tbody>
        </table>
      </div>
    </div>
    <div id="img-info-panel" className="drawer" hidden={!details} role="dialog" aria-label="Image details">
      <div className="drawer-head"><span>Image details <span id="ii-id" className="machine">{image.id}</span></span>
        <button ref={close} className="btn ghost" id="ii-close" aria-label="Close image details" onClick={() => controller.closeDetails()}>✕</button></div>
      <div className="drawer-body"><p className="muted" id="ii-file">{image.filename || ''}</p>
        <h3>Cisco Bulk Hash verification</h3><p id="ii-verdict"><Verdict image={image} /></p>
        <p className="muted" id="ii-verdict-detail">{verificationDetail(image.hash_verification)}</p>
        <p className="muted" id="ii-operator-attestation">{image.operator_attested_signature
          ? 'Operator attested at publish time that the Cisco signature was verified elsewhere.' : 'Not attested by the publishing operator.'}</p>
        <div id="ii-release-block" hidden={!image.quarantined}><h3>Release from quarantine</h3>
          <p className="muted">This image's hash did not match Cisco's feed. Releasing it allows it to be assigned to devices again.</p>
          <button className="btn" type="button" id="ii-release" disabled={details?.busy} onClick={() => controller.release(false)}>Release</button>
          <div id="ii-override-block" hidden={!details?.override}>
            <p className="err" id="ii-override-note" role="alert">{details?.override && 'Still mismatching the Cisco feed — type the exact filename below to override.'}</p>
            <p className="muted">Type the exact filename below to confirm the override and release it anyway.</p>
            <label className="field" htmlFor="ii-confirm-text"><span className="field-label">Exact filename</span>
              <input id="ii-confirm-text" placeholder="Exact filename" spellCheck={false} value={details?.confirmText || ''}
                onChange={event => controller.editConfirmation(event.target.value)} /></label>{' '}
            <button className="btn danger" type="button" id="ii-release-override"
              disabled={!!details?.busy || !details?.confirmText || details.confirmText !== image.filename}
              onClick={() => controller.release(true)}>Release anyway (override)</button>
          </div>
          <p className="err" id="ii-release-msg" role="alert">{details?.error || ''}</p>
        </div>
      </div>
    </div>
  </>;
}

export function mountImages() {
  const root = document.getElementById('iris-images-root');
  if (!root) return;
  const controller = new ImagesController();
  window.addEventListener('iris:images-command', event => {
    const {action, services, resolve, reject} = event.detail;
    try {
      let result;
      if (action === 'connect') controller.connect(services);
      else if (action === 'refresh') result = controller.refresh();
      else if (action === 'importable') result = controller.refresh('importable');
      else if (action === 'attention') controller.setAttention(true);
      else throw new Error('Unknown Images command');
      Promise.resolve(result).then(resolve, reject);
    } catch (error) { reject?.(error); }
  });
  window.addEventListener('pagehide', event => { if (!event.persisted) controller.dispose(); });
  createRoot(root).render(<Images controller={controller} />);
}
