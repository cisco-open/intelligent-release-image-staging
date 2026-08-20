// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

(async function () {
  try {
  var res = await fetch('/api/session');
  if (res.status === 401) { window.location.href = '/login.html'; return; }
  if (!res.ok) throw new Error('Session check failed (' + res.status + ')');
  var info = await res.json();
  if (!info || typeof info !== 'object' || !info.csrf) throw new Error('Session check returned invalid data');
  document.getElementById('who').textContent = info.username;
  document.getElementById('logout').addEventListener('click', async function () {
    await fetch('/api/logout', { method: 'POST', headers: { 'X-CSRF-Token': info.csrf } });
    window.location.href = '/login.html';
  });

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  // Telemetry posture as the DEVICE last reported it (not what onboarding
  // asked for). Tri-state: an agent that predates the flag reports nothing,
  // which is "unknown" — never shown as "off", since off is a real choice.
  function telemetryCell(d) {
    if (d.telemetry_enabled === false) {
      return '<span class="badge badge-off" title="the agent sends no telemetry">off</span>';
    }
    if (d.telemetry_stream_enabled === true) {
      return '<span class="badge badge-ok" title="live samples ride this device\'s heartbeats">streaming</span>';
    }
    if (d.telemetry_stream_enabled === false) {
      return '<span class="badge badge-queued" title="terminal reports only; re-onboard with Telemetry streaming ticked to enable">reports</span>';
    }
    if (d.telemetry_enabled === true) {
      return '<span class="badge badge-queued" title="agent predates the streaming flag">reports</span>';
    }
    return '<span class="muted" title="no heartbeat yet">—</span>';
  }
  function fmtSize(n) {
    if (n == null) return '';
    var u = ['B', 'KB', 'MB', 'GB']; var i = 0; n = Number(n);
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return n.toFixed(i ? 1 : 0) + ' ' + u[i];
  }
  function fmtDate(t) { return t ? new Date(t * 1000).toLocaleString() : ''; }
  function csrfHdr(extra) { var h = { 'X-CSRF-Token': info.csrf }; if (extra) for (var k in extra) h[k] = extra[k]; return h; }
  async function jpost(url, body) {
    return fetch(url, { method: 'POST', headers: csrfHdr({ 'Content-Type': 'application/json' }), body: JSON.stringify(body) });
  }

  // ---- Images (unchanged behavior) ----
  var statusEl = document.getElementById('status');
  var prog = document.getElementById('prog');
  var bar = document.getElementById('bar');
  var imageJobGen = 0;
  async function refreshImages() {
    var r = await fetch('/api/images'); if (!r.ok) return;
    var imgs = (await r.json()).images || [];
    imgs.sort(function (a, b) { return (b.published_at || 0) - (a.published_at || 0); });
    document.getElementById('rows').innerHTML = imgs.map(function (i) {
      return '<tr data-id="' + esc(i.id) + '"><td>' + esc(i.id) + '</td><td>' + esc(i.filename || '') + '</td><td>' +
        esc(fmtSize(i.size)) + '</td><td>' + esc((i.sha256 || '').slice(0, 16)) + '…</td><td>' +
        esc(fmtDate(i.published_at)) + '</td><td><button class="linkish danger-link del-img">delete</button></td></tr>';
    }).join('');
    document.querySelectorAll('#rows .del-img').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        var id = btn.closest('tr').getAttribute('data-id');
        if (!confirm('Delete image ' + id + '? This removes it from the catalog and stops seeding.')) return;
        var r = await fetch('/api/images/' + encodeURIComponent(id), { method: 'DELETE', headers: csrfHdr() });
        if (r.status === 409) { var j = await r.json(); alert('Cannot delete: assigned to ' + (j.assigned || []).join(', ') + '. Reassign those devices first.'); return; }
        refreshImages(); refreshImportable();
      });
    });
  }
  function pollJob(jobId) {
    var gen = ++imageJobGen;
    function next() { setTimeout(poll, 1000); }
    async function poll() {
      try {
        var r = await fetch('/api/images/jobs/' + jobId);
        if (gen !== imageJobGen) return;
        if (!r.ok) { statusEl.textContent = 'Publish status unavailable (' + r.status + '); retrying…'; next(); return; }
        var j = await r.json();
        if (gen !== imageJobGen) return;
        if (j.state === 'done') { statusEl.textContent = 'Published ' + (j.image_id || '') + ' ✓'; prog.hidden = true; refreshImages().catch(function () {}); refreshImportable().catch(function () {}); }
        else if (j.state === 'error') { statusEl.textContent = 'Publish failed: ' + j.message; prog.hidden = true; refreshImportable().catch(function () {}); }
        else { statusEl.textContent = 'Publishing ' + j.filename + '…'; next(); }
      } catch (e) { statusEl.textContent = 'Publish status unavailable; retrying…'; next(); }
    }
    poll();
  }
  // Images already on disk but not in the catalog: orphaned uploads after a
  // catalog reset, and operator-staged files under the read-only image root.
  async function refreshImportable() {
    var panel = document.getElementById('import-panel');
    var r = await fetch('/api/images/importable');
    if (!r.ok) { panel.hidden = true; return; }
    var out = await r.json();
    var cands = out.importable || [];
    var skipped = out.skipped || [];
    panel.hidden = cands.length === 0 && skipped.length === 0;
    // The full path is shown, not just the basename: two files can share a
    // basename across the roots, and the path is what distinguishes them.
    document.getElementById('import-rows').innerHTML = cands.map(function (c) {
      return '<tr><td>' + esc(c.filename) + '</td><td>' + esc(fmtSize(c.size)) +
        '</td><td class="muted">' + esc(c.path) +
        '</td><td><button class="linkish do-import" data-path="' + esc(c.path) +
        '">import</button></td></tr>';
    }).concat(skipped.map(function (c) {
      return '<tr class="muted"><td>' + esc(c.filename) + '</td><td>' +
        esc(fmtSize(c.size)) + '</td><td class="muted">' + esc(c.path) +
        '</td><td>' + esc(c.reason) + '</td></tr>';
    })).join('');
    document.querySelectorAll('#import-rows .do-import').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        btn.disabled = true;
        statusEl.textContent = 'Importing…';
        var res = await fetch('/api/images/import', {
          method: 'POST', headers: csrfHdr({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({ path: btn.getAttribute('data-path') })
        });
        if (!res.ok) {
          btn.disabled = false;
          var j = await res.json().catch(function () { return {}; });
          statusEl.textContent = 'Import failed: ' + (j.error || res.status);
          refreshImportable();
          return;
        }
        pollJob((await res.json()).job_id);
      });
    });
  }
  // Per-file upload rows: every picked/dropped file gets its OWN row (name,
  // progress bar, state text) and its OWN publish poller, so concurrent
  // uploads never fight over shared elements. The legacy #status/#prog/#bar
  // singletons above now serve only the import-from-disk flow.
  var uploadsEl = document.getElementById('uploads');
  function uploadRowUi(name) {
    var row = document.createElement('div');
    row.className = 'upload-row';
    var label = document.createElement('span');
    label.className = 'up-name'; label.textContent = name; label.title = name;
    var rowProg = document.createElement('div'); rowProg.className = 'progress';
    var rowBar = document.createElement('div'); rowBar.className = 'bar';
    rowProg.appendChild(rowBar);
    var state = document.createElement('span'); state.className = 'up-state muted';
    var dismiss = document.createElement('button');
    dismiss.type = 'button'; dismiss.className = 'linkish up-dismiss';
    dismiss.textContent = '×'; dismiss.title = 'Dismiss'; dismiss.hidden = true;
    dismiss.addEventListener('click', function () { row.remove(); });
    row.appendChild(label); row.appendChild(rowProg);
    row.appendChild(state); row.appendChild(dismiss);
    uploadsEl.appendChild(row);
    return {
      progress: function (pct) {
        rowBar.style.width = pct + '%';
        state.textContent = Math.round(pct) + '%';
      },
      publishing: function () { rowBar.style.width = '100%'; state.textContent = 'publishing…'; },
      done: function (text) {
        rowBar.style.width = '100%'; state.textContent = text;
        state.classList.remove('err'); dismiss.hidden = false;
        // auto-fade finished rows; errors stay until dismissed
        setTimeout(function () { row.remove(); }, 8000);
      },
      error: function (text) {
        state.textContent = text; state.classList.add('err'); dismiss.hidden = false;
      }
    };
  }
  function pollUploadJob(jobId, ui) {
    function next() { setTimeout(poll, 1000); }
    async function poll() {
      try {
        var r = await fetch('/api/images/jobs/' + jobId);
        if (!r.ok) { next(); return; }
        var j = await r.json();
        if (j.state === 'done') {
          ui.done('published ' + (j.image_id || '') + ' ✓');
          refreshImages().catch(function () {}); refreshImportable().catch(function () {});
        } else if (j.state === 'error') {
          ui.error('publish failed: ' + j.message);
          refreshImportable().catch(function () {});
        } else { next(); }
      } catch (e) { next(); }
    }
    poll();
  }
  function upload(file) {
    if (!file) return;
    var ui = uploadRowUi(file.name);
    var MAX = 4 * 1024 * 1024 * 1024;
    if (file.size > MAX) { ui.error('too large: ' + fmtSize(file.size) + ' (max 4 GB) — not uploaded'); return; }
    ui.progress(0);
    var xhr = new XMLHttpRequest();
    xhr.open('PUT', '/api/images/upload/' + encodeURIComponent(file.name));
    xhr.setRequestHeader('X-CSRF-Token', info.csrf);
    xhr.upload.onprogress = function (e) { if (e.lengthComputable) ui.progress(e.loaded / e.total * 100); };
    xhr.onload = function () {
      if (xhr.status === 200) { ui.publishing(); pollUploadJob(JSON.parse(xhr.responseText).job_id, ui); }
      else { ui.error('upload failed (' + xhr.status + ')'); }
    };
    xhr.onerror = function () { ui.error('upload error'); };
    xhr.send(file);
  }
  document.getElementById('pick').addEventListener('click', function () { document.getElementById('file').click(); });
  document.getElementById('file').addEventListener('change', function (e) {
    Array.prototype.forEach.call(e.target.files, upload);
    e.target.value = '';   // allow re-picking the same file
  });
  var drop = document.getElementById('drop');
  ['dragenter', 'dragover'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('drag'); }); });
  ['dragleave', 'drop'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('drag'); }); });
  drop.addEventListener('drop', function (e) { Array.prototype.forEach.call(e.dataTransfer.files, upload); });

  // ---- Devices ----
  var devStatus = document.getElementById('dev-status');
  var imageIds = [];
  var credOpts = [];
  // Live status: the devices table previously refreshed only on tab switches
  // and after actions, so stage_state changes (staging -> transferring ->
  // ready) sat stale until the operator clicked something. Poll every 10s —
  // but never while the operator is interacting with a row control (redrawing
  // innerHTML would yank an open dropdown out from under them) and never in a
  // hidden browser tab.
  function scheduleDevices() {
    setTimeout(async function () {
      if (!document.hidden) {
        var a = document.activeElement;
        if (!(a && a.closest && a.closest('#dev-rows'))) {
          try { await refreshDevices(); }
          catch (e) { devStatus.textContent = 'Device refresh unavailable; retrying…'; }
        }
      }
      scheduleDevices();
    }, 10000);
  }
  scheduleDevices();
  async function refreshDevices() {
    var [dr, ir, cr] = await Promise.all([fetch('/api/devices'), fetch('/api/images'), fetch('/api/credentials')]);
    if (!dr.ok) return;
    var dbody = await dr.json();
    var devs = dbody.devices || [];
    var devNow = dbody.now || Date.now() / 1000;   // server clock for last_seen freshness
    imageIds = ir.ok ? ((await ir.json()).images || []).map(function (i) { return i.id; }) : [];
    credOpts = cr.ok ? ((await cr.json()).profiles || []) : [];
    syncCredSelected();
    // keep batch checkbox selections across the periodic re-render
    var marked = {};
    document.querySelectorAll('#dev-rows .mark:checked').forEach(function (cb) {
      marked[cb.getAttribute('data-id')] = true;
    });
    document.getElementById('dev-rows').innerHTML = devs.map(function (d) {
      var opts = ['<option value="">' + (d.assigned_image_id ? '— unassign —' : '— assign —') + '</option>'].concat(imageIds.map(function (id) {
        return '<option value="' + esc(id) + '"' + (id === d.assigned_image_id ? ' selected' : '') + '>' + esc(id) + '</option>';
      })).join('');
      var credSel = ['<option value="">— no credential —</option>'].concat(credOpts.map(function (c) {
        return '<option value="' + esc(c.id) + '"' + (c.id === d.credential_profile_id ? ' selected' : '') + '>' + esc(c.id) + '</option>';
      })).join('');
      var platVal = d.platform || '';
      var platSel = [
        ['', '— auto —'], ['guestshell', 'Guest Shell'], ['iox', 'IOx'],
        ['router', 'Router (VPG)']
      ].map(function (o) {
        return '<option value="' + esc(o[0]) + '"' + (o[0] === platVal ? ' selected' : '') + '>' + esc(o[1]) + '</option>';
      }).join('');
      // "deployed" = the assigned image is staged and verified on the box;
      // anything else shows the raw stage_state, or enrollment/liveness.
      // Job-aware states come FIRST: right after an onboard the agent needs
      // minutes to bootstrap before its first heartbeat — without these the
      // row reads "not enrolled" and looks like the onboard did nothing.
      var fresh = d.last_seen && (devNow - d.last_seen) < 600;
      // "no heartbeat since the job finished" — the job outcome is the
      // freshest truth we have about this device
      var jobFresh = d.onboard_finished_at && (!d.last_seen || d.last_seen < d.onboard_finished_at);
      var status;
      if (d.onboard_state === 'queued' || d.onboard_state === 'running') {
        status = '<span class="badge badge-running">' +
          (d.onboard_action === 'undeploy' ? 'undeploying…' : 'onboarding…') + '</span>';
      } else if (d.onboard_state === 'done' && d.onboard_action === 'onboard' && jobFresh) {
        status = '<span class="badge badge-queued">waiting for heartbeat</span>';
      } else if (d.onboard_state === 'error' && jobFresh) {
        status = '<span class="badge badge-fail">' +
          (d.onboard_action === 'undeploy' ? 'undeploy' : 'onboard') + ' failed</span>';
      } else if (d.stage_state === 'ready' && d.current_image_id && d.current_image_id === d.assigned_image_id) {
        status = '<span class="badge badge-ok">deployed</span>';
      } else if (d.stage_error) {
        status = '<span class="badge badge-fail" title="' + esc(d.stage_error) + '">placement failed</span>' +
          ' <span class="muted" title="' + esc(d.stage_error) + '">' + esc(d.stage_error) + '</span>';
      } else if (d.stage_state === 'transferring_to_ios') {
        status = '<span class="badge badge-running">copying to ' + esc(d.target_fs || 'IOS storage') + '</span>';
      } else if (d.stage_state) {
        status = '<span class="badge badge-running">' + esc(d.stage_state) + '</span>';
      } else if (d.last_seen) {
        status = '<span class="badge badge-queued">enrolled</span>';
      } else {
        status = '<span class="muted">not enrolled</span>';
      }
      if (d.last_seen && !fresh) status += ' <span class="muted" style="font-size:10px">offline</span>';
      var attachment = d.management_type || d.network_attachment || 'legacy';
      var attachmentDetail = attachment.indexOf('router-') === 0
        ? (' / VPG' + (d.vpg_number == null ? '' : d.vpg_number))
        : (' / ' + (d.inband_vlan || d.iris_vlan || ''));
      return '<tr data-id="' + esc(d.device_id) + '">' +
        '<td><input type="checkbox" class="mark" data-id="' + esc(d.device_id) + '"' +
        (marked[d.device_id] ? ' checked' : '') + '></td>' +
        '<td>' + esc(d.device_id) + '</td><td>' + esc(d.device_ip || '') + '</td>' +
        '<td>' + esc(d.model || d.heartbeat_model || '') + '</td>' +
        '<td>' + esc(attachment + attachmentDetail) + '</td>' +
        '<td><select class="platform">' + platSel + '</select></td>' +
        '<td><select class="cred">' + credSel + '</select></td>' +
        '<td><select class="assign">' + opts + '</select></td>' +
        '<td>' + telemetryCell(d) + '</td>' +
        '<td>' + status +
        ' <button class="linkish dinfo" title="Deployment details">ⓘ</button></td></tr>';
    }).join('');
    document.querySelectorAll('#dev-rows .assign').forEach(function (sel) {
      sel.addEventListener('change', async function () {
        var id = sel.closest('tr').getAttribute('data-id');
        var r = await jpost('/api/devices/' + encodeURIComponent(id) + '/assign', { image_id: sel.value });
        devStatus.textContent = r.ok
          ? (sel.value ? ('Assigned ' + sel.value + ' to ' + id) : ('Unassigned ' + id))
          : (sel.value ? 'Assign failed' : 'Unassign failed');
      });
    });
    document.querySelectorAll('#dev-rows .cred').forEach(function (sel) {
      sel.addEventListener('change', async function () {
        var id = sel.closest('tr').getAttribute('data-id');
        var r = await jpost('/api/devices/' + encodeURIComponent(id) + '/credential', { credential_profile_id: sel.value });
        devStatus.textContent = r.ok ? ('Credential updated for ' + id) : 'Credential update failed';
      });
    });
    document.querySelectorAll('#dev-rows .platform').forEach(function (sel) {
      sel.addEventListener('change', async function () {
        var id = sel.closest('tr').getAttribute('data-id');
        var r = await jpost('/api/devices/' + encodeURIComponent(id) + '/platform', { platform: sel.value });
        if (r.ok) {
          devStatus.textContent = 'Platform updated for ' + id;
        } else {
          // surface the real reason and revert the dropdown to the saved value
          devStatus.textContent = 'Platform update failed: ' + ((await r.json()).error || r.status);
          refreshDevices();
        }
      });
    });
    document.querySelectorAll('#dev-rows .dinfo').forEach(function (btn) {
      btn.addEventListener('click', function () {
        openDeployInfo(btn.closest('tr').getAttribute('data-id'));
      });
    });
    document.getElementById('mark-all').checked = false;
    document.getElementById('dev-count').textContent =
      devs.length + ' device' + (devs.length === 1 ? '' : 's');
    updateSelBar();
  }
  // ---- Device deployment details (per-row ⓘ) ----
  // The panel lives OUTSIDE #dev-rows so the 10s table re-render never
  // touches it. deployInfoDev guards against a slow fetch for one device
  // painting over the panel after another row was opened.
  var deployInfoDev = null;
  var DEPLOY_STATE_BADGE = { active: 'badge-ok', removed: 'badge-queued',
                             superseded: 'badge-cancelled', 'needs-reconcile': 'badge-fail' };
  function deployReceiptRows(rec, total) {
    var res = rec.resolved || {};
    var ts = rec.timestamps || {};
    var pf = rec.preflight || {};
    var attach = res.attachment || '';
    var mgmt = attach.indexOf('router-') === 0
      ? (res.vpg_number ? 'VPG' + res.vpg_number : '')
      : ((res.inband_vlan || res.iris_vlan) ? 'VLAN ' + (res.inband_vlan || res.iris_vlan) : '');
    var svi = res.svi_ip ? res.svi_ip + (res.svi_mask ? ' / ' + res.svi_mask : '') : '';
    var app = res.app_ip
      ? res.app_ip + (res.app_mask ? ' / ' + res.app_mask : '') +
        (res.app_gateway ? ' → gw ' + res.app_gateway : '')
      : '';
    var stateCls = DEPLOY_STATE_BADGE[rec.state] || 'badge-queued';
    var pairs = [
      ['State', '<span class="badge ' + stateCls + '">' + esc(rec.state || 'unknown') + '</span>' +
        (rec.adopted ? ' <span class="muted">(adopted)</span>' : '')],
      ['Receipt', esc(rec.receipt_id || '') +
        ' <span class="muted">(' + esc(total) + ' stored for this device)</span>'],
      ['Planned', esc(fmtDate(ts.planned_at) || '—')],
      ['Finished', esc(fmtDate(ts.finished_at) || '—')],
      ['Preflight', esc(pf.status || '—')],
      ['Attachment', esc(attach || '—')],
      ['Management VLAN / VPG', esc(mgmt || '—')],
      ['SVI', esc(svi || '—')],
      ['App IP', esc(app || '—')],
      ['NAT interface', esc(res.nat_interface || '—')],
      ['Swarm port', esc(res.swarm_port || '—')],
      ['Model', esc(res.model || '—')],
      ['Platform', esc(res.platform || '—')],
      ['Device identity', esc(res.device_identity || '—')]
    ];
    return pairs.map(function (kv) {
      return '<tr><td class="muted">' + esc(kv[0]) + '</td><td>' + kv[1] + '</td></tr>';
    }).join('');
  }
  async function openDeployInfo(id) {
    deployInfoDev = id;
    var note = document.getElementById('di-note');
    document.getElementById('di-dev').textContent = id;
    document.getElementById('di-rows').innerHTML = '';
    document.getElementById('di-log-rows').innerHTML = '';
    var lt = document.getElementById('di-log-text');
    lt.hidden = true; lt.textContent = '';
    note.textContent = 'Loading…';
    document.getElementById('deploy-info-panel').hidden = false;
    var r = null;
    try { r = await fetch('/api/devices/' + encodeURIComponent(id) + '/deployment'); } catch (e) { }
    if (deployInfoDev !== id) return;      // another row was opened meanwhile
    if (!r) {
      note.textContent = 'Deployment details unavailable.';
    } else if (r.status === 404) {
      note.textContent = 'Deployment receipts are unavailable on this server.';
    } else if (!r.ok) {
      note.textContent = 'Deployment details unavailable (' + r.status + ').';
    } else {
      var body = await r.json();
      if (deployInfoDev !== id) return;
      if (!body.receipt) {
        note.textContent = 'No deployment receipt — onboarded before receipts ' +
          'existed, or added manually; adopt or re-onboard to create one.';
      } else {
        note.textContent = '';
        document.getElementById('di-rows').innerHTML =
          deployReceiptRows(body.receipt, body.total || 0);
      }
    }
    renderDeviceDeployLogs(id);
  }
  async function renderDeviceDeployLogs(id) {
    var tbody = document.getElementById('di-log-rows');
    var r = null;
    try { r = await fetch('/api/deploy-logs?device_id=' + encodeURIComponent(id)); } catch (e) { }
    if (deployInfoDev !== id) return;
    if (!r || !r.ok) {
      tbody.innerHTML = '<tr><td colspan="5" class="muted">Deployment logs unavailable.</td></tr>';
      return;
    }
    var logs = (await r.json()).logs || [];
    if (deployInfoDev !== id) return;
    if (!logs.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="muted">No deployment logs for this device yet.</td></tr>';
      return;
    }
    tbody.innerHTML = logs.map(function (l) {
      return '<tr data-file="' + esc(l.file) + '"><td>' + esc(fmtDate(l.finished_at)) +
        '</td><td>' + esc(l.action || '') + '</td><td>' + deployLogResult(l) +
        '</td><td>' + esc(fmtSize(l.size)) + '</td>' +
        '<td><button class="linkish dlog-view">view</button></td></tr>';
    }).join('');
    document.querySelectorAll('#di-log-rows .dlog-view').forEach(function (btn) {
      btn.addEventListener('click', function () {
        showDeployLog(btn.closest('tr').getAttribute('data-file'),
                      document.getElementById('di-log-text'));
      });
    });
  }
  document.getElementById('di-close').addEventListener('click', function () {
    deployInfoDev = null;
    document.getElementById('deploy-info-panel').hidden = true;
  });
  // ---- Per-job onboard log panels ----
  // One panel PER JOB in #onboard-logs — its own <pre>, its own EventSource,
  // its own close/abort — so two concurrent onboards never merge into (or
  // blank) each other's window. Opening a job that already has a panel
  // focuses it; at most MAX_ONBOARD_PANELS panels, oldest closed first.
  var onboardPanels = {};        // job_id -> { root, es }
  var onboardPanelOrder = [];    // job ids, oldest first
  var MAX_ONBOARD_PANELS = 6;
  var MAX_LOG_LINES = 500;
  function closeJobLog(jobId) {
    var p = onboardPanels[jobId];
    if (!p) return;
    if (p.es) { p.es.close(); p.es = null; }
    p.root.remove();
    delete onboardPanels[jobId];
    var i = onboardPanelOrder.indexOf(jobId);
    if (i > -1) onboardPanelOrder.splice(i, 1);
  }
  function openJobLog(jobId, deviceId, action, queued) {
    if (onboardPanels[jobId]) {
      onboardPanels[jobId].root.scrollIntoView({ block: 'nearest' });
      return;
    }
    while (onboardPanelOrder.length >= MAX_ONBOARD_PANELS) closeJobLog(onboardPanelOrder[0]);
    var root = document.createElement('div');
    root.className = 'job-log-panel';
    root.setAttribute('data-job', jobId);
    var head = document.createElement('div'); head.className = 'job-log-head';
    var title = document.createElement('h3');
    title.textContent = deviceId + ' — ' + action;
    var abortBtn = document.createElement('button');
    abortBtn.type = 'button'; abortBtn.className = 'btn ghost';
    abortBtn.textContent = 'Abort';
    var closeBtn = document.createElement('button');
    closeBtn.type = 'button'; closeBtn.className = 'btn ghost';
    closeBtn.textContent = 'Close';
    head.appendChild(title); head.appendChild(abortBtn); head.appendChild(closeBtn);
    var log = document.createElement('pre'); log.className = 'log';
    root.appendChild(head); root.appendChild(log);
    document.getElementById('onboard-logs').appendChild(root);
    var entry = { root: root, es: null };
    onboardPanels[jobId] = entry;
    onboardPanelOrder.push(jobId);
    var lines = [], flushPending = false;
    function flush() { flushPending = false; log.textContent = lines.join('\n') + (lines.length ? '\n' : ''); log.scrollTop = log.scrollHeight; }
    function append(text) {
      lines = lines.concat(String(text).split('\n')).slice(-MAX_LOG_LINES);
      if (!flushPending) { flushPending = true; requestAnimationFrame(flush); }
    }
    if (queued) append('(queued — waiting for a free install slot; the log streams once it starts)');
    var es = new EventSource('/api/onboard/jobs/' + encodeURIComponent(jobId) + '/stream');
    entry.es = es;
    es.onmessage = function (e) { append(e.data); };
    es.addEventListener('end', function (e) {
      append('— ' + e.data + ' —'); flush();
      es.close(); entry.es = null; abortBtn.hidden = true;
      refreshDevices().catch(function () {});
    });
    es.onerror = function () { append('[stream closed]'); if (entry.es) { entry.es.close(); entry.es = null; } };
    abortBtn.addEventListener('click', async function () {
      if (!confirm('Abort this ' + action + ' of ' + deviceId + '?\n\nThis stops ' +
          'the running installer. The device may be left partially configured; ' +
          're-onboard (idempotent) or undeploy to clean up.')) return;
      var r = await jpost('/api/onboard/jobs/' + encodeURIComponent(jobId) + '/abort', {});
      append(r.ok ? '[abort requested]' : '[abort failed (' + r.status + ')]');
    });
    closeBtn.addEventListener('click', function () { closeJobLog(jobId); });
    root.scrollIntoView({ block: 'nearest' });
  }
  // Telemetry flags for onboard job bodies (reports default on, streaming
  // default off — the server treats an absent key the same way).
  function telemetryFlags() {
    var t = document.getElementById('onboard-telemetry');
    var s = document.getElementById('onboard-telemetry-stream');
    return { telemetry: !t || t.checked,
             telemetry_stream: !!(s && s.checked) };
  }
  document.getElementById('mark-all').addEventListener('change', function (e) {
    document.querySelectorAll('#dev-rows .mark').forEach(function (cb) { cb.checked = e.target.checked; });
    updateSelBar();
  });
  // ---- menus / selection bar (toolbar rework, spec 2026-08-12) ----
  // CSP-safe popovers: static hidden panels toggled by their trigger; a click
  // on .menu-close (menu items, the Start button) closes; outside click and
  // Escape close; the onboard popover's checkboxes keep it open.
  var openMenuPanel = null;
  function closeMenus() {
    document.querySelectorAll('.menu').forEach(function (p) { p.hidden = true; });
    document.querySelectorAll('.menu-wrap [aria-expanded]').forEach(function (b) {
      b.setAttribute('aria-expanded', 'false');
    });
    openMenuPanel = null;
  }
  function wireMenu(btnId, panelId) {
    var btn = document.getElementById(btnId), panel = document.getElementById(panelId);
    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      var opening = panel.hidden;
      closeMenus();
      if (opening) { panel.hidden = false; btn.setAttribute('aria-expanded', 'true'); openMenuPanel = panel; }
    });
    panel.addEventListener('click', function (e) {
      if (e.target.closest('.menu-close')) closeMenus();
      else e.stopPropagation();
    });
  }
  document.addEventListener('click', function () { if (openMenuPanel) closeMenus(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && openMenuPanel) closeMenus(); });
  wireMenu('csv-menu-btn', 'csv-menu');
  wireMenu('onboard-menu-btn', 'onboard-pop');
  wireMenu('help-btn', 'help-pop');
  function updateSelBar() {
    var n = document.querySelectorAll('#dev-rows .mark:checked').length;
    document.getElementById('sel-bar').hidden = n === 0;
    document.getElementById('sel-count').textContent = n + ' selected';
    document.getElementById('onboard-selected').textContent = 'Start onboard (' + n + ')';
    document.querySelectorAll('#dev-rows tr').forEach(function (tr) {
      var cb = tr.querySelector('.mark');
      tr.classList.toggle('sel', !!(cb && cb.checked));
    });
    if (n === 0) closeMenus();
  }
  document.getElementById('dev-rows').addEventListener('change', function (e) {
    if (e.target.classList.contains('mark')) updateSelBar();
  });
  document.getElementById('sel-clear').addEventListener('click', function () {
    document.querySelectorAll('#dev-rows .mark:checked').forEach(function (cb) { cb.checked = false; });
    document.getElementById('mark-all').checked = false;
    updateSelBar();
  });
  // ---- Batch onboarding ----
  // "Onboard selected" fires every device's onboard POST; the SERVER caps how
  // many installers run at once (OnboardService pool, default 25, env
  // IRIS_ONBOARD_CONCURRENCY) and queues the rest. This panel polls
  // GET /api/onboard/jobs for live per-device state; a row's "log" action
  // opens the SSE log panel for that job (streams once it starts running).
  var batchJobs = {};    // job_id -> device_id for jobs tracked by this panel
  var batchTimer = null;
  var batchGen = 0;      // bumped by close/new batch so stale async work bails
  var pollSeq = 0;       // drop out-of-order poll responses (slow poll racing a fresh one)
  function jobBadge(state) {
    var cls = { queued: 'badge-queued', running: 'badge-running', done: 'badge-ok',
                error: 'badge-fail', cancelled: 'badge-cancelled' }[state] || 'badge-queued';
    return '<span class="badge ' + cls + '">' + esc(state) + '</span>';
  }
  function jobDur(j, now) {
    if (!j.started_at) return '';
    var s = Math.max(0, Math.round((j.finished_at || now) - j.started_at));
    return s < 60 ? s + 's' : Math.floor(s / 60) + 'm' + String(s % 60).padStart(2, '0') + 's';
  }
  function stopBatchPoll() {
    if (batchTimer) { clearTimeout(batchTimer); batchTimer = null; }
  }
  function startBatchPoll(gen) {
    if (gen !== batchGen || batchTimer) return;
    batchTimer = setTimeout(async function run() {
      batchTimer = null;
      var active;
      try { active = await pollBatch(); }
      catch (e) { document.getElementById('batch-summary').textContent = 'Job refresh unavailable; retrying…'; active = true; }
      if (active && gen === batchGen) startBatchPoll(gen);
    }, 2000);
  }
  function renderBatch(listing) {
    // running durations are server-clock minus server-clock: the listing's
    // "now" rides along precisely so a skewed lab VM can't distort them
    var now = listing.now || Date.now() / 1000;
    // queue position is GLOBAL (the pool is server-wide FIFO), so "#2 in
    // line" is honest even when another session's batch is ahead of ours
    var queuedAll = (listing.jobs || []).filter(function (j) { return j.state === 'queued'; });
    var jobs = (listing.jobs || []).filter(function (j) { return batchJobs[j.id]; });
    var counts = {};
    document.getElementById('batch-rows').innerHTML = jobs.map(function (j) {
      counts[j.state] = (counts[j.state] || 0) + 1;
      var queuePos = j.state === 'queued' ? ('#' + (queuedAll.indexOf(j) + 1) + ' in line') : jobDur(j, now);
      var act = (j.action === 'undeploy')
        ? '<div style="color:#8a4baf;font-size:10px;font-weight:600">undeploy</div>' : '';
      return '<tr data-job="' + esc(j.id) + '" data-dev="' + esc(j.device_id) + '"' +
        ' data-state="' + esc(j.state) + '" data-action="' + esc(j.action || 'onboard') + '">' +
        '<td>' + esc(j.device_id) + act + '</td>' +
        '<td>' + jobBadge(j.state) + '</td>' +
        '<td class="muted">' + queuePos + '</td>' +
        '<td class="out">' + esc(j.last_line || '') + '</td>' +
        '<td><button class="linkish blog">log</button></td></tr>';
    }).join('');
    var parts = ['queued', 'running', 'done', 'error', 'cancelled']
      .filter(function (s) { return counts[s]; })
      .map(function (s) { return counts[s] + ' ' + (s === 'error' ? 'failed' : s); });
    document.getElementById('batch-summary').textContent =
      parts.join(' · ') + ' (max ' + listing.max_concurrent + ' parallel)';
    document.querySelectorAll('#batch-rows .blog').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var tr = btn.closest('tr');
        openJobLog(tr.getAttribute('data-job'), tr.getAttribute('data-dev'),
                   tr.getAttribute('data-action') || 'onboard',
                   tr.getAttribute('data-state') === 'queued');
      });
    });
    return jobs.some(function (j) { return j.state === 'queued' || j.state === 'running'; });
  }
  async function pollBatch() {
    var seq = ++pollSeq;
    var r;
    try { r = await fetch('/api/onboard/jobs'); } catch (e) { return true; }
    if (r.status === 401) {   // session gone: stop hammering, tell the operator
      stopBatchPoll();
      document.getElementById('batch-summary').textContent = 'session expired — sign in again';
      return false;
    }
    if (!r.ok) return true;   // transient failure: keep polling
    var listing = await r.json();
    if (seq !== pollSeq) return true;   // a newer poll already rendered
    var active = renderBatch(listing);
    if (!active) { stopBatchPoll(); refreshDevices().catch(function () {}); }
    return active;
  }
  // After a reload (or an accidental panel close + reload), re-attach to
  // whatever the server is still onboarding instead of losing sight of it —
  // the jobs live server-side; only this panel's tracking was in page memory.
  async function restoreBatch() {
    var r;
    try { r = await fetch('/api/onboard/jobs'); } catch (e) { return; }
    if (!r.ok) return;
    var listing = await r.json();
    var jobs = listing.jobs || [];
    if (!jobs.some(function (j) { return j.state === 'queued' || j.state === 'running'; })) return;
    var gen = ++batchGen;
    batchJobs = {};
    jobs.forEach(function (j) { batchJobs[j.id] = j.device_id; });
    document.getElementById('batch-panel').hidden = false;
    renderBatch(listing);
    startBatchPoll(gen);
  }
  // Per-device submission rejections (a router preflight failure, a busy
  // device, an unreachable device, etc.) must never read as a silent no-op:
  // paint them in the same .err red the rest of the page uses for validation
  // failures (see styles.css), one line per device, "<device_id>: <reason>".
  function renderOnboardOutcome(action, startedCount, failed) {
    var msg = 'Started ' + action + ' for ' + startedCount + ' device(s)';
    if (failed.length) msg += '; refused: ' + failed.join(', ');
    devStatus.textContent = msg;
    devStatus.classList.toggle('err', failed.length > 0);
    devStatus.classList.toggle('muted', failed.length === 0);
  }
  async function startBatch(action) {
    var ids = claimSelection();
    if (!ids) return;
    if (action === 'undeploy' &&
        !confirm('Undeploy ' + ids.length + ' device(s)?\n\nThis removes the device agent ' +
                  '(Guest Shell or IOx app) and only receipt-owned resources. Inband deployments preserve their existing network; router NAT preserves a pre-existing outside marking. Staged images at ' +
                 'the filesystem root are left in place. Running jobs are never interrupted.')) {
      setBulkBusy(false); return;
    }
    var gen = ++batchGen;
    stopBatchPoll();
    batchJobs = {};
    document.getElementById('batch-rows').innerHTML = '';
    document.getElementById('batch-summary').textContent = 'starting…';
    document.getElementById('batch-panel').hidden = false;
    var failed = [];
    try {
      await Promise.all(ids.map(async function (id) {
        try {
          var r = await jpost('/api/devices/' + encodeURIComponent(id) + '/' + action,
                              action === 'onboard' ? telemetryFlags() : {});
          if (r.ok) { batchJobs[(await r.json()).job_id] = id; } else {
            // surface WHY it was refused — a bare id reads as a mystery
            var reason = '';
            try { reason = (await r.json()).error || ''; } catch (e2) { }
            failed.push(reason ? id + ': ' + reason : id);
          }
        } catch (e) { failed.push(id); }   // one blipped POST must not kill the batch
      }));
    } finally {
      setBulkBusy(false);
    }
    if (gen !== batchGen) return;    // panel was closed mid-start
    renderOnboardOutcome(action, Object.keys(batchJobs).length, failed);
    if (await pollBatch()) startBatchPoll(gen);
  }
  document.getElementById('onboard-selected').addEventListener('click', function () { startBatch('onboard'); });
  document.getElementById('undeploy-selected').addEventListener('click', function () { startBatch('undeploy'); });

  // ---- bulk row actions (adopt / delete / assign credential) ----
  function selectedIds() {
    return Array.prototype.map.call(document.querySelectorAll('#dev-rows .mark:checked'),
      function (cb) { return cb.getAttribute('data-id'); });
  }
  // Every selected-action shares one lock. Without it a delete could fire while
  // an onboard batch is still starting, removing inventory out from under a
  // running job — onboard/undeploy previously guarded only each other.
  var BULK_BTNS = ['onboard-selected', 'undeploy-selected', 'adopt-selected',
                   'delete-selected', 'apply-cred-selected'];
  var bulkBusy = false;
  function setBulkBusy(busy) {
    bulkBusy = busy;
    BULK_BTNS.forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.disabled = busy;
    });
  }
  // Claim the lock for a selected-action, returning the checked ids (or null if
  // another action holds it or nothing is selected).
  function claimSelection() {
    if (bulkBusy) return null;
    var ids = selectedIds();
    if (!ids.length) { devStatus.textContent = 'No devices selected.'; return null; }
    setBulkBusy(true);
    return ids;
  }
  // The bulk credential picker is populated from the same credOpts the per-row
  // dropdowns use, and is re-synced whenever profiles change — creating a
  // profile must make it immediately assignable, not on the next 10s poll.
  function syncCredSelected() {
    var sel = document.getElementById('cred-selected');
    if (!sel) return;
    var keep = sel.value;
    sel.innerHTML = '<option value="">— credential for selected —</option>' +
      '<option value="">— no credential —</option>' +
      credOpts.map(function (c) {
        return '<option value="' + esc(c.id) + '">' + esc(c.id) + '</option>';
      }).join('');
    if (keep) sel.value = keep;
  }
  function delWarning(ids) {
    // Removing inventory does NOT undeploy: an onboarded device keeps running
    // its agent with no Console record of it, so say so before it happens.
    return 'Delete ' + ids.length + ' device(s) from the inventory?\n\n' +
      ids.join(', ') + '\n\nThis removes the Console record only — it does NOT ' +
      'undeploy. An onboarded device keeps its agent and staged image with no ' +
      'inventory entry left to manage it. Undeploy first if that is what you want.' +
      '\n\nThis cannot be undone.';
  }
  // Run *fn* for each selected id, reporting per-device refusals rather than
  // failing the whole batch — same shape as startBatch's error handling.
  async function forSelected(label, ids, fn) {
    var failed = [];
    try {
      await Promise.all(ids.map(async function (id) {
        try {
          var r = await fn(id);
          if (!r.ok) {
            var reason = '';
            try { reason = (await r.json()).error || ''; } catch (e2) { }
            failed.push(reason ? id + ' (' + reason + ')' : id);
          }
        } catch (e) { failed.push(id); }
      }));
    } finally {
      setBulkBusy(false);
    }
    devStatus.textContent = label + ' ' + (ids.length - failed.length) + '/' +
      ids.length + ' device(s)' + (failed.length ? '; failed: ' + failed.join(', ') : '');
    refreshDevices();
  }
  document.getElementById('delete-selected').addEventListener('click', async function () {
    var ids = claimSelection();
    if (!ids) return;
    if (!confirm(delWarning(ids))) { setBulkBusy(false); return; }
    await forSelected('Deleted', ids, function (id) {
      return fetch('/api/devices/' + encodeURIComponent(id),
                   { method: 'DELETE', headers: csrfHdr() });
    });
  });
  document.getElementById('adopt-selected').addEventListener('click', async function () {
    var ids = claimSelection();
    if (!ids) return;
    if (!confirm('Adopt ' + ids.length + ' device(s)?\n\n' + ids.join(', ') +
      '\n\nAdoption records an ownership receipt for a device IRIS did not onboard, ' +
      'so undeploy may later remove resources IRIS did not create. Only adopt ' +
      'devices whose inventory matches what is really on the box; re-onboarding ' +
      '(idempotent) is the safer option. Router deployments cannot be adopted.' +
      '\n\nProceed with adopt?')) { setBulkBusy(false); return; }
    await forSelected('Adopted', ids, function (id) {
      return jpost('/api/devices/' + encodeURIComponent(id) + '/adopt',
                   { acknowledge_adopt: true });
    });
  });
  document.getElementById('apply-cred-selected').addEventListener('click', async function () {
    var ids = claimSelection();
    if (!ids) return;
    var pid = document.getElementById('cred-selected').value;
    await forSelected(pid ? 'Assigned ' + pid + ' to' : 'Cleared credential on', ids,
      function (id) {
        return jpost('/api/devices/' + encodeURIComponent(id) + '/credential',
                     { credential_profile_id: pid });
      });
  });
  document.getElementById('batch-cancel').addEventListener('click', async function () {
    // scoped to THIS panel's jobs — other sessions' queued batches and parked
    // single-device onboards must survive our cancel
    var r = await jpost('/api/onboard/cancel-queued', { job_ids: Object.keys(batchJobs) });
    if (r.ok) {
      var n = (await r.json()).cancelled;
      devStatus.textContent = 'Cancelled ' + n + ' queued onboard(s).';
      pollBatch();
    }
  });
  document.getElementById('batch-close').addEventListener('click', function () {
    batchGen++;                      // strand any in-flight start/poll work
    stopBatchPoll();
    document.getElementById('batch-panel').hidden = true;
  });
  restoreBatch();
  var devForm = document.getElementById('dev-form');
  function updateDeviceFields() {
    var attach = document.getElementById('df-attachment').value;
    var router = attach === 'router-routed' || attach === 'router-nat';
    document.getElementById('df-vlan').hidden = router;
    document.getElementById('df-svi').hidden = attach !== 'routed';
    document.getElementById('df-vpg').hidden = !router;
    document.getElementById('df-nat-interface').hidden = attach !== 'router-nat';
    var platform = document.getElementById('df-platform');
    if (router && !platform.value) platform.value = 'router';
    if (!router && platform.value === 'router') platform.value = '';
  }
  document.getElementById('df-attachment').addEventListener('change', updateDeviceFields);
  document.getElementById('add-dev').addEventListener('click', function () {
    // populate the credential dropdown from the latest profiles
    var sel = document.getElementById('df-cred');
    sel.innerHTML = '<option value="">— no credential —</option>' +
      credOpts.map(function (c) { return '<option value="' + esc(c.id) + '">' + esc(c.id) + '</option>'; }).join('');
    devForm.hidden = !devForm.hidden;
    if (!devForm.hidden) updateDeviceFields();
  });
  document.getElementById('df-cancel').addEventListener('click', function () { devForm.hidden = true; });
  devForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    var did = document.getElementById('df-id').value.trim();
    var derr = document.getElementById('df-err'); derr.textContent = '';
    if (!did) { derr.textContent = 'Device ID is required.'; return; }
    var attach = document.getElementById('df-attachment').value;
    var vlan = document.getElementById('df-vlan').value.trim();
    var mask = document.getElementById('df-mask').value.trim();
    var body = {
      device_id: did,
      device_ip: document.getElementById('df-ip').value.trim() || did,
      management_type: attach,
      app_ip: document.getElementById('df-guest').value.trim(),
      app_mask: mask,
      app_gateway: document.getElementById('df-gateway').value.trim(),
      model: document.getElementById('df-model').value.trim(),
      platform: document.getElementById('df-platform').value,
      credential_profile_id: document.getElementById('df-cred').value
    };
    if (attach === 'inband') {
      body.inband_vlan = vlan;
    } else if (attach === 'router-routed' || attach === 'router-nat') {
      body.vpg_number = document.getElementById('df-vpg').value.trim();
      if (attach === 'router-nat') {
        body.nat_interface = document.getElementById('df-nat-interface').value.trim();
      }
    } else {
      body.iris_vlan = vlan;
      body.svi_ip = document.getElementById('df-svi').value.trim();
      body.svi_mask = mask;
    }
    var r = await jpost('/api/devices', body);
    if (!r.ok) { derr.textContent = 'Add failed: ' + ((await r.json()).error || r.status); return; }
    devForm.hidden = true; devForm.reset(); refreshDevices();
  });
  document.getElementById('import-csv').addEventListener('click', function () { document.getElementById('csv-file').click(); });
  document.getElementById('csv-file').addEventListener('change', function (e) {
    var f = e.target.files[0]; if (!f) return;
    var rd = new FileReader();
    rd.onload = async function () {
      var r = await fetch('/api/devices/import-csv', { method: 'POST', headers: csrfHdr({ 'Content-Type': 'text/csv' }), body: rd.result });
      var j = await r.json();
      devStatus.textContent = r.ok ? ('Imported ' + j.imported) : ('Import failed: ' + j.error);
      refreshDevices();
    };
    rd.readAsText(f);
  });
  // fetch + blob download (not a plain <a download> nav): Chrome blocks
  // download-attribute navigations over connections with certificate errors
  // (self-signed labs), which made these buttons appear dead.
  async function downloadCsv(url, filename) {
    var r = await fetch(url);                      // same-origin, session cookie rides along
    if (!r.ok) { devStatus.textContent = 'Download failed (' + r.status + ')'; return; }
    var blob = new Blob([await r.text()], { type: 'text/csv' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(a.href);
  }
  document.getElementById('export-csv').addEventListener('click', function () { downloadCsv('/api/devices/export-csv', 'devices.csv'); });
  document.getElementById('example-csv').addEventListener('click', function () { downloadCsv('/api/devices/example-csv', 'devices-example.csv'); });
  var credPanel = document.getElementById('cred-panel');
  var _credProfs = [];
  async function renderCreds() {
    var cr = await fetch('/api/credentials'); var profs = cr.ok ? (await cr.json()).profiles : [];
    credOpts = profs; _credProfs = profs;
    syncCredSelected();
    document.getElementById('cred-rows').innerHTML = profs.length
      ? profs.map(function (p) {
          return '<tr data-id="' + esc(p.id) + '"><td><b>' + esc(p.id) + '</b></td><td>' +
            esc(p.name || '') + '</td><td>' + esc(p.device_user || '') +
            '</td><td><button class="linkish cred-edit">edit</button> · ' +
            '<button class="linkish cred-del">delete</button></td></tr>'; }).join('')
      : '<tr><td colspan="4" class="muted">No credential profiles yet.</td></tr>';
    document.querySelectorAll('#cred-rows .cred-edit').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var id = btn.closest('tr').getAttribute('data-id');
        var p = _credProfs.filter(function (x) { return x.id === id; })[0];
        if (p) editCred(p);
      });
    });
    document.querySelectorAll('#cred-rows .cred-del').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        var id = btn.closest('tr').getAttribute('data-id');
        if (!confirm('Delete credential profile ' + id + '?')) return;
        await fetch('/api/credentials/' + encodeURIComponent(id), { method: 'DELETE', headers: csrfHdr() });
        await renderCreds(); refreshDevices();
      });
    });
  }
  function editCred(p) {
    document.getElementById('cf-id').value = p.id;
    document.getElementById('cf-name').value = p.name || '';
    document.getElementById('cf-user').value = p.device_user || '';
    document.getElementById('cf-pass').value = '';
    document.getElementById('cf-pass2').value = '';
    document.getElementById('cf-en').value = '';
    document.getElementById('cf-err').textContent =
      'Editing "' + p.id + '" — re-enter the device password to save changes.';
    document.getElementById('cf-pass').focus();
  }
  document.getElementById('cf-reset').addEventListener('click', function () {
    document.getElementById('cred-form').reset();
    document.getElementById('cf-err').textContent = '';
  });
  document.getElementById('manage-creds').addEventListener('click', function () {
    credPanel.hidden = !credPanel.hidden;
    if (!credPanel.hidden) renderCreds();
  });
  document.getElementById('cf-close').addEventListener('click', function () { credPanel.hidden = true; });
  document.getElementById('cred-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var err = document.getElementById('cf-err'); err.textContent = '';
    var id = document.getElementById('cf-id').value.trim();
    var pass = document.getElementById('cf-pass').value;
    var pass2 = document.getElementById('cf-pass2').value;
    if (!id) { err.textContent = 'Profile id is required.'; return; }
    if (!pass) { err.textContent = 'Password is required.'; return; }
    if (pass !== pass2) { err.textContent = 'Passwords do not match.'; return; }
    var body = { id: id, name: document.getElementById('cf-name').value.trim() || id,
                 device_user: document.getElementById('cf-user').value.trim(),
                 device_pass: pass, enable_secret: document.getElementById('cf-en').value };
    var r = await jpost('/api/credentials', body);
    if (!r.ok) { err.textContent = 'Save failed: ' + ((await r.json()).error || r.status); return; }
    document.getElementById('cred-form').reset();
    // Re-render the device rows too: their credential dropdowns are built from
    // credOpts, so a device imported before any profile existed stays
    // unassignable until the table is redrawn.
    await renderCreds(); refreshDevices();
  });

  // ---- Overview ----
  async function refreshOverview() {
    var r = await fetch('/api/overview'); if (!r.ok) return;
    var ov = await r.json();
    var cards = [['Images', ov.images], ['Devices', ov.devices],
                 ['Staged', ov.staged], ['Staging now', ov.staging_now],
                 ['Waiting for heartbeat', ov.awaiting_heartbeat || 0]];
    document.getElementById('ov-cards').innerHTML = cards.map(function (c) {
      return '<div class="card"><div class="lbl">' + esc(c[0]) +
        '</div><div class="num">' + esc(c[1]) + '</div></div>';
    }).join('');
    document.getElementById('ov-rows').innerHTML = (ov.rollout || []).map(function (x) {
      var pct = x.assigned ? Math.round(x.staged / x.assigned * 100) : 0;
      return '<tr><td>' + esc(x.image_id) + '</td><td>' + esc(x.assigned) + '</td><td>' +
        esc(x.staged) + '</td><td><div class="pbar"><span data-pct="' + pct +
        '"></span></div></td></tr>';
    }).join('');
    // set widths via JS property (CSP forbids inline style= attributes)
    document.querySelectorAll('#ov-rows .pbar > span').forEach(function (s) {
      s.style.width = s.getAttribute('data-pct') + '%';
    });
  }
  async function refreshSwarm() {
    var [or_, sr] = await Promise.all([fetch('/api/overview'), fetch('/api/swarm')]);
    var mapUrl = or_.ok ? (await or_.json()).swarm_map_url : '';
    var link = document.getElementById('swarm-open');
    if (mapUrl) { link.href = mapUrl; link.style.display = ''; } else { link.style.display = 'none'; }
    var frame = document.getElementById('swarm-frame');
    if (frame && !frame.src) frame.src = '/swarmmap';
    var s = document.getElementById('swarm-summary');
    if (!sr.ok) { s.textContent = 'Swarm data unavailable.'; return; }
    var sw = await sr.json();
    if (sw.error) { s.textContent = 'Swarm data unavailable (' + sw.error + ').'; return; }
    var peers = (sw.images || []).reduce(function (n, im) {
      return n + ((im.peers || []).length);
    }, 0);
    s.textContent = peers + ' peer(s) in the swarm. Open the full map for the live view.';
  }

  // ---- Settings ----
  // CA bundle source presets (Feature 3): the select is a client-side view
  // over the same stored URL the free-text input always wrote — "cisco"
  // means "no override" (server default), "mozilla" is this curated URL,
  // anything else is "custom" and shows the raw input.
  var CA_MOZILLA_URL = 'https://curl.se/ca/cacert.pem';
  async function refreshSettings() {
    var r = await fetch('/api/settings'); if (!r.ok) return;
    var s = await r.json();
    var rows = [
      ['Version', s.version],
      ['Admin', s.admin_username],
      ['Host IP', s.host_ip || '(unset)'],
      ['Ports', 'tracker ' + s.ports.tracker + ' · catalog ' + s.ports.catalog +
                ' · artifacts ' + s.ports.artifacts + ' · swarm ' + s.ports.swarm +
                ' · console ' + s.ports.console]
    ];
    document.querySelector('#settings-info tbody').innerHTML = rows.map(function (kv) {
      return '<tr><td class="muted">' + esc(kv[0]) + '</td><td>' + esc(kv[1]) + '</td></tr>';
    }).join('');
    document.getElementById('sessions-info').textContent =
      s.sessions.active + ' active session(s); idle timeout ' +
      s.sessions.idle_ttl_minutes + ' min.';
    var sh = s.stage_host || {};
    document.getElementById('sh-user').value = sh.username || '';
    document.getElementById('sh-status').textContent = sh.configured
      ? ('Configured — onboarding will ssh to the stage host as "' + sh.username +
         '". To change it, edit the username and/or re-enter the password below and Save.')
      : 'Not configured — needed when the Console runs in Docker, so the onboard ' +
        'installer can ssh to the stage host to stage per-device artifacts. ' +
        'Stored age-encrypted; the password is never shown again.';
    // --- Certificate (metadata only — key material never reaches this page) ---
    var gc = s.gui_cert || {};
    var certStatus = document.getElementById('cert-status');
    if (gc.source === 'custom' || gc.source === 'built-in') {
      certStatus.innerHTML = (gc.source === 'custom'
          ? '<span class="badge badge-running">custom</span> '
          : '<span class="badge badge-queued">built-in</span> ') +
        esc(gc.subject || 'unknown') +
        ' — expires ' + esc(gc.not_after || 'unknown') +
        ' — sha256 ' + esc((gc.fingerprint_sha256 || '').slice(0, 16)) + '…' +
        (gc.source === 'custom' ? ''
          : ' <span class="muted">(the revert button appears once a custom certificate is installed)</span>');
    } else {
      certStatus.textContent =
        'No TLS certificate — the console is serving plain HTTP.';
    }
    document.getElementById('cert-revert').hidden = gc.source !== 'custom';
    // --- Trusted CAs table (rows rebuilt per render, like the images table) ---
    var trust = s.trust || [];
    var caSrcNow = (s.ca_trust || {}).url;
    var bundleLabel = !caSrcNow ? 'Cisco Trusted Root Store'
      : (caSrcNow === CA_MOZILLA_URL ? 'Mozilla CA bundle (curl.se)' : 'Custom URL');
    document.getElementById('trust-rows').innerHTML = trust.length
      ? trust.map(function (t) {
          // The downloaded bundle is ONE store file holding the whole public
          // CA set — name it as such, not by its (arbitrary) first cert.
          var isBundle = t.source === 'downloaded';
          return '<tr data-name="' + esc(t.name) + '"><td>' +
            (isBundle
              ? esc('Public CA bundle — ' + bundleLabel)
              : esc(t.subject || 'unknown')) +
            '</td><td>' + esc(t.not_after || 'unknown') +
            '</td><td>' + esc((t.fingerprint_sha256 || '').slice(0, 16)) + '…</td><td>' +
            (isBundle
              ? '<span class="badge badge-queued">downloaded</span>'
              : '<span class="badge badge-ok">manual</span>') +
            '</td><td>' + esc(t.cert_count) +
            '</td><td><button class="linkish danger-link trust-del">' +
            (isBundle ? 'remove bundle' : 'remove') + '</button></td></tr>';
        }).join('')
      : '<tr><td colspan="6" class="muted">No CA certificates installed — ' +
        'outbound TLS uses the system store only.</td></tr>';
    document.querySelectorAll('#trust-rows .trust-del').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        var name = btn.closest('tr').getAttribute('data-name');
        if (!confirm('Remove trusted CA ' + name + '?\n\nOutbound TLS (telemetry ' +
            'export, CA bundle download) stops trusting certificates issued by it ' +
            'on the next connection.')) return;
        var msg = document.getElementById('trust-msg');
        msg.textContent = ''; msg.classList.remove('ok');
        var r = await fetch('/api/settings/trust/' + encodeURIComponent(name),
                            { method: 'DELETE', headers: csrfHdr() });
        if (!r.ok) { msg.textContent = 'Remove failed (' + r.status + ')'; return; }
        refreshSettings();
      });
    });
    var ct = s.ca_trust || {};
    document.getElementById('ca-url').value = ct.url || '';
    document.getElementById('ca-auto').checked = !!ct.auto;
    var caSourceSel = document.getElementById('ca-source');
    caSourceSel.value = !ct.url ? 'cisco' : (ct.url === CA_MOZILLA_URL ? 'mozilla' : 'custom');
    document.getElementById('ca-url').hidden = caSourceSel.value !== 'custom';
    // --- Telemetry destination (replaces the old read-only Observability row) ---
    var td = s.telemetry_destination || {};
    var obs = s.observability || {};
    document.getElementById('td-status').innerHTML =
      (td.source === 'override'
        ? '<span class="badge badge-running">console override</span> '
        : '<span class="badge badge-queued">deployment default</span> ') +
      (td.effective_enabled
        ? ('export on — ' + esc(td.effective_endpoint || '(no endpoint)'))
        : 'export off') +
      (obs.metrics_url
        ? ' · Prometheus scrape ' + esc(obs.metrics_url) : '');
    document.getElementById('td-endpoint').value = td.effective_endpoint || '';
    document.getElementById('td-enabled').checked = !!td.effective_enabled;
    document.getElementById('td-revert').hidden = td.source !== 'override';
    // --- Audit export (the settings echo never carries the password) ---
    var ae = s.audit_export || {};
    document.getElementById('ae-host').value = ae.host || '';
    document.getElementById('ae-port').value = ae.port == null ? '' : ae.port;
    document.getElementById('ae-user').value = ae.user || '';
    document.getElementById('ae-path').value = ae.path || '';
    document.getElementById('ae-recipient').value = ae.age_recipient || '';
    document.getElementById('ae-auto').checked = !!ae.auto;
    var aePass = document.getElementById('ae-pass');
    aePass.value = '';
    aePass.placeholder = ae.password_set ? 'unchanged' : 'Password';
    var aeStatus = document.getElementById('ae-status');
    if (!ae.host) {
      aeStatus.textContent = 'Not configured — the audit trail stays on this server.';
    } else {
      var last;
      if (ae.last_run_ts) {
        var lr = String(ae.last_result || '');
        var lrOk = lr.slice(0, 3) === 'ok:';
        last = ' · last export ' + esc(fmtDate(ae.last_run_ts)) +
          ' <span class="badge ' + (lrOk ? 'badge-ok">ok' : 'badge-fail">fail') + '</span>' +
          (lr ? ' <span class="muted">' + esc(lr.slice(lr.indexOf(':') + 1)) + '</span>' : '');
      } else {
        last = ' · never exported yet';
      }
      aeStatus.innerHTML = '<span class="badge badge-running">configured</span> ' +
        esc((ae.user || '?') + '@' + ae.host + ':' + (ae.path || '')) +
        (ae.auto ? ' · daily' : ' · manual only') + last;
    }
  }
  document.getElementById('pw-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('pw-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var cur = document.getElementById('pw-cur').value;
    var nw = document.getElementById('pw-new').value;
    var cf = document.getElementById('pw-confirm').value;
    if (nw.length < 8) { msg.textContent = 'New password must be at least 8 characters.'; return; }
    if (nw !== cf) { msg.textContent = 'Passwords do not match.'; return; }
    var r = await jpost('/api/settings/password', { current: cur, new: nw, confirm: cf });
    if (!r.ok) { msg.textContent = ((await r.json()).error || ('Failed (' + r.status + ')')); return; }
    document.getElementById('pw-form').reset();
    msg.textContent = 'Password changed. Other sessions signed out.'; msg.classList.add('ok');
    refreshSettings();
  });
  document.getElementById('revoke-others').addEventListener('click', async function () {
    var m = document.getElementById('revoke-msg'); m.textContent = '';
    var r = await jpost('/api/settings/sessions/revoke-others', {});
    if (!r.ok) { m.textContent = 'Failed (' + r.status + ')'; return; }
    m.textContent = 'Signed out ' + (await r.json()).revoked + ' other session(s).';
    refreshSettings();
  });
  document.getElementById('sh-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('sh-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var user = document.getElementById('sh-user').value.trim();
    var pass = document.getElementById('sh-pass').value;
    var pass2 = document.getElementById('sh-pass2').value;
    if (!user) { msg.textContent = 'Username is required.'; return; }
    if (!pass) { msg.textContent = 'Password is required.'; return; }
    if (pass !== pass2) { msg.textContent = 'Passwords do not match.'; return; }
    var r = await jpost('/api/settings/stage-host', { username: user, password: pass });
    if (!r.ok) { msg.textContent = ((await r.json()).error || ('Failed (' + r.status + ')')); return; }
    document.getElementById('sh-form').reset();
    msg.textContent = 'Stage host credentials saved.'; msg.classList.add('ok');
    refreshSettings();
  });
  document.getElementById('sh-clear').addEventListener('click', async function () {
    var msg = document.getElementById('sh-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var r = await fetch('/api/settings/stage-host', { method: 'DELETE', headers: csrfHdr() });
    if (!r.ok) { msg.textContent = 'Failed (' + r.status + ')'; return; }
    msg.textContent = 'Stage host credentials cleared.'; msg.classList.add('ok');
    refreshSettings();
  });

  // ---- Settings: certificate / trust store / telemetry destination ----

  // Drag-and-drop onto the TLS pane (Feature 2). Client-side only: a
  // FileReader read plus content sniffing, then the existing textareas /
  // endpoints do the rest — no new backend surface. Recognition is by PEM
  // block content, never filename/extension, since operators name these
  // files all sorts of things.
  var PEM_PRIVATE_KEY_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
  // Mirrors gui_tls.key_is_encrypted: PKCS#8 and legacy PEM encodings. An
  // encrypted key reveals the passphrase field; the server decrypts at
  // import and stores the key age-encrypted at rest.
  function keyLooksEncrypted(text) {
    return text.indexOf('ENCRYPTED PRIVATE KEY') > -1
        || text.indexOf('Proc-Type: 4,ENCRYPTED') > -1;
  }
  function syncPassphraseRow() {
    var t = document.getElementById('cert-key').value;
    document.getElementById('cert-passphrase-row').hidden = !keyLooksEncrypted(t);
  }
  document.getElementById('cert-key').addEventListener('input', syncPassphraseRow);
  var PEM_CERTIFICATE_RE = /-----BEGIN CERTIFICATE-----/;
  function readFileAsText(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () { resolve(String(reader.result || '')); };
      reader.onerror = function () { reject(reader.error || new Error('read failed')); };
      reader.readAsText(file);
    });
  }
  // Wires a focusable drop-zone div to: click/Enter/Space -> hidden file
  // input; dragover/dragleave -> 'drag' class for the dashed-border hover
  // state; and a drop/file-pick callback receiving a FileList. Shared by
  // both TLS drop zones below.
  function wireDropzone(zone, input, onFiles) {
    zone.addEventListener('click', function () { input.click(); });
    zone.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
        e.preventDefault();
        input.click();
      }
    });
    ['dragenter', 'dragover'].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add('drag'); });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.remove('drag'); });
    });
    zone.addEventListener('drop', function (e) {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) onFiles(e.dataTransfer.files);
    });
    input.addEventListener('change', function (e) {
      if (e.target.files && e.target.files.length) onFiles(e.target.files);
      input.value = '';   // allow re-dropping/re-picking the same file
    });
  }
  wireDropzone(document.getElementById('cert-dropzone'), document.getElementById('cert-dropzone-input'),
    async function (files) {
      var msg = document.getElementById('cert-msg'); msg.textContent = ''; msg.classList.remove('ok');
      var recognized = [], errors = [];
      for (var i = 0; i < files.length; i++) {
        var file = files[i];
        var text;
        try { text = await readFileAsText(file); } catch (err) { errors.push(file.name + ': could not read file'); continue; }
        var hasKey = PEM_PRIVATE_KEY_RE.test(text);
        var hasCert = PEM_CERTIFICATE_RE.test(text);
        if (!hasKey && !hasCert) { errors.push(file.name + ': no PEM block recognized'); continue; }
        var what = [];
        if (hasCert) { document.getElementById('cert-pem').value = text; what.push('certificate'); }
        if (hasKey) {
          document.getElementById('cert-key').value = text;
          what.push(keyLooksEncrypted(text)
            ? 'private key (passphrase-protected — enter it below)'
            : 'private key');
          syncPassphraseRow();
        }
        recognized.push(file.name + ': ' + what.join(' + ') + ' recognized');
      }
      msg.textContent = recognized.concat(errors).join('; ') || 'No files recognized.';
      if (recognized.length && !errors.length) msg.classList.add('ok');
      // Filled the textareas only — the existing Upload button still owns
      // the actual /api/settings/gui-cert submit.
    });
  document.getElementById('cert-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('cert-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var cert = document.getElementById('cert-pem').value.trim();
    var key = document.getElementById('cert-key').value.trim();
    if (cert.indexOf('BEGIN CERTIFICATE') < 0) {
      msg.textContent = 'Certificate PEM is required (-----BEGIN CERTIFICATE-----).'; return;
    }
    if (key.indexOf('PRIVATE KEY') < 0) {
      msg.textContent = 'Private key PEM is required (-----BEGIN ... PRIVATE KEY-----).'; return;
    }
    var body = { cert_pem: cert, key_pem: key };
    if (keyLooksEncrypted(key)) {
      var pw = document.getElementById('cert-passphrase').value;
      if (!pw) {
        document.getElementById('cert-passphrase-row').hidden = false;
        msg.textContent = 'This private key is passphrase-protected — enter its passphrase.';
        return;
      }
      body.key_passphrase = pw;
    }
    var r = await jpost('/api/settings/gui-cert', body);
    if (!r.ok) { msg.textContent = ((await r.json()).error || ('Failed (' + r.status + ')')); return; }
    document.getElementById('cert-form').reset();   // never leave the key in the DOM
    msg.textContent = 'Certificate replaced. New connections use it now; reload to see it on this one.';
    msg.classList.add('ok');
    refreshSettings();
  });
  document.getElementById('cert-revert').addEventListener('click', async function () {
    var msg = document.getElementById('cert-msg'); msg.textContent = ''; msg.classList.remove('ok');
    if (!confirm('Use the built-in certificate?\n\nThe uploaded certificate and key ' +
        'are deleted and the console serves the bootstrap certificate again. New ' +
        'connections switch immediately; open sessions continue.')) return;
    var r = await fetch('/api/settings/gui-cert', { method: 'DELETE', headers: csrfHdr() });
    if (!r.ok) { msg.textContent = 'Revert failed (' + r.status + ')'; return; }
    msg.textContent = 'Reverted to the built-in certificate.'; msg.classList.add('ok');
    refreshSettings();
  });
  document.getElementById('trust-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('trust-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var pem = document.getElementById('trust-pem').value.trim();
    if (pem.indexOf('BEGIN CERTIFICATE') < 0) {
      msg.textContent = 'Paste at least one PEM certificate block.'; return;
    }
    var r = await jpost('/api/settings/trust', { pem: pem });
    if (!r.ok) { msg.textContent = ((await r.json()).error || ('Failed (' + r.status + ')')); return; }
    document.getElementById('trust-form').reset();
    msg.textContent = 'CA installed.'; msg.classList.add('ok');
    refreshSettings();
  });
  wireDropzone(document.getElementById('trust-dropzone'), document.getElementById('trust-dropzone-input'),
    async function (files) {
      var msg = document.getElementById('trust-msg'); msg.textContent = ''; msg.classList.remove('ok');
      var ok = 0, fail = 0, skipped = 0;
      for (var i = 0; i < files.length; i++) {
        var file = files[i];
        var text;
        try { text = await readFileAsText(file); } catch (err) { fail++; continue; }
        if (!PEM_CERTIFICATE_RE.test(text)) { skipped++; continue; }
        var r = await jpost('/api/settings/trust', { pem: text });
        if (r.ok) ok++; else fail++;
      }
      var parts = [];
      if (ok) parts.push(ok + ' added');
      if (fail) parts.push(fail + ' failed');
      if (skipped) parts.push(skipped + ' skipped (no certificate PEM found)');
      msg.textContent = parts.length ? (parts.join(', ') + '.') : 'No files processed.';
      if (ok && !fail && !skipped) msg.classList.add('ok');
      refreshSettings();
    });
  document.getElementById('ca-source').addEventListener('change', function () {
    document.getElementById('ca-url').hidden = this.value !== 'custom';
  });
  document.getElementById('ca-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('ca-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var source = document.getElementById('ca-source').value;
    // cisco -> null (server default, existing semantics); mozilla -> the
    // curated curl.se URL; custom -> whatever is typed in the (now visible)
    // free-text input. Either way this still posts to the one existing
    // ca-trust endpoint — the preset is purely a client-side URL picker.
    var url = source === 'cisco' ? '' :
      source === 'mozilla' ? CA_MOZILLA_URL :
      document.getElementById('ca-url').value.trim();
    var auto = document.getElementById('ca-auto').checked;
    if (url && url.indexOf('https://') !== 0) { msg.textContent = 'Bundle URL must be https://'; return; }
    if (auto && !url) { msg.textContent = 'Auto-refresh needs a bundle URL.'; return; }
    var r = await jpost('/api/settings/ca-trust', { url: url || null, auto: auto });
    if (!r.ok) { msg.textContent = ((await r.json()).error || ('Failed (' + r.status + ')')); return; }
    msg.textContent = 'CA download settings saved.'; msg.classList.add('ok');
    refreshSettings();
  });
  // "Download now" starts the server-side job and polls it, like image publish
  var caPollTimer = null;
  var caPollGen = 0;
  function pollCaRefresh(jobId) {
    var gen = ++caPollGen;
    var msg = document.getElementById('ca-msg');
    if (caPollTimer) { clearTimeout(caPollTimer); caPollTimer = null; }
    function next() { caPollTimer = setTimeout(poll, 1000); }
    async function poll() {
      try {
      var r = await fetch('/api/settings/ca-trust/refresh/' + encodeURIComponent(jobId));
      if (gen !== caPollGen) return;
      if (!r.ok) { msg.textContent = 'Download status unavailable (' + r.status + '); retrying…'; next(); return; }
      var j = await r.json();
      if (gen !== caPollGen) return;
      if (j.state === 'done') {
        caPollTimer = null;
        msg.textContent = 'Downloaded ' + (j.certs == null ? '?' : j.certs) +
          ' certificate(s).'; msg.classList.add('ok');
        refreshSettings().catch(function () {});
      } else if (j.state === 'failed') {
        caPollTimer = null;
        msg.textContent = 'Download failed: ' + (j.detail || 'unknown error');
      } else {
        msg.textContent = 'Downloading…';
        next();
      }
      } catch (e) { msg.textContent = 'Download status unavailable; retrying…'; next(); }
    }
    poll();
  }
  document.getElementById('ca-refresh').addEventListener('click', async function () {
    var msg = document.getElementById('ca-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var r = await jpost('/api/settings/ca-trust/refresh', {});
    if (!r.ok) { msg.textContent = ((await r.json()).error || ('Failed (' + r.status + ')')); return; }
    msg.textContent = 'Downloading…';
    pollCaRefresh((await r.json()).job);
  });
  document.getElementById('td-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('td-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var endpoint = document.getElementById('td-endpoint').value.trim().replace(/\/+$/, '');
    var enabled = document.getElementById('td-enabled').checked;
    if (enabled && !endpoint) { msg.textContent = 'An endpoint is required when export is enabled.'; return; }
    if (endpoint && !(endpoint.indexOf('http://') === 0 || endpoint.indexOf('https://') === 0)) {
      msg.textContent = 'Endpoint must be an http:// or https:// URL.'; return;
    }
    var r = await jpost('/api/settings/telemetry-destination',
                        { endpoint: endpoint || null, enabled: enabled });
    if (!r.ok) { msg.textContent = ((await r.json()).error || ('Failed (' + r.status + ')')); return; }
    msg.textContent = 'Telemetry destination saved. The exporter picks it up on the next sample pass.';
    msg.classList.add('ok');
    refreshSettings();
  });
  document.getElementById('td-revert').addEventListener('click', async function () {
    var msg = document.getElementById('td-msg'); msg.textContent = ''; msg.classList.remove('ok');
    if (!confirm('Revert the telemetry destination to the deployment default?\n\n' +
        'The console override is deleted and the exporter goes back to the environment configuration ' +
        '(IRIS_OTLP_ENDPOINT / IRIS_OBSERVABILITY) on the next sample pass.')) return;
    var r = await fetch('/api/settings/telemetry-destination', { method: 'DELETE', headers: csrfHdr() });
    if (!r.ok) { msg.textContent = 'Revert failed (' + r.status + ')'; return; }
    msg.textContent = 'Reverted to the deployment default.'; msg.classList.add('ok');
    refreshSettings();
  });

  // ---- Settings: audit export (SCP + age) ----
  document.getElementById('ae-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('ae-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var host = document.getElementById('ae-host').value.trim();
    var port = document.getElementById('ae-port').value.trim();
    var user = document.getElementById('ae-user').value.trim();
    var path = document.getElementById('ae-path').value.trim();
    var recipient = document.getElementById('ae-recipient').value.trim();
    var pass = document.getElementById('ae-pass').value;
    if (!host || !user || !path) { msg.textContent = 'Host, username and remote path are required.'; return; }
    if (!/^age1[0-9a-z]+$/.test(recipient)) {
      msg.textContent = 'A valid age recipient (age1…) is required — the export is always encrypted.'; return;
    }
    var portNum = port ? Number(port) : 22;
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      msg.textContent = 'Port must be a number between 1 and 65535.'; return;
    }
    var body = { host: host, port: portNum, user: user, path: path,
                 age_recipient: recipient,
                 auto: document.getElementById('ae-auto').checked };
    if (pass) body.password = pass;    // absent password keeps the stored one
    var r = await jpost('/api/settings/audit-export', body);
    if (!r.ok) { msg.textContent = ((await r.json()).error || ('Failed (' + r.status + ')')); return; }
    document.getElementById('ae-pass').value = '';   // never leave the password in the DOM
    msg.textContent = 'Audit export settings saved.'; msg.classList.add('ok');
    refreshSettings();
  });
  // "Export now" starts the server-side job and polls it, like the CA refresh
  var aePollTimer = null;
  var aePollGen = 0;
  function pollAuditExport(jobId) {
    var gen = ++aePollGen;
    var msg = document.getElementById('ae-msg');
    if (aePollTimer) { clearTimeout(aePollTimer); aePollTimer = null; }
    function next() { aePollTimer = setTimeout(poll, 1000); }
    async function poll() {
      try {
      var r = await fetch('/api/settings/audit-export/run/' + encodeURIComponent(jobId));
      if (gen !== aePollGen) return;
      if (!r.ok) { msg.textContent = 'Export status unavailable (' + r.status + '); retrying…'; next(); return; }
      var j = await r.json();
      if (gen !== aePollGen) return;
      if (j.state === 'done') {
        aePollTimer = null;
        msg.textContent = 'Exported: ' + (j.detail || 'ok'); msg.classList.add('ok');
        refreshSettings().catch(function () {});
      } else if (j.state === 'error') {
        aePollTimer = null;
        msg.textContent = 'Export failed: ' + (j.detail || 'unknown error');
        refreshSettings().catch(function () {});
      } else {
        msg.textContent = 'Exporting…';
        next();
      }
      } catch (e) { msg.textContent = 'Export status unavailable; retrying…'; next(); }
    }
    poll();
  }
  document.getElementById('ae-run').addEventListener('click', async function () {
    var msg = document.getElementById('ae-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var r = await jpost('/api/settings/audit-export/run', {});
    if (!r.ok) { msg.textContent = ((await r.json()).error || ('Failed (' + r.status + ')')); return; }
    msg.textContent = 'Exporting…';
    pollAuditExport((await r.json()).job_id);
  });
  document.getElementById('ae-clear').addEventListener('click', async function () {
    var msg = document.getElementById('ae-msg'); msg.textContent = ''; msg.classList.remove('ok');
    if (!confirm('Clear the audit export configuration?\n\nThe stored settings and ' +
        'password are deleted and the daily export stops. Audit events stay on ' +
        'this server; files already exported to the remote host are untouched.')) return;
    var r = await fetch('/api/settings/audit-export', { method: 'DELETE', headers: csrfHdr() });
    if (!r.ok) { msg.textContent = 'Clear failed (' + r.status + ')'; return; }
    msg.textContent = 'Audit export configuration cleared.'; msg.classList.add('ok');
    refreshSettings();
  });

  // ---- Settings: sidebar feature sub-menu (General / TLS & trust / Telemetry) ----
  // refreshSettings() above always populates all panes' ids regardless of
  // which is visible, so switching sub-pages is pure class/hidden toggling.
  // The sub-menu entries live in the sidebar under Settings and are plain
  // hash links (#settings/<sub>), so the router below owns selection and the
  // sub-pages are deep-linkable; the menu itself is revealed only while a
  // settings sub-page is showing.
  var SETTINGS_SUBS = ['general', 'tls', 'telemetry'];
  // The audit-export pane rides the same pane/nav id pattern; appended
  // separately so the original trio stays a literal for the source guard
  // that pins it.
  SETTINGS_SUBS.push('audit');
  function showSettingsSub(sub) {
    if (SETTINGS_SUBS.indexOf(sub) < 0) sub = 'general';
    SETTINGS_SUBS.forEach(function (t) {
      document.getElementById('settings-pane-' + t).hidden = t !== sub;
      document.getElementById('nav-settings-' + t).classList.toggle('active', t === sub);
    });
  }
  // Monitoring uses the same sidebar sub-menu pattern (audit | deploylogs):
  // when a view hosts multiple features, each gets its own sub-page instead
  // of stacking cards.
  var MONITORING_SUBS = ['audit', 'deploylogs'];
  function showMonitoringSub(sub) {
    if (MONITORING_SUBS.indexOf(sub) < 0) sub = 'audit';
    MONITORING_SUBS.forEach(function (t) {
      document.getElementById('monitoring-pane-' + t).hidden = t !== sub;
      document.getElementById('nav-monitoring-' + t).classList.toggle('active', t === sub);
    });
  }

  // ---- Monitoring (audit trail + draggable time brush) ----
  var auditOldestTs = null;
  // Preset ranges: window in seconds + bucket count (server-side retention
  // is ~90d, so "all" uses that as its window too).
  var AUDIT_RETENTION_SECONDS = 7776000; // 90 days
  var AUDIT_RANGES = {
    '24h': { window: 86400, buckets: 24 },
    '7d': { window: 604800, buckets: 28 },
    '30d': { window: 2592000, buckets: 30 },
    '90d': { window: AUDIT_RETENTION_SECONDS, buckets: 45 },
    'all': { window: AUDIT_RETENTION_SECONDS, buckets: 45 }
  };
  var auditRange = '24h';

  // Brush constants: viewBox geometry vs screen-px hit tolerances. The SVG is
  // preserveAspectRatio="none", so viewBox units are non-uniform vs screen px
  // — handle hit-testing is done in SCREEN px, drawing in viewBox units.
  var HIST_W = 600, HIST_H = 64;          // viewBox units (match the SVG)
  var HANDLE_HIT_PX = 8;                  // edge-handle hit tolerance, screen px
  var HANDLE_VB = 4;                      // drawn handle width, viewBox units
  var CLICK_SLOP_PX = 3;                  // <= this movement == click, not drag
  var MIN_SEL_SECONDS = 60;               // minimum selection span (min bucket res)

  var auditSel = null;                    // {start,end} epoch secs, or null
  var auditDomain = null;                 // {since,until} epochs the histogram displays
  var auditBuckets = [];                  // last-fetched bucket array
  var auditBucketSecs = 0;                // from response bucket_seconds
  var svgEl = document.getElementById('audit-histogram');
  var barsG = document.getElementById('audit-bars');
  var brushG = document.getElementById('audit-brush');

  // Shared x-scale: the one source of truth for both bar render and brush.
  function epochToVb(t) {                 // epoch -> viewBox x
    return (t - auditDomain.since) / (auditDomain.until - auditDomain.since) * HIST_W;
  }
  function clientXToEpoch(clientX) {      // pointer -> epoch; NO clamp — extrapolates
    var r = svgEl.getBoundingClientRect();     //  past the canvas so captured drags
    var frac = (clientX - r.left) / r.width;   //  can widen/pan beyond the domain
    return auditDomain.since + frac * (auditDomain.until - auditDomain.since);
  }
  function epochToClientX(t) {            // epoch -> screen px (handle hit tests)
    var r = svgEl.getBoundingClientRect();
    return r.left + (t - auditDomain.since) / (auditDomain.until - auditDomain.since) * r.width;
  }

  // Chips define the OUTER window; recomputed at commit time so until tracks now.
  function outerBounds() {
    var cfg = AUDIT_RANGES[auditRange] || AUDIT_RANGES['7d'];
    var now = Date.now() / 1000;
    return { since: now - cfg.window, until: now };
  }
  function clampSel(start, end) {         // clamp a candidate selection into the
    var ob = outerBounds();               // outer window, enforce ordering + min span
    start = Math.max(ob.since, Math.min(start, end));
    end = Math.min(ob.until, Math.max(start, end));
    if (end - start < MIN_SEL_SECONDS) {
      end = Math.min(ob.until, start + MIN_SEL_SECONDS);
      start = end - MIN_SEL_SECONDS;      // grow leftwards if pinned at 'now'
    }
    return { start: start, end: end };
  }

  // -- Message composer: Time | Actor | Message | Result --
  function fmtAgo(ts) {
    var s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }
  // Legacy broker events (mint/refresh/auth_fail...) carry device_id/secret_name
  // instead of actor/category/target/detail — map them to first-class rows.
  var AUDIT_LEGACY_CATS = { mint: 'token', refresh: 'token', refresh_fail: 'token',
                            revoke: 'token', auth_fail: 'auth' };
  var AUDIT_VERBS = {
    login: 'logged in',
    login_fail: 'failed to log in',
    setup: 'created the admin account',
    logout: 'logged out',
    password_change: 'changed the console password',
    password_change_fail: 'failed to change the console password',
    revoke_other_sessions: 'revoked other console sessions',
    stage_host_set: 'set stage-host credentials',
    stage_host_clear: 'cleared stage-host credentials',
    'gui-cert-replace': 'replaced the console TLS certificate',
    'gui-cert-revert': 'reverted the console to the built-in certificate',
    'trust-add': 'installed a trusted CA certificate',
    'trust-remove': 'removed a trusted CA certificate',
    'ca-trust-config': 'changed the CA bundle download settings',
    'ca-trust-refresh': 'refreshed the public CA bundle',
    'telemetry-destination-set': 'changed the telemetry destination',
    'telemetry-destination-clear': 'reverted the telemetry destination to the deployment default',
    audit_export: 'exported audit log',
    audit_export_config: 'changed audit export settings',
    device_csv_import: 'imported devices from CSV',
    revoke: 'had all secrets revoked',
    auth_fail: 'failed token authentication'
  };
  function auditVerb(e, target) {
    var t = esc(target);
    if (AUDIT_VERBS[e.event]) return AUDIT_VERBS[e.event];
    switch (e.event) {
      case 'device_upsert':
        return (e.action === 'create' ? 'added device ' :
                e.action === 'update' ? 'updated device ' : 'saved device ') + t;
      case 'device_assign': return 'assigned an image to ' + t;
      case 'device_credential_change': return 'changed the credential profile of ' + t;
      case 'device_platform_change': return 'changed the platform of ' + t;
      case 'device_delete': return 'deleted device ' + t;
      case 'request_report': return 'requested a fresh report from ' + t;
      case 'onboard_start': return 'started onboarding ' + t;
      case 'onboard_finished':
        return e.result === 'ok' ? 'finished onboarding ' + t : 'onboarding of ' + t + ' failed';
      case 'onboard_cancel': return 'cancelled queued onboarding jobs';
      case 'undeploy_start': return 'started undeploying ' + t;
      case 'undeploy_finished':
        return e.result === 'ok' ? 'finished undeploying ' + t : 'undeploy of ' + t + ' failed';
      case 'credential_profile_set':
        return (e.action === 'create' ? 'created' : 'updated') + ' credential profile ' + t;
      case 'credential_profile_delete': return 'deleted credential profile ' + t;
      case 'image_upload':
        return e.result === 'ok' ? 'uploaded image ' + t : 'rejected upload of ' + t;
      case 'image_publish_finished':
        return e.result === 'ok' ? 'published image ' + t : 'failed to publish image ' + t;
      case 'image_delete':
        return e.result === 'ok' ? 'deleted image ' + t : 'could not delete image ' + t;
      case 'mint': return 'minted a token for ' + t;
      case 'refresh': return 'rotated the catalog token of ' + t;
      case 'refresh_fail': return 'failed to rotate the token of ' + t;
    }
    return esc(e.event || 'event') + (t ? ' ' + t : '');
  }
  function auditActorHtml(actor) {
    if (actor.slice(0, 8) === 'console:')
      return '<span title="console session">' + esc(actor.slice(8)) + '</span>';
    if (actor.slice(0, 7) === 'device:')
      return '<span title="device">' + esc(actor.slice(7)) + '</span>';
    if (actor === 'system') return '<span class="muted">system</span>';
    return esc(actor);
  }
  function auditBadge(result) {
    if (!result) return '';
    return '<span class="badge ' + (result === 'ok' ? 'badge-ok' : 'badge-fail') +
      '">' + esc(result) + '</span>';
  }
  function auditRowHtml(e) {
    var category = e.category || AUDIT_LEGACY_CATS[e.event] || 'system';
    var target = e.target || e.device_id || '';
    var actor = e.actor || (e.device_id ? 'device:' + e.device_id : 'system');
    var detail = e.detail ||
      (e.secret_name ? e.secret_name + ' ' + (e.old_id || '?') + ' -> ' + (e.new_id || '?') : '');
    var msg = '<span class="cat-tag cat-' + esc(category) + '">' + esc(category) + '</span> ' +
      auditVerb(e, target) +
      (detail ? ' <span class="detail">— ' + esc(detail) + '</span>' : '') +
      (e.src_ip && category === 'auth' ? ' <span class="muted">(from ' + esc(e.src_ip) + ')</span>' : '');
    return '<tr><td class="nowrap" title="' + esc(fmtAgo(e.ts)) + '">' + esc(fmtDate(e.ts)) + '</td>' +
      '<td>' + auditActorHtml(actor) + '</td>' +
      '<td class="msg">' + msg + '</td>' +
      '<td>' + auditBadge(e.result) + '</td></tr>';
  }

  function renderAuditRows(events, append) {
    var tbody = document.getElementById('audit-rows');
    if (!events.length && !append) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted">No events in this range.</td></tr>';
      auditOldestTs = null;               // Load older is inert on an empty range
      return;
    }
    var html = events.map(auditRowHtml).join('');
    tbody.innerHTML = append ? tbody.innerHTML + html : html;
    if (events.length) auditOldestTs = events[events.length - 1].ts;
  }

  function auditWindow() {
    var cfg = AUDIT_RANGES[auditRange] || AUDIT_RANGES['7d'];
    var now = Math.floor(Date.now() / 1000);
    return { since: now - cfg.window, until: now, buckets: cfg.buckets, window: cfg.window };
  }

  function auditTableUrl() {
    var cat = document.getElementById('audit-category').value;
    var params = ['limit=200'];
    if (cat) params.push('category=' + encodeURIComponent(cat));
    if (auditSel) {
      params.push('after_ts=' + auditSel.start);
      params.push('before_ts=' + auditSel.end);
    } else {
      var w = auditWindow();
      params.push('after_ts=' + w.since);
    }
    return '/api/audit?' + params.join('&');
  }

  function renderWindowLabel() {
    var label = document.getElementById('audit-window-label');
    var clearBtn = document.getElementById('audit-clear-selection');
    if (auditSel) {
      label.textContent = fmtDate(auditSel.start) + ' – ' + fmtDate(auditSel.end);
      clearBtn.hidden = false;
    } else {
      var w = auditWindow();
      label.textContent = fmtDate(w.since) + ' – ' + fmtDate(w.until);
      clearBtn.hidden = true;
    }
  }
  function renderWindowLabelPending(start, end) { // live readout mid-drag
    document.getElementById('audit-window-label').textContent =
      fmtDate(start) + ' – ' + fmtDate(end);
  }

  function renderHistogramBars(buckets) {
    var maxCount = buckets.reduce(function (m, b) { return Math.max(m, b.count); }, 0);
    var n = buckets.length || 1;
    var barW = HIST_W / n;
    var parts = ['<line x1="0" y1="' + (HIST_H - 1) + '" x2="' + HIST_W + '" y2="' + (HIST_H - 1) + '" class="axis"/>'];
    buckets.forEach(function (b, i) {
      var barH = b.count > 0 ? Math.max(1, Math.round((b.count / (maxCount || 1)) * (HIST_H - 4))) : 0;
      var x = i * barW;
      var y = HIST_H - barH;
      var title = esc(fmtDate(b.start)) + '–' + esc(fmtDate(b.start + auditBucketSecs)) +
        ': ' + esc(b.count) + ' event' + (b.count === 1 ? '' : 's');
      parts.push('<rect class="bar" x="' + (x + 1) + '" y="' + y +
        '" width="' + Math.max(1, barW - 2) + '" height="' + barH +
        '"><title>' + title + '</title></rect>');
    });
    barsG.innerHTML = parts.join('');     // bars layer only — brush layer persists
  }

  // Auto-rezoom picker: never finer than 60s/bucket, never more than 90 bars
  // (spans <=90min get exact minute buckets; always within the server's 1..200).
  function pickBucketCount(spanSecs) {
    var maxByRes = Math.max(1, Math.floor(spanSecs / 60));
    return Math.min(90, maxByRes);
  }

  function renderBrush(sel) {
    if (!sel || !auditDomain) { brushG.innerHTML = ''; return; }
    var x0 = epochToVb(sel.start), x1 = epochToVb(sel.end); // may lie outside 0..600
    var hL = Math.max(0, Math.min(x0 - HANDLE_VB / 2, HIST_W - HANDLE_VB));
    var hR = Math.max(0, Math.min(x1 - HANDLE_VB / 2, HIST_W - HANDLE_VB));
    brushG.innerHTML =
      '<rect class="brush-sel" x="' + x0 + '" y="0" width="' + Math.max(0, x1 - x0) + '" height="' + HIST_H + '"/>' +
      '<rect class="brush-handle" x="' + hL + '" y="0" width="' + HANDLE_VB + '" height="' + HIST_H + '"/>' +
      '<rect class="brush-handle" x="' + hR + '" y="0" width="' + HANDLE_VB + '" height="' + HIST_H + '"/>';
  }

  async function refreshHistogram() {
    var cat = document.getElementById('audit-category').value;
    var url, domain;
    if (auditSel) {
      var span = auditSel.end - auditSel.start;
      url = '/api/audit/histogram?since_ts=' + encodeURIComponent(auditSel.start) +
        '&until_ts=' + encodeURIComponent(auditSel.end) +
        '&buckets=' + pickBucketCount(span);
      domain = { since: auditSel.start, until: auditSel.end };
    } else {
      var w = auditWindow();
      url = '/api/audit/histogram?window=' + w.window + '&buckets=' + w.buckets;
      domain = null;                      // set from response 'now' below
    }
    if (cat) url += '&category=' + encodeURIComponent(cat);
    var r = await fetch(url);
    if (!r.ok) return;
    var body = await r.json();
    auditBuckets = body.buckets || [];
    auditBucketSecs = body.bucket_seconds ||
      ((auditSel ? auditSel.end - auditSel.start : auditWindow().window) / (auditBuckets.length || 1));
    var now = body.now || Math.floor(Date.now() / 1000);
    auditDomain = domain || { since: now - auditWindow().window, until: now };
    renderHistogramBars(auditBuckets);
    renderBrush(auditSel);
    renderWindowLabel();
  }

  async function refreshAuditTable() {
    var r = await fetch(auditTableUrl());
    if (!r.ok) return;
    var events = (await r.json()).events || [];
    renderAuditRows(events, false);
  }

  async function refreshMonitoring() {
    await Promise.all([refreshHistogram(), refreshAuditTable(),
                       refreshTelemetryHealth(), refreshDeployLogs()]);
  }

  // ---- Monitoring: persistent deployment logs pane ----
  function deployLogResult(l) {
    return jobBadge(l.state || 'done') +
      (l.rc == null ? '' : ' <span class="muted">rc=' + esc(l.rc) + '</span>');
  }
  async function showDeployLog(file, pre) {
    pre.hidden = false;
    pre.textContent = 'Loading ' + file + '…';
    var r = null;
    try { r = await fetch('/api/deploy-logs/' + encodeURIComponent(file)); } catch (e) { }
    if (!r || !r.ok) {
      pre.textContent = 'Log unavailable' + (r ? ' (' + r.status + ')' : '') + '.';
      return;
    }
    pre.textContent = await r.text();
  }
  async function refreshDeployLogs() {
    var tbody = document.getElementById('dl-rows');
    var dev = document.getElementById('dl-filter').value.trim();
    var url = '/api/deploy-logs' + (dev ? '?device_id=' + encodeURIComponent(dev) : '');
    var r = null;
    try { r = await fetch(url); } catch (e) { }
    if (!r || !r.ok) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">Deployment logs unavailable' +
        (r ? ' (' + r.status + ')' : '') + '.</td></tr>';
      return;
    }
    var logs = (await r.json()).logs || [];
    if (!logs.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">No deployment logs' +
        (dev ? ' for ' + esc(dev) : '') + ' yet.</td></tr>';
      return;
    }
    tbody.innerHTML = logs.map(function (l) {
      return '<tr data-file="' + esc(l.file) + '"><td>' + esc(fmtDate(l.finished_at)) +
        '</td><td>' + esc(l.device_id || '') + '</td><td>' + esc(l.action || '') +
        '</td><td>' + deployLogResult(l) + '</td><td>' + esc(fmtSize(l.size)) + '</td>' +
        '<td><button class="linkish dlog-view">view</button></td></tr>';
    }).join('');
    document.querySelectorAll('#dl-rows .dlog-view').forEach(function (btn) {
      btn.addEventListener('click', function () {
        showDeployLog(btn.closest('tr').getAttribute('data-file'),
                      document.getElementById('dl-text'));
      });
    });
  }
  document.getElementById('dl-refresh').addEventListener('click', refreshDeployLogs);
  document.getElementById('dl-filter').addEventListener('change', refreshDeployLogs);

  // OTLP export health badge (spec 8.3), via the console's session-gated
  // proxy — never the unauthenticated :9101 directly.
  async function refreshTelemetryHealth() {
    var el = document.getElementById('telemetry-health');
    if (!el) return;
    var state = 'unknown';
    try {
      var r = await fetch('/api/telemetry/health');
      var d = await r.json();
      if (d && d.otlp_export && d.otlp_export.state) state = d.otlp_export.state;
      else if (d && d.ok === false) state = 'unknown';
      else state = 'off';
    } catch (e) { state = 'unknown'; }
    el.hidden = false;
    el.textContent = 'Telemetry export: ' + state;
    el.className = 'badge ' + (state === 'ok' ? 'badge-ok'
                               : state === 'degraded' ? 'badge-cancelled'
                               : 'badge-queued');
  }

  async function loadOlderAudit() {
    if (auditOldestTs == null) return;
    var cat = document.getElementById('audit-category').value;
    var params = ['limit=200', 'before_ts=' + auditOldestTs];
    if (cat) params.push('category=' + encodeURIComponent(cat));
    var lowerBound = auditSel ? auditSel.start : auditWindow().since;
    params.push('after_ts=' + lowerBound);
    var r = await fetch('/api/audit?' + params.join('&'));
    if (!r.ok) return;
    var events = (await r.json()).events || [];
    renderAuditRows(events, true);
  }

  function commitSelection(start, end) {
    auditSel = clampSel(start, end);
    refreshMonitoring();
  }
  function clearSelection() {
    if (!auditSel) return;
    auditSel = null;
    refreshMonitoring();
  }

  // -- Brush pointer state machine (one listener set on the SVG; all
  //    hit-testing is numeric, the overlay layer is pointer-events:none) --
  var brushDrag = null;
  // { mode:'new'|'left'|'right'|'pan', downX, anchor, orig, pending, moved }
  function hitTest(clientX) {
    if (auditSel) {
      var pxL = epochToClientX(auditSel.start), pxR = epochToClientX(auditSel.end);
      if (Math.abs(clientX - pxL) <= HANDLE_HIT_PX) return 'left';
      if (Math.abs(clientX - pxR) <= HANDLE_HIT_PX) return 'right';
      if (clientX > pxL && clientX < pxR) return 'pan';
    }
    return 'new';
  }
  svgEl.addEventListener('pointerdown', function (e) {
    if (e.button !== 0 || !e.isPrimary || brushDrag || !auditDomain) return;
    var mode = hitTest(e.clientX);
    var t = clientXToEpoch(e.clientX);
    brushDrag = {
      mode: mode, downX: e.clientX, moved: false,
      orig: auditSel ? { start: auditSel.start, end: auditSel.end } : null,
      anchor: mode === 'left' ? auditSel.end : mode === 'right' ? auditSel.start : t,
      pending: auditSel ? { start: auditSel.start, end: auditSel.end } : { start: t, end: t }
    };
    svgEl.setPointerCapture(e.pointerId);
    e.preventDefault();
  });
  svgEl.addEventListener('pointermove', function (e) {
    if (!brushDrag) {                     // idle: cursor feedback only
      var m = hitTest(e.clientX);
      svgEl.style.cursor = (m === 'left' || m === 'right') ? 'ew-resize'
                         : m === 'pan' ? 'grab' : 'crosshair';
      return;
    }
    if (Math.abs(e.clientX - brushDrag.downX) > CLICK_SLOP_PX) brushDrag.moved = true;
    if (!brushDrag.moved) return;
    var t = clientXToEpoch(e.clientX);    // unclamped: may extend past the canvas
    var ob = outerBounds(), p;
    if (brushDrag.mode === 'pan') {
      var d = t - clientXToEpoch(brushDrag.downX);
      var span = brushDrag.orig.end - brushDrag.orig.start;
      var s = brushDrag.orig.start + d;   // clamp shift, PRESERVING span
      s = Math.max(ob.since, Math.min(s, ob.until - span));
      p = { start: s, end: s + span };
      svgEl.style.cursor = 'grabbing';
    } else {                              // 'new' | 'left' | 'right'
      t = Math.max(ob.since, Math.min(t, ob.until));
      p = { start: Math.min(brushDrag.anchor, t), end: Math.max(brushDrag.anchor, t) };
    }
    brushDrag.pending = p;
    renderBrush(p);                       // overlay only — no refetch mid-drag
    renderWindowLabelPending(p.start, p.end);
  });
  svgEl.addEventListener('pointerup', function (e) {
    if (!brushDrag) return;
    var d = brushDrag; brushDrag = null;
    svgEl.releasePointerCapture(e.pointerId);
    svgEl.style.cursor = '';
    if (!d.moved) {                       // CLICK: select the underlying bucket
      var n = auditBuckets.length;
      if (n && d.mode === 'new' || n && d.mode === 'pan') {
        var r = svgEl.getBoundingClientRect();
        var i = Math.max(0, Math.min(n - 1, Math.floor((e.clientX - r.left) / r.width * n)));
        var bStart = auditDomain.since + i * auditBucketSecs; // derive from domain+index,
        commitSelection(bStart, bStart + auditBucketSecs);    // not the int-truncated 'start'
      } else { renderBrush(auditSel); renderWindowLabel(); }  // handle-click: restore
      return;
    }
    if (d.pending.end - d.pending.start < 1) {  // degenerate zero-width drag: restore
      renderBrush(auditSel); renderWindowLabel(); return;
    }
    commitSelection(d.pending.start, d.pending.end);
  });
  function abortDrag() {                  // idempotent: also fires after normal release
    if (!brushDrag) return;
    brushDrag = null; svgEl.style.cursor = '';
    renderBrush(auditSel); renderWindowLabel();
  }
  svgEl.addEventListener('pointercancel', abortDrag);
  svgEl.addEventListener('lostpointercapture', abortDrag);

  document.getElementById('audit-refresh').addEventListener('click', refreshMonitoring);
  document.getElementById('audit-category').addEventListener('change', refreshMonitoring);
  document.getElementById('audit-load-older').addEventListener('click', loadOlderAudit);
  document.getElementById('audit-clear-selection').addEventListener('click', clearSelection);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !document.getElementById('view-monitoring').hidden) clearSelection();
  });
  Array.prototype.forEach.call(document.querySelectorAll('#audit-range-chips .chip'), function (chip) {
    chip.addEventListener('click', function () {
      auditRange = chip.getAttribute('data-range');
      auditSel = null;
      Array.prototype.forEach.call(document.querySelectorAll('#audit-range-chips .chip'), function (c) {
        c.classList.toggle('active', c === chip);
      });
      refreshMonitoring();
    });
  });

  // ---- header help popover ----
  // Version / deployment id / docs links come from GET /api/help, fetched
  // lazily on the first open and cached for the session.
  var helpLoaded = false;
  document.getElementById('help-btn').addEventListener('click', async function () {
    if (helpLoaded) return;
    var r;
    try { r = await fetch('/api/help'); } catch (e) { return; }
    if (!r.ok) return;
    var h = await r.json();
    helpLoaded = true;
    document.getElementById('help-version').textContent = 'Version ' + (h.version || 'unknown');
    document.getElementById('help-deployment-id').textContent = h.deployment_id || '';
    if (h.docs_url) document.getElementById('help-docs-link').href = h.docs_url;
    var g = h.guides || {};
    if (g.device) document.getElementById('help-device-guide').href = g.device;
    if (g.server) document.getElementById('help-server-guide').href = g.server;
  });
  document.getElementById('help-copy-id').addEventListener('click', async function () {
    var id = document.getElementById('help-deployment-id').textContent;
    if (!id) return;
    var btn = document.getElementById('help-copy-id');
    try { await navigator.clipboard.writeText(id); btn.textContent = 'copied'; }
    catch (e) { btn.textContent = 'copy failed'; }
    setTimeout(function () { btn.textContent = 'copy'; }, 1500);
  });

  // ---- hash router ----
  var VIEWS = ['overview', 'images', 'devices', 'swarm', 'settings', 'monitoring'];
  function show(view) {
    // "#settings/tls" style hashes: the part before the slash picks the view,
    // the rest picks the view's sub-page (showSettingsSub / showMonitoringSub
    // validate it).
    var sub = view.indexOf('/') > -1 ? view.slice(view.indexOf('/') + 1) : '';
    view = view.split('/')[0];
    if (VIEWS.indexOf(view) < 0) view = 'overview';
    VIEWS.forEach(function (v) {
      document.getElementById('view-' + v).hidden = v !== view;
      var nav = document.getElementById('nav-' + v);
      if (nav) nav.classList.toggle('active', v === view);
    });
    document.getElementById('settings-submenu').hidden = view !== 'settings';
    if (view === 'settings') showSettingsSub(sub || 'general');
    document.getElementById('monitoring-submenu').hidden = view !== 'monitoring';
    if (view === 'monitoring') showMonitoringSub(sub || 'audit');
    if (view === 'overview') refreshOverview();
    else if (view === 'images') { refreshImages(); refreshImportable(); }
    else if (view === 'devices') refreshDevices();
    else if (view === 'swarm') refreshSwarm();
    else if (view === 'settings') refreshSettings();
    else if (view === 'monitoring') refreshMonitoring();
  }
  function current() { return (location.hash || '#overview').slice(1); }
  window.addEventListener('hashchange', function () { show(current()); });
  show(current());
  } catch (e) {
    var notice = document.createElement('div');
    notice.textContent = 'Console initialization failed: ' + (e && e.message ? e.message : e) + '. Reload to retry.';
    notice.setAttribute('role', 'alert');
    notice.style.cssText = 'position:fixed;top:12px;left:12px;right:12px;z-index:9999;padding:12px;background:#5b1d1d;color:#fff;border:1px solid #d66;border-radius:4px';
    document.body.appendChild(notice);
  }
})();
