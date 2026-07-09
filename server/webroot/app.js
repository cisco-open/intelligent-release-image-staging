// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

(async function () {
  var res = await fetch('/api/session');
  if (res.status === 401) { window.location.href = '/login.html'; return; }
  var info = await res.json();
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
  async function refreshImages() {
    var r = await fetch('/api/images'); if (!r.ok) return;
    var imgs = (await r.json()).images || [];
    imgs.sort(function (a, b) { return (b.published_at || 0) - (a.published_at || 0); });
    document.getElementById('rows').innerHTML = imgs.map(function (i) {
      return '<tr data-id="' + esc(i.id) + '"><td>' + esc(i.id) + '</td><td>' + esc(i.filename || '') + '</td><td>' +
        esc(fmtSize(i.size)) + '</td><td>' + esc((i.sha256 || '').slice(0, 16)) + '…</td><td>' +
        esc(fmtDate(i.published_at)) + '</td><td><button class="linkish del-img">delete</button></td></tr>';
    }).join('');
    document.querySelectorAll('#rows .del-img').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        var id = btn.closest('tr').getAttribute('data-id');
        if (!confirm('Delete image ' + id + '? This removes it from the catalog and stops seeding.')) return;
        var r = await fetch('/api/images/' + encodeURIComponent(id), { method: 'DELETE', headers: csrfHdr() });
        if (r.status === 409) { var j = await r.json(); alert('Cannot delete: assigned to ' + (j.assigned || []).join(', ') + '. Reassign those devices first.'); return; }
        refreshImages();
      });
    });
  }
  function pollJob(jobId) {
    var iv = setInterval(async function () {
      var r = await fetch('/api/images/jobs/' + jobId);
      if (!r.ok) { clearInterval(iv); return; }
      var j = await r.json();
      if (j.state === 'done') { clearInterval(iv); statusEl.textContent = 'Published ' + (j.image_id || '') + ' ✓'; prog.hidden = true; refreshImages(); }
      else if (j.state === 'error') { clearInterval(iv); statusEl.textContent = 'Publish failed: ' + j.message; prog.hidden = true; }
      else { statusEl.textContent = 'Publishing ' + j.filename + '…'; }
    }, 1000);
  }
  function upload(file) {
    if (!file) return;
    var MAX = 4 * 1024 * 1024 * 1024;
    if (file.size > MAX) { prog.hidden = true; statusEl.textContent = 'File too large: ' + fmtSize(file.size) + ' (max 4 GB). Not uploaded.'; return; }
    prog.hidden = false; bar.style.width = '0'; statusEl.textContent = 'Uploading ' + file.name + '…';
    var xhr = new XMLHttpRequest();
    xhr.open('PUT', '/api/images/upload/' + encodeURIComponent(file.name));
    xhr.setRequestHeader('X-CSRF-Token', info.csrf);
    xhr.upload.onprogress = function (e) { if (e.lengthComputable) bar.style.width = (e.loaded / e.total * 100) + '%'; };
    xhr.onload = function () { if (xhr.status === 200) { statusEl.textContent = 'Upload done, publishing…'; pollJob(JSON.parse(xhr.responseText).job_id); } else { prog.hidden = true; statusEl.textContent = 'Upload failed (' + xhr.status + ')'; } };
    xhr.onerror = function () { prog.hidden = true; statusEl.textContent = 'Upload error'; };
    xhr.send(file);
  }
  document.getElementById('pick').addEventListener('click', function () { document.getElementById('file').click(); });
  document.getElementById('file').addEventListener('change', function (e) { upload(e.target.files[0]); });
  var drop = document.getElementById('drop');
  ['dragenter', 'dragover'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('drag'); }); });
  ['dragleave', 'drop'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('drag'); }); });
  drop.addEventListener('drop', function (e) { upload(e.dataTransfer.files[0]); });

  // ---- Devices ----
  var devStatus = document.getElementById('dev-status');
  var imageIds = [];
  var credOpts = [];
  async function refreshDevices() {
    var [dr, ir, cr] = await Promise.all([fetch('/api/devices'), fetch('/api/images'), fetch('/api/credentials')]);
    if (!dr.ok) return;
    var dbody = await dr.json();
    var devs = dbody.devices || [];
    var devNow = dbody.now || Date.now() / 1000;   // server clock for last_seen freshness
    imageIds = ir.ok ? ((await ir.json()).images || []).map(function (i) { return i.id; }) : [];
    credOpts = cr.ok ? ((await cr.json()).profiles || []) : [];
    document.getElementById('dev-rows').innerHTML = devs.map(function (d) {
      var opts = ['<option value="">— assign —</option>'].concat(imageIds.map(function (id) {
        return '<option value="' + esc(id) + '"' + (id === d.assigned_image_id ? ' selected' : '') + '>' + esc(id) + '</option>';
      })).join('');
      var credSel = ['<option value="">— no credential —</option>'].concat(credOpts.map(function (c) {
        return '<option value="' + esc(c.id) + '"' + (c.id === d.credential_profile_id ? ' selected' : '') + '>' + esc(c.id) + '</option>';
      })).join('');
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
      } else if (d.stage_state) {
        status = '<span class="badge badge-running">' + esc(d.stage_state) + '</span>';
      } else if (d.last_seen) {
        status = '<span class="badge badge-queued">enrolled</span>';
      } else {
        status = '<span class="muted">not enrolled</span>';
      }
      if (d.last_seen && !fresh) status += ' <span class="muted" style="font-size:10px">offline</span>';
      return '<tr data-id="' + esc(d.device_id) + '">' +
        '<td><input type="checkbox" class="mark" data-id="' + esc(d.device_id) + '"></td>' +
        '<td>' + esc(d.device_id) + '</td><td>' + esc(d.device_ip || '') + '</td>' +
        '<td>' + esc(d.model || d.heartbeat_model || '') + '</td>' +
        '<td>' + esc(d.vlan || '') + ' / ' + esc(d.svi_ip || '') + '</td>' +
        '<td><select class="cred">' + credSel + '</select></td>' +
        '<td><select class="assign">' + opts + '</select></td>' +
        '<td>' + status + '</td>' +
        '<td><button class="linkish onboard">onboard</button> · <button class="linkish del">delete</button></td></tr>';
    }).join('');
    document.querySelectorAll('#dev-rows .assign').forEach(function (sel) {
      sel.addEventListener('change', async function () {
        var id = sel.closest('tr').getAttribute('data-id');
        if (!sel.value) return;
        var r = await jpost('/api/devices/' + encodeURIComponent(id) + '/assign', { image_id: sel.value });
        devStatus.textContent = r.ok ? ('Assigned ' + sel.value + ' to ' + id) : 'Assign failed';
      });
    });
    document.querySelectorAll('#dev-rows .cred').forEach(function (sel) {
      sel.addEventListener('change', async function () {
        var id = sel.closest('tr').getAttribute('data-id');
        var r = await jpost('/api/devices/' + encodeURIComponent(id) + '/credential', { credential_profile_id: sel.value });
        devStatus.textContent = r.ok ? ('Credential updated for ' + id) : 'Credential update failed';
      });
    });
    document.querySelectorAll('#dev-rows .del').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        var id = btn.closest('tr').getAttribute('data-id');
        await fetch('/api/devices/' + encodeURIComponent(id), { method: 'DELETE', headers: csrfHdr() });
        refreshDevices();
      });
    });
    document.querySelectorAll('#dev-rows .onboard').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var id = btn.closest('tr').getAttribute('data-id');
        startOnboard(id);
      });
    });
    document.getElementById('mark-all').checked = false;
  }
  var onboardEs = null;
  function openOnboardPanel(label) {
    var panel = document.getElementById('onboard-panel');
    var log = document.getElementById('onboard-log');
    document.getElementById('onboard-dev').textContent = label;
    log.textContent = ''; panel.hidden = false;
    if (onboardEs) { onboardEs.close(); onboardEs = null; }
    return log;
  }
  function streamOnboardJob(jobId, log) {
    onboardEs = new EventSource('/api/onboard/jobs/' + encodeURIComponent(jobId) + '/stream');
    onboardEs.onmessage = function (e) { log.textContent += e.data + '\n'; log.scrollTop = log.scrollHeight; };
    onboardEs.addEventListener('end', function (e) { log.textContent += '\n— ' + e.data + ' —\n'; onboardEs.close(); onboardEs = null; refreshDevices(); });
    onboardEs.onerror = function () { log.textContent += '\n[stream closed]\n'; if (onboardEs) { onboardEs.close(); onboardEs = null; } };
  }
  function startOnboard(id) {
    var log = openOnboardPanel(id);
    jpost('/api/devices/' + encodeURIComponent(id) + '/onboard', {}).then(function (r) {
      if (!r.ok) { log.textContent = 'Failed to start onboarding (' + r.status + ')'; return; }
      return r.json();
    }).then(function (j) { if (j) streamOnboardJob(j.job_id, log); });
  }
  document.getElementById('onboard-close').addEventListener('click', function () {
    if (onboardEs) { onboardEs.close(); onboardEs = null; }
    document.getElementById('onboard-panel').hidden = true;
  });
  document.getElementById('mark-all').addEventListener('change', function (e) {
    document.querySelectorAll('#dev-rows .mark').forEach(function (cb) { cb.checked = e.target.checked; });
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
    if (batchTimer) { clearInterval(batchTimer); batchTimer = null; }
  }
  function startBatchPoll(gen) {
    if (gen === batchGen && !batchTimer) batchTimer = setInterval(pollBatch, 2000);
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
        ' data-state="' + esc(j.state) + '">' +
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
        var log = openOnboardPanel(tr.getAttribute('data-dev'));
        if (tr.getAttribute('data-state') === 'queued') {
          log.textContent = '(queued — waiting for a free install slot; the log streams once it starts)\n';
        }
        streamOnboardJob(tr.getAttribute('data-job'), log);
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
    if (!active) { stopBatchPoll(); refreshDevices(); }
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
  async function startBatch(action) {
    var onBtn = document.getElementById('onboard-selected');
    var unBtn = document.getElementById('undeploy-selected');
    if (onBtn.disabled) return;
    var ids = Array.prototype.map.call(document.querySelectorAll('#dev-rows .mark:checked'),
      function (cb) { return cb.getAttribute('data-id'); });
    if (!ids.length) { devStatus.textContent = 'No devices selected.'; return; }
    if (action === 'undeploy' &&
        !confirm('Undeploy ' + ids.length + ' device(s)?\n\nThis removes the device agent, ' +
                 'guestshell, VLAN/SVI and trustpoint from each device (staged images at ' +
                 'flash root are left in place). Running jobs are never interrupted.')) return;
    onBtn.disabled = true; unBtn.disabled = true;   // no overlapping batches from double-clicks
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
          var r = await jpost('/api/devices/' + encodeURIComponent(id) + '/' + action, {});
          if (r.ok) { batchJobs[(await r.json()).job_id] = id; } else { failed.push(id); }
        } catch (e) { failed.push(id); }   // one blipped POST must not kill the batch
      }));
    } finally {
      onBtn.disabled = false; unBtn.disabled = false;
    }
    if (gen !== batchGen) return;    // panel was closed mid-start
    devStatus.textContent = 'Started ' + action + ' for ' + Object.keys(batchJobs).length + ' device(s)' +
      (failed.length ? '; failed to start: ' + failed.join(', ') : '');
    if (await pollBatch()) startBatchPoll(gen);
  }
  document.getElementById('onboard-selected').addEventListener('click', function () { startBatch('onboard'); });
  document.getElementById('undeploy-selected').addEventListener('click', function () { startBatch('undeploy'); });
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
  document.getElementById('add-dev').addEventListener('click', function () {
    // populate the credential dropdown from the latest profiles
    var sel = document.getElementById('df-cred');
    sel.innerHTML = '<option value="">— no credential —</option>' +
      credOpts.map(function (c) { return '<option value="' + esc(c.id) + '">' + esc(c.id) + '</option>'; }).join('');
    devForm.hidden = !devForm.hidden;
  });
  document.getElementById('df-cancel').addEventListener('click', function () { devForm.hidden = true; });
  devForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    var did = document.getElementById('df-id').value.trim();
    var derr = document.getElementById('df-err'); derr.textContent = '';
    if (!did) { derr.textContent = 'Device ID is required.'; return; }
    var body = {
      device_id: did,
      device_ip: document.getElementById('df-ip').value.trim() || did,
      vlan: document.getElementById('df-vlan').value.trim(),
      svi_ip: document.getElementById('df-svi').value.trim(),
      svi_mask: document.getElementById('df-mask').value.trim(),
      guest_ip: document.getElementById('df-guest').value.trim(),
      model: document.getElementById('df-model').value.trim(),
      credential_profile_id: document.getElementById('df-cred').value
    };
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
  async function renderCreds() {
    var cr = await fetch('/api/credentials'); var profs = cr.ok ? (await cr.json()).profiles : [];
    credOpts = profs;
    document.getElementById('cred-rows').innerHTML = profs.length
      ? profs.map(function (p) {
          return '<tr data-id="' + esc(p.id) + '"><td><b>' + esc(p.id) + '</b></td><td>' +
            esc(p.name || '') + '</td><td>' + esc(p.device_user || '') +
            '</td><td><button class="linkish cred-del">delete</button></td></tr>'; }).join('')
      : '<tr><td class="muted">No credential profiles yet.</td></tr>';
    document.querySelectorAll('#cred-rows .cred-del').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        var id = btn.closest('tr').getAttribute('data-id');
        if (!confirm('Delete credential profile ' + id + '?')) return;
        await fetch('/api/credentials/' + encodeURIComponent(id), { method: 'DELETE', headers: csrfHdr() });
        renderCreds();
      });
    });
  }
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
    document.getElementById('cred-form').reset(); renderCreds();
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
  async function refreshSettings() {
    var r = await fetch('/api/settings'); if (!r.ok) return;
    var s = await r.json();
    var rows = [
      ['Version', s.version],
      ['Admin', s.admin_username],
      ['Host IP', s.host_ip || '(unset)'],
      ['Ports', 'tracker ' + s.ports.tracker + ' · catalog ' + s.ports.catalog +
                ' · artifacts ' + s.ports.artifacts + ' · swarm ' + s.ports.swarm +
                ' · console ' + s.ports.console],
      ['Observability', s.observability.enabled
        ? ('on — ' + (s.observability.metrics_url || '')) : 'off']
    ];
    document.querySelector('#settings-info tbody').innerHTML = rows.map(function (kv) {
      return '<tr><td class="muted">' + esc(kv[0]) + '</td><td>' + esc(kv[1]) + '</td></tr>';
    }).join('');
    document.getElementById('sessions-info').textContent =
      s.sessions.active + ' active session(s); idle timeout ' +
      s.sessions.idle_ttl_minutes + ' min.';
    var sh = s.stage_host || {};
    document.getElementById('sh-status').textContent = sh.configured
      ? ('Configured — onboarding will ssh to the stage host as "' + sh.username + '".')
      : 'Not configured — needed when the Console runs in Docker, so the onboard ' +
        'installer can ssh to the stage host to stage per-device artifacts. ' +
        'Stored age-encrypted; the password is never shown again.';
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
    await Promise.all([refreshHistogram(), refreshAuditTable()]);
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

  // ---- hash router ----
  var VIEWS = ['overview', 'images', 'devices', 'swarm', 'settings', 'monitoring'];
  function show(view) {
    if (VIEWS.indexOf(view) < 0) view = 'overview';
    VIEWS.forEach(function (v) {
      document.getElementById('view-' + v).hidden = v !== view;
      var nav = document.getElementById('nav-' + v);
      if (nav) nav.classList.toggle('active', v === view);
    });
    if (view === 'overview') refreshOverview();
    else if (view === 'images') refreshImages();
    else if (view === 'devices') refreshDevices();
    else if (view === 'swarm') refreshSwarm();
    else if (view === 'settings') refreshSettings();
    else if (view === 'monitoring') refreshMonitoring();
  }
  function current() { return (location.hash || '#overview').slice(1); }
  window.addEventListener('hashchange', function () { show(current()); });
  show(current());
})();
