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
  // ---- Devices: column filters -------------------------------------------
  // Every bulk action operates on the checked rows, and only FILTERED rows are
  // rendered, so filtering then "select all" is how an operator acts on a
  // subset without hand-picking. Filter state lives in the DOM controls, not
  // in the row data, so the periodic re-render never clears it.
  var LAST_DEVICES = [];
  var LAST_DEV_NOW = 0;

  function deviceFilterState() {
    function val(id) {
      var el = document.getElementById(id);
      return el ? el.value : '';
    }
    return {
      q: val('dev-filter-q').trim().toLowerCase(),
      managementType: val('dev-filter-management-type'),
      platform: val('dev-filter-platform'),
      cred: val('dev-filter-cred'),
      telemetry: val('dev-filter-telemetry'),
      peer: val('dev-filter-peer'),
      status: val('dev-filter-status')
    };
  }

  // ONE derivation of the Status cell, read by the row renderer AND by the
  // filter. It used to be written twice, and the filter's copy knew only three
  // of the eleven states the cell can actually show: a device reading
  // "onboarding…", "placement failed" or "copying to bootflash:" could not be
  // picked from the Status filter at all, and asking for "enrolled" silently
  // swept them in. Returning the label and the class from the same place is
  // what makes the two structurally unable to disagree.
  //
  // Order matters and mirrors the cell exactly: job-aware states come FIRST,
  // because right after an onboard the agent needs minutes to bootstrap before
  // its first heartbeat, and without them the row reads "not enrolled" and
  // looks like the onboard did nothing.
  var DEVICE_STATUS_OPTIONS = [
    ['onboarding', 'onboarding'],
    ['undeploying', 'undeploying'],
    ['waiting-heartbeat', 'waiting for heartbeat'],
    ['onboard-failed', 'onboard failed'],
    ['undeploy-failed', 'undeploy failed'],
    ['deployed', 'deployed'],
    ['placement-failed', 'placement failed'],
    ['image-failed', 'image failed'],
    ['copying', 'copying to IOS storage'],
    ['staging', 'staging (other)'],
    ['enrolled', 'enrolled'],
    ['not-enrolled', 'not enrolled'],
    ['offline', 'offline (no recent heartbeat)']
  ];
  // The device's approved image ids, ordered. assigned_image_ids is absent
  // for a policy row that predates the ordered set (or simply unassigned),
  // so fall back to the singular field it still carries -- mirrors the
  // server's _row_assigned_ids exactly, so the two can never disagree about
  // what "assigned" means.
  function rowAssignedIds(d) {
    var ids = d.assigned_image_ids;
    if (ids && ids.length) return ids;
    return d.assigned_image_id ? [d.assigned_image_id] : [];
  }
  // Whether *d*'s device has staged image *iid*: membership in the
  // heartbeat's staged_image_ids when the agent reports it directly (Task
  // 3), else the legacy current_image_id/stage_state=='ready' pair for an
  // agent that predates the field. Mirrors the server's _row_has_staged.
  function rowHasStaged(d, iid) {
    var sids = d.staged_image_ids;
    if (sids != null) return sids.indexOf(iid) !== -1;
    return d.stage_state === 'ready' && d.current_image_id === iid;
  }
  // The images this device's last tick called a terminal per-image failure.
  // Empty for an agent that predates the field (and for a healthy set), so a
  // one-image agent's row is decided exactly as it always was.
  function rowErroredIds(d) {
    return d.errored_image_ids || [];
  }
  function deviceStatus(d, devNow) {
    // "no heartbeat since the job finished" — the job outcome is the freshest
    // truth we have about this device
    var jobFresh = d.onboard_finished_at &&
      (!d.last_seen || d.last_seen < d.onboard_finished_at);
    if (d.onboard_state === 'queued' || d.onboard_state === 'running') {
      return d.onboard_action === 'undeploy'
        ? { key: 'undeploying', label: 'undeploying…', cls: 'badge badge-running' }
        : { key: 'onboarding', label: 'onboarding…', cls: 'badge badge-running' };
    }
    if (d.onboard_state === 'done' && d.onboard_action === 'onboard' && jobFresh) {
      return { key: 'waiting-heartbeat', label: 'waiting for heartbeat',
               cls: 'badge badge-queued' };
    }
    if (d.onboard_state === 'error' && jobFresh) {
      return d.onboard_action === 'undeploy'
        ? { key: 'undeploy-failed', label: 'undeploy failed', cls: 'badge badge-fail' }
        : { key: 'onboard-failed', label: 'onboard failed', cls: 'badge badge-fail' };
    }
    // "deployed" = every image in the assigned SET is staged and verified on
    // the box -- not just one of them. rowHasStaged() folds in the legacy
    // fallback for an agent that predates staged_image_ids, so a one-image
    // set on an old agent is exactly today's single-field check.
    var assignedIds = rowAssignedIds(d);
    // Images of the set the agent's own last tick gave up on. They are not
    // staged, so the set is not deployed -- this cell used to answer
    // "deployed" before it looked at any error, and read all-green beside a
    // drawer and a swarm map both showing the same image as failed.
    var erroredIds = rowErroredIds(d).filter(function (iid) {
      return assignedIds.indexOf(iid) !== -1;
    });
    if (assignedIds.length && !erroredIds.length &&
        assignedIds.every(function (iid) { return rowHasStaged(d, iid); })) {
      return { key: 'deployed', label: 'deployed', cls: 'badge badge-ok' };
    }
    // Named per-image failures beat the collapsed single stage_state below:
    // that one string is whatever the tick found most actionable, so falling
    // through to it would report a set with three dead images as whatever the
    // fourth is doing. The drawer says WHICH images these are.
    if (erroredIds.length) {
      return { key: 'image-failed',
               label: erroredIds.length + ' of ' + assignedIds.length +
                      ' image(s) failed',
               cls: 'badge badge-fail', detail: d.stage_error };
    }
    if (d.stage_error) {
      return { key: 'placement-failed', label: 'placement failed',
               cls: 'badge badge-fail', detail: d.stage_error };
    }
    if (d.stage_state === 'transferring_to_ios') {
      return { key: 'copying', label: 'copying to ' + (d.target_fs || 'IOS storage'),
               cls: 'badge badge-running' };
    }
    if (d.stage_state) {
      return { key: 'staging', label: d.stage_state, cls: 'badge badge-running' };
    }
    if (d.last_seen) {
      return { key: 'enrolled', label: 'enrolled', cls: 'badge badge-queued' };
    }
    return { key: 'not-enrolled', label: 'not enrolled', cls: 'muted' };
  }
  function deviceStatusHtml(d, devNow) {
    var st = deviceStatus(d, devNow);
    var title = st.detail ? ' title="' + esc(st.detail) + '"' : '';
    var html = '<span class="' + st.cls + '"' + title + '>' + esc(st.label) + '</span>';
    if (st.detail) {
      html += ' <span class="muted"' + title + '>' + esc(st.detail) + '</span>';
    }
    if (deviceIsOffline(d, devNow)) {
      html += ' <span class="muted" style="font-size:10px">offline</span>';
    }
    return html;
  }
  function deviceIsOffline(d, devNow) {
    return !!(d.last_seen && (devNow - d.last_seen) >= 600);
  }

  function deviceMatchesFilters(d, f, devNow) {
    if (f.q) {
      var hay = [d.device_id, d.device_ip, d.model, d.heartbeat_model]
        .filter(Boolean).join(' ').toLowerCase();
      if (hay.indexOf(f.q) === -1) return false;
    }
    if (f.managementType &&
        (d.management_type || 'legacy') !== f.managementType) return false;
    if (f.platform) {
      var plat = d.platform || '';
      if (f.platform === '__none' ? plat !== '' : plat !== f.platform) return false;
    }
    if (f.cred) {
      var cred = d.credential_profile_id || '';
      if (f.cred === '__none' ? cred !== '' : cred !== f.cred) return false;
    }
    if (f.telemetry) {
      var tel = d.telemetry_enabled === false ? 'off' : 'on';
      if (tel !== f.telemetry) return false;
    }
    if (f.peer) {
      var q = peerPolicyAssigned(d.device_id) ? 'quarantined' : 'not-quarantined';
      if (q !== f.peer) return false;
    }
    if (f.status) {
      // "offline" is a modifier on top of whatever the cell says (a device can
      // read "deployed" and still be stale), so it stays its own choice.
      if (f.status === 'offline') { if (!deviceIsOffline(d, devNow)) return false; }
      else if (deviceStatus(d, devNow).key !== f.status) return false;
    }
    return true;
  }

  // Re-render from the devices already in hand -- filtering must not wait on
  // (or fire) a network round trip.
  function applyDeviceFilters() { renderDevices(LAST_DEVICES, LAST_DEV_NOW); }

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
  // The full last-fetched /api/images rows, kept for the image-detail drawer
  // (KGV / Cisco Bulk Hash reconciler, Task 5) -- refreshImages() only ever
  // wrote row HTML before, with nowhere to read a single image's verdict
  // back out of once the drawer needed one.
  var LAST_IMAGES = [];
  // Verdict badge shared by the Images table, the image-detail drawer and
  // the image picker: null state (never checked) reads as neutral, a
  // mismatch reads as quarantined only while quarantined is actually still
  // true (an override-released mismatch stays a mismatch verdict forever --
  // release_quarantine() deliberately never rewrites hash_verification.state
  // -- but it is no longer BLOCKING anything, so it must not keep claiming
  // "quarantined"). Deferral is an orthogonal warning that can accompany any
  // state, per the spec.
  function bulkhashVerdictBadge(hv, quarantined) {
    var state = hv && hv.state;
    var html;
    if (!state) {
      html = '<span class="badge badge-queued">Not checked</span>';
    } else if (state === 'verified') {
      html = '<span class="badge badge-ok">Verified</span>';
    } else if (state === 'mismatch') {
      html = quarantined
        ? '<span class="badge badge-fail">MISMATCH — quarantined</span>'
        : '<span class="badge badge-fail">MISMATCH — released</span>';
    } else if (state === 'not_in_feed') {
      html = '<span class="badge badge-queued">Not in Cisco\'s feed</span>';
    } else {
      // Defensive: bulkhash.py only ever writes verified/mismatch/
      // not_in_feed, but a catch-all that silently relabeled anything else
      // as "Not in Cisco's feed" would misreport a genuinely unrecognized
      // state as a specific, wrong verdict instead of admitting it doesn't
      // know.
      html = '<span class="badge badge-queued">Unknown verification state</span>';
    }
    if (hv && hv.deferral) {
      html += ' <span class="badge badge-cancelled" title="Deferred by Cisco">⚠ Deferred by Cisco</span>';
    }
    return html;
  }
  async function refreshImages() {
    var r = await fetch('/api/images'); if (!r.ok) return;
    var imgs = (await r.json()).images || [];
    imgs.sort(function (a, b) { return (b.published_at || 0) - (a.published_at || 0); });
    LAST_IMAGES = imgs;
    document.getElementById('rows').innerHTML = imgs.map(function (i) {
      return '<tr data-id="' + esc(i.id) + '"><td>' + esc(i.id) + '</td><td>' + esc(i.filename || '') + '</td><td>' +
        esc(fmtSize(i.size)) + '</td><td>' + esc((i.sha256 || '').slice(0, 16)) + '…</td><td>' +
        esc(fmtDate(i.published_at)) + '</td><td>' + bulkhashVerdictBadge(i.hash_verification, i.quarantined) +
        '</td><td><button class="linkish img-info" title="Image details" aria-label="' +
        'Image details for ' + esc(i.id) + '">ⓘ</button> ' +
        '<button class="linkish danger-link del-img">delete</button></td></tr>';
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
    document.querySelectorAll('#rows .img-info').forEach(function (btn) {
      btn.addEventListener('click', function () {
        openImageInfo(btn.closest('tr').getAttribute('data-id'));
      });
    });
  }
  // ---- Image detail drawer: verdict + release-from-quarantine, with the
  // typed-confirm override path (KGV / Cisco Bulk Hash reconciler, Task 5).
  // Mirrors openDeployInfo/closeDeployInfo's drawer pattern below.
  var imgInfoId = null;
  function imageVerdictDetailText(hv) {
    if (!hv || !hv.checked_at) return 'Never checked against the Cisco Bulk Hash feed.';
    var text = 'Checked ' + fmtDate(hv.checked_at) + ' (source: ' + (hv.source || 'unknown') + ')';
    if (hv.feed_published_at) text += '; feed published ' + fmtDate(hv.feed_published_at);
    return text + '.';
  }
  function openImageInfo(id) {
    imgInfoId = id;
    var img = LAST_IMAGES.filter(function (x) { return x.id === id; })[0] || {};
    document.getElementById('ii-id').textContent = id;
    document.getElementById('ii-file').textContent = img.filename || '';
    document.getElementById('ii-verdict').innerHTML = bulkhashVerdictBadge(img.hash_verification, img.quarantined);
    document.getElementById('ii-verdict-detail').textContent = imageVerdictDetailText(img.hash_verification);
    // The release action only makes sense while an image is ACTUALLY
    // quarantined -- an override-released mismatch keeps its "mismatch"
    // verdict (see bulkhashVerdictBadge) but is not blocking anything, so
    // there is nothing left here to release.
    document.getElementById('ii-release-block').hidden = !img.quarantined;
    document.getElementById('ii-override-block').hidden = true;
    document.getElementById('ii-override-note').textContent = '';
    document.getElementById('ii-confirm-text').value = '';
    document.getElementById('ii-release-msg').textContent = '';
    document.getElementById('img-info-panel').hidden = false;
  }
  function closeImageInfo() {
    imgInfoId = null;
    document.getElementById('img-info-panel').hidden = true;
  }
  document.getElementById('ii-close').addEventListener('click', closeImageInfo);
  document.addEventListener('keydown', function (e) {
    var panel = document.getElementById('img-info-panel');
    if (e.key === 'Escape' && panel && !panel.hidden) closeImageInfo();
  });
  // Normal release first; the API answers 409 quarantine_still_mismatched
  // when the stored sha512 still disagrees, which is when the override path
  // (typed filename confirmation) appears. Every other failure is surfaced
  // via the API's own error message, honestly, rather than a made-up one.
  async function attemptReleaseQuarantine(override, confirmText) {
    var msg = document.getElementById('ii-release-msg'); msg.textContent = '';
    var releaseBtn = document.getElementById('ii-release');
    var overrideBtn = document.getElementById('ii-release-override');
    releaseBtn.disabled = true; overrideBtn.disabled = true;
    try {
      var r = await jpost('/api/images/' + encodeURIComponent(imgInfoId) + '/release-quarantine',
        { override: override, confirm_text: confirmText });
      var body = {};
      try { body = await r.json(); } catch (e) { }
      if (r.ok) {
        closeImageInfo(); refreshImages();
        // Same reason as the Refresh now / offline upload handlers below:
        // keeps imageQuarantined (the picker's block list) from lagging
        // this release by up to one periodic devices-view poll interval,
        // during which the just-released image would stay unpickable.
        refreshDevices().catch(function () { });
        return;
      }
      if (r.status === 409 && body.error === 'quarantine_still_mismatched') {
        document.getElementById('ii-override-block').hidden = false;
        document.getElementById('ii-override-note').textContent =
          'Still mismatching the Cisco feed — type the exact filename below to override.';
        return;
      }
      msg.textContent = body.error || ('Release failed (' + r.status + ').');
    } catch (e) {
      msg.textContent = 'Network error — release request failed.';
    } finally {
      releaseBtn.disabled = false; overrideBtn.disabled = false;
    }
  }
  document.getElementById('ii-release').addEventListener('click', function () {
    attemptReleaseQuarantine(false, '');
  });
  document.getElementById('ii-release-override').addEventListener('click', function () {
    attemptReleaseQuarantine(true, document.getElementById('ii-confirm-text').value);
  });
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
        if (!r.ok) {
          // A non-OK status (401 session gone, 404 job evicted/unknown) never
          // heals — stop the poller and surface it in the row instead of
          // spinning forever. Network blips (catch below) still retry.
          ui.error('publish status unavailable (' + r.status + ')');
          return;
        }
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
  // Whether imageIds/imageFilenames came from a SUCCESSFUL /api/images read.
  // A failed fetch substitutes an empty list, which is indistinguishable from
  // an empty catalog once it reaches the picker -- and a picker showing no
  // images can only be applied as "unassign everything".
  var imageListOk = false;
  // id -> filename, refreshed alongside imageIds -- so a picker/drawer row
  // can show which file an id actually is, the way the catalog list does.
  var imageFilenames = {};
  // id -> quarantined bool, refreshed alongside imageIds (KGV / Cisco Bulk
  // Hash reconciler, Task 5) -- so the picker can visibly block a
  // quarantined image instead of only relying on the server's own
  // set_policy() refusal, which the operator would only discover at Apply.
  var imageQuarantined = {};
  var credOpts = [];
  var peerPolicy = { revision: null, quarantine_assignments: [], enforcement: {} };
  var peerPolicyBusy = {};
  function peerPolicyAssigned(deviceId) {
    return (peerPolicy.quarantine_assignments || []).indexOf(deviceId) !== -1;
  }
  function peerPolicyStatus() {
    var e = peerPolicy.enforcement || {};
    var state = ['pending', 'enforced', 'degraded', 'rpc_unavailable', 'fail_closed'].indexOf(e.state) !== -1
      ? e.state : 'pending';
    var details = 'Last tracker enforcement: ' + state + '; desired peers: ' +
      (typeof e.desired_ip_count === 'number' ? e.desired_ip_count : 0);
    if (e.conflict_count) details += '; conflicts: ' + (e.conflict_types || []).join(', ');
    return '<span class="badge ' + (state === 'enforced' ? 'badge-ok' :
      (state === 'degraded' || state === 'fail_closed' ? 'badge-fail' : 'badge-queued')) +
      '" title="' + esc(details) + '">' + esc(state) + '</span>';
  }
  var devicesRefreshGeneration = 0, devicesRefreshController = null;
  async function setQuarantine(btn) {
    var id = btn.closest('tr').getAttribute('data-id');
    var quarantined = !peerPolicyAssigned(id);
    var action = quarantined ? 'Quarantine' : 'Release';
    if (!confirm(action + ' ' + id + '?\n\nThis changes peer discovery and the server seeder across all torrents. ' +
        'It may not terminate existing device-to-device sessions immediately. It never installs or reloads a device.')) return;
    btn.disabled = true;
    peerPolicyBusy[id] = true;
    try {
      var r = await fetch('/api/peer-policy/quarantine/' + encodeURIComponent(id), {
        method: 'PUT', headers: csrfHdr({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ quarantined: quarantined, if_revision: peerPolicy.revision })
      });
      var body = await r.json().catch(function () { return {}; });
      if (r.ok) {
        peerPolicy.revision = body.revision;
        peerPolicy.quarantine_assignments = (peerPolicy.quarantine_assignments || []).filter(function (x) { return x !== id; });
        if (body.quarantined) peerPolicy.quarantine_assignments.push(id);
        devStatus.textContent = action + ' intent saved for ' + id + '.';
        // The mutation is already committed. A follow-up read failure may leave
        // the view stale, but must never turn a truthful success into "failed".
        refreshDevices().catch(function () {});
      } else if (r.status === 409) {
        devStatus.textContent = 'Peer policy changed elsewhere. Review the current policy and retry; no change was made.';
        // Refresh best-effort without masking the accurate conflict outcome.
        refreshDevices().catch(function () {});
      } else if (r.status === 503 && body.error === 'operation_backlog_full') {
        devStatus.textContent = 'Peer-policy operation backlog is full; retry later.';
      } else {
        devStatus.textContent = 'Peer-policy update failed: ' + (body.error || r.status) + '.';
      }
    } catch (e) {
      devStatus.textContent = 'Peer-policy update failed; retry later.';
    } finally {
      delete peerPolicyBusy[id];
      if (btn.isConnected) btn.disabled = false;
    }
  }
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
    var mine = ++devicesRefreshGeneration;
    if (devicesRefreshController) devicesRefreshController.abort();
    devicesRefreshController = new AbortController();
    var signal = devicesRefreshController.signal;
    var results;
    try {
      results = await Promise.all([fetch('/api/devices', { signal: signal }), fetch('/api/images', { signal: signal }), fetch('/api/credentials', { signal: signal }), fetch('/api/peer-policy', { signal: signal })]);
    } catch (e) {
      // Superseding a refresh is expected; callers must not see an unhandled
      // AbortError. Other failures still reach their caller/status handling.
      if (e && e.name === 'AbortError') return;
      throw e;
    }
    var dr = results[0], ir = results[1], cr = results[2], pr = results[3];
    if (!dr.ok || mine !== devicesRefreshGeneration) return;
    var nextPolicy = pr.ok ? await pr.json() : peerPolicy;
    var dbody = await dr.json();
    if (mine !== devicesRefreshGeneration) return;
    peerPolicy = nextPolicy;
    var devs = dbody.devices || [];
    var devNow = dbody.now || Date.now() / 1000;   // server clock for last_seen freshness
    var imgs = ir.ok ? ((await ir.json()).images || []) : [];
    imageListOk = ir.ok;
    imageIds = imgs.map(function (i) { return i.id; });
    imageFilenames = {};
    imageQuarantined = {};
    imgs.forEach(function (i) {
      imageFilenames[i.id] = i.filename || '';
      imageQuarantined[i.id] = !!i.quarantined;
    });
    credOpts = cr.ok ? ((await cr.json()).profiles || []) : [];
    if (mine !== devicesRefreshGeneration) return;
    syncCredSelected();
    LAST_DEVICES = devs;
    LAST_DEV_NOW = devNow;
    syncDeviceFilterOptions();
    renderDevices(devs, devNow);
  }

  // Populate the credential filter from the profiles that actually exist,
  // preserving the operator's current choice even if it is momentarily absent
  // from a slow /api/credentials response.
  function syncDeviceFilterOptions() {
    var sel = document.getElementById('dev-filter-cred');
    if (!sel) return;
    var keep = sel.value;
    sel.innerHTML = ['<option value="">Credential: any</option>',
                     '<option value="__none">— none —</option>']
      .concat(credOpts.map(function (c) {
        return '<option value="' + esc(c.id) + '">' + esc(c.id) + '</option>';
      })).join('');
    sel.value = keep;
    if (sel.value !== keep) sel.value = '';
  }

  function renderDevices(devs, devNow) {
    var filters = deviceFilterState();
    var total = devs.length;
    devs = devs.filter(function (d) { return deviceMatchesFilters(d, filters, devNow); });
    // keep batch checkbox selections across the periodic re-render
    var marked = {};
    document.querySelectorAll('#dev-rows .mark:checked').forEach(function (cb) {
      marked[cb.getAttribute('data-id')] = true;
    });
    document.getElementById('dev-rows').innerHTML = devs.map(function (d) {
      var rowIds = rowAssignedIds(d);
      var assignLabel = rowIds.length ? (rowIds.length + ' image(s)') : '— assign —';
      var credSel = ['<option value="">— no credential —</option>'].concat(credOpts.map(function (c) {
        return '<option value="' + esc(c.id) + '"' + (c.id === d.credential_profile_id ? ' selected' : '') + '>' + esc(c.id) + '</option>';
      })).join('');
      var platVal = d.platform || '';
      var platSel = [
        ['', '— auto —'], ['guestshell', 'Guest Shell'], ['iox', 'IOx'],
        ['router', 'Router (VPG)'], ['xr-appmgr', 'XR appmgr container']
      ].map(function (o) {
        return '<option value="' + esc(o[0]) + '"' + (o[0] === platVal ? ' selected' : '') + '>' + esc(o[1]) + '</option>';
      }).join('');
      var status = deviceStatusHtml(d, devNow);
      var managementType = d.management_type || 'legacy';
      var managementTypeDetail = managementType.indexOf('router-') === 0
        ? (' / VPG' + (d.vpg_number == null ? '' : d.vpg_number))
        : (' / ' + (d.inband_vlan || d.iris_vlan || ''));
      var managementTypeLabel = (managementType === 'legacy_routed' || managementType === 'legacy')
        ? 'Inventory only — management type not chosen'
        : managementType === 'xr-host' ? 'XR host'
        : (managementType + managementTypeDetail);
      return '<tr data-id="' + esc(d.device_id) + '">' +
        '<td><input type="checkbox" class="mark" data-id="' + esc(d.device_id) + '"' +
        (marked[d.device_id] ? ' checked' : '') + '></td>' +
        '<td>' + esc(d.device_id) + '</td><td>' + esc(d.device_ip || '') + '</td>' +
        '<td>' + esc(d.model || d.heartbeat_model || '') + '</td>' +
        '<td>' + esc(managementTypeLabel) + '</td>' +
        '<td><select class="platform">' + platSel + '</select></td>' +
        '<td><select class="cred">' + credSel + '</select></td>' +
        '<td><button type="button" class="linkish assign-btn">' + esc(assignLabel) + '</button></td>' +
        '<td>' + telemetryCell(d) + '</td>' +
        '<td><span class="peer-intent">' + (peerPolicyAssigned(d.device_id) ? 'Quarantined intent' : 'Not quarantined') +
        '</span> ' + peerPolicyStatus() + ' <button type="button" class="linkish peer-quarantine" ' +
        'title="' + (peerPolicyAssigned(d.device_id) ? 'Release device from quarantine' : 'Quarantine device') + '" aria-label="' +
        (peerPolicyAssigned(d.device_id) ? 'Release ' : 'Quarantine ') + esc(d.device_id) + '"' +
        (peerPolicyBusy[d.device_id] ? ' disabled' : '') + '>' +
        (peerPolicyAssigned(d.device_id) ? 'Release' : 'Quarantine') + '</button></td>' +
        '<td>' + status +
        ' <button class="linkish dinfo" title="Deployment details">ⓘ</button></td></tr>';
    }).join('');
    document.querySelectorAll('#dev-rows .assign-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        openRowAssign(btn.closest('tr').getAttribute('data-id'), btn);
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
          devStatus.textContent = 'Agent install updated for ' + id;
        } else {
          // surface the real reason and revert the dropdown to the saved value
          devStatus.textContent = 'Agent install update failed: ' + ((await r.json()).error || r.status);
          refreshDevices();
        }
      });
    });
    document.querySelectorAll('#dev-rows .dinfo').forEach(function (btn) {
      btn.addEventListener('click', function () {
        openDeployInfo(btn.closest('tr').getAttribute('data-id'));
      });
    });
    document.querySelectorAll('#dev-rows .peer-quarantine').forEach(function (btn) {
      btn.addEventListener('click', function () { setQuarantine(btn); });
    });
    document.getElementById('mark-all').checked = false;
    document.getElementById('dev-count').textContent =
      total + ' device' + (total === 1 ? '' : 's');
    var fc = document.getElementById('dev-filter-count');
    if (fc) {
      fc.textContent = devs.length === total ? ''
        : ('showing ' + devs.length + ' of ' + total);
    }
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
    var attach = res.management_type || '';
    // xr-host carries none of the four addressing rows below -- the
    // appmgr container runs on the router's own network stack -- so they
    // are dropped from the table entirely rather than shown as dashes,
    // which would read as "unknown" instead of "not applicable".
    var xrHost = attach === 'xr-host';
    var attachLabel = xrHost ? 'XR host' : attach;
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
      ['Management type', esc(attachLabel || '—')]
    ];
    if (!xrHost) {
      pairs.push(
        ['Management VLAN / VPG', esc(mgmt || '—')],
        ['SVI', esc(svi || '—')],
        ['App IP', esc(app || '—')],
        ['NAT interface', esc(res.nat_interface || '—')]
      );
    }
    pairs.push(
      ['Swarm port', esc(res.swarm_port || '—')],
      ['Model', esc(res.model || '—')],
      ['Agent install', esc(res.platform || '—')],
      ['Device identity', esc(res.device_identity || '—')]
    );
    return pairs.map(function (kv) {
      return '<tr><td class="muted">' + esc(kv[0]) + '</td><td>' + kv[1] + '</td></tr>';
    }).join('');
  }
  // One row per assigned image: id + state, resolved from the per-image
  // MEMBERSHIP the agent reports -- staged_image_ids first, then
  // errored_image_ids -- which is exactly how the Swarm Map's own image list
  // resolves it, so two views of one heartbeat cannot disagree about an image.
  //
  // current_image_id is deliberately NOT consulted here. It is the wire-compat
  // identity pointer: the FIRST image of the set that produced heartbeat data
  // this tick, which is typically one already staged -- not the one in flight.
  // Reading it as "the image currently transferring" is what left a failed
  // image that happened not to be it reading "queued" in this drawer while the
  // map showed it as "error", and pinned the tick's stage_error to a row that
  // had nothing to do with it.
  //
  // stage_state and stage_error describe the whole TICK, not one image, so
  // they are shown against an image only where they unambiguously are that
  // image's own: an agent reporting no per-image lists at all, which is a
  // one-image heartbeat and always has been. For a set, the tick's error rides
  // its own row below the images, attributed no further than the agent
  // attributes it. Parked is deliberately not a state here: a parked image is
  // no longer in the assigned set, so it never produces a row at all.
  function deployImageRows(d) {
    var ids = rowAssignedIds(d);
    if (!ids.length) {
      return '<tr><td colspan="2" class="muted">No images assigned.</td></tr>';
    }
    var errored = rowErroredIds(d);
    var perImage = d.staged_image_ids != null || d.errored_image_ids != null;
    var rows = ids.map(function (iid) {
      var state;
      if (rowHasStaged(d, iid)) {
        state = 'ready';
      } else if (errored.indexOf(iid) !== -1) {
        state = 'error';
      } else if (!perImage) {
        state = (d.stage_state || 'staging') + (d.stage_error ? ' — ' + d.stage_error : '');
      } else {
        // neither staged nor errored this tick: genuinely still in flight
        state = 'staging';
      }
      return '<tr><td class="mono">' + imageLabel(iid) + '</td><td>' + esc(state) + '</td></tr>';
    }).join('');
    if (perImage && d.stage_error) {
      rows += '<tr><td class="muted">Last reported error</td><td>' +
        esc(d.stage_error) + '</td></tr>';
    }
    return rows;
  }
  async function openDeployInfo(id) {
    deployInfoDev = id;
    var note = document.getElementById('di-note');
    document.getElementById('di-dev').textContent = id;
    document.getElementById('di-rows').innerHTML = '';
    document.getElementById('di-log-rows').innerHTML = '';
    var d = LAST_DEVICES.filter(function (x) { return x.device_id === id; })[0] || {};
    document.getElementById('di-img-rows').innerHTML = deployImageRows(d);
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
      // Deployment logs deliberately outlive a delete — they are the record of
      // what actually ran. So a device deleted and added back under the same
      // name inherits its predecessor's runs, and without this they read as its
      // own history. The run is kept and shown; it is just never presented as
      // belonging to the device currently holding the name.
      var prev = l.previous_registration
        ? ' <span class="badge badge-off" title="This run finished before the' +
          ' current device was registered under this name, so it belongs to a' +
          ' previous device.">previous device</span>'
        : '';
      return '<tr data-file="' + esc(l.file) + '"><td>' + esc(fmtDate(l.finished_at)) +
        prev + '</td><td>' + esc(l.action || '') + '</td><td>' + deployLogResult(l) +
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
  function closeDeployInfo() {
    deployInfoDev = null;
    document.getElementById('deploy-info-panel').hidden = true;
  }
  document.getElementById('di-close').addEventListener('click', closeDeployInfo);
  // Escape closes it, the same as the deployment-log drawer: a drawer that
  // covers part of the table needs a way out that is not aiming for the ✕.
  document.addEventListener('keydown', function (e) {
    var panel = document.getElementById('deploy-info-panel');
    if (e.key === 'Escape' && panel && !panel.hidden) closeDeployInfo();
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
    // Tracks whether the job is still parked in the queue: log lines only
    // exist once a job runs, so the first streamed message means it started.
    var isQueued = !!queued;
    if (queued) append('(queued — waiting for a free install slot; the log streams once it starts)');
    var es = new EventSource('/api/onboard/jobs/' + encodeURIComponent(jobId) + '/stream');
    entry.es = es;
    es.onmessage = function (e) { isQueued = false; append(e.data); };
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
      // A queued job has no registered process, so the abort route can only
      // 409 — take it out of the queue instead, scoped to just this job
      // (same endpoint the batch panel's cancel uses).
      if (isQueued) {
        var qr = await jpost('/api/onboard/cancel-queued', { job_ids: [jobId] });
        if (!qr.ok) { append('[cancel failed (' + qr.status + ')]'); return; }
        var cancelled = 0;
        try { cancelled = (await qr.json()).cancelled || 0; } catch (e2) { }
        if (cancelled) { append('[cancelled while queued]'); return; }
        isQueued = false;   // won a slot between open and click: abort the running job
      }
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
  wireMenu('undeploy-menu-btn', 'undeploy-pop');
  wireMenu('help-btn', 'help-pop');
  function updateSelBar() {
    var n = document.querySelectorAll('#dev-rows .mark:checked').length;
    document.getElementById('sel-bar').hidden = n === 0;
    document.getElementById('sel-count').textContent = n + ' selected';
    document.getElementById('onboard-selected').textContent = 'Start onboard (' + n + ')';
    document.getElementById('assign-images-selected').textContent =
      'Assign images to ' + n + ' devices…';
    document.querySelectorAll('#dev-rows tr').forEach(function (tr) {
      var cb = tr.querySelector('.mark');
      tr.classList.toggle('sel', !!(cb && cb.checked));
    });
    // An empty selection closes the selection-scoped popovers — but never
    // the header help popover: the 10s devices poll re-renders the (empty)
    // table and lands here with n === 0, and yanking an open "?" panel out
    // from under the operator reads as a broken control.
    if (n === 0 && openMenuPanel && openMenuPanel.id !== 'help-pop') closeMenus();
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
    var forceEl = document.getElementById('undeploy-force');
    var forced = action === 'undeploy' && forceEl && forceEl.checked;
    if (action === 'undeploy' &&
        !confirm('Undeploy ' + ids.length + ' device(s)?' + (forced
          ? '\n\nFORCE is on. For any device with no deployment receipt this removes the IRIS agent footprint only — EEM applets, Guest Shell and the IRIS guest-share files. The VirtualPortGroup and NAT are NOT removed, because without a receipt there is no proof IRIS created them; clean those up yourself if IRIS did. On an IOS-XR device, force removes the same IRIS-named footprint a normal undeploy would — the appmgr application iris, its iris-xr package source, the RPM, iris-work/, and the IRIS sidecar files at harddisk: root — but a staged image file there is never removed by IRIS teardown, and the agent deletes an adopted file only when the catalog republishes new content under that same image id — never otherwise.'
          : '\n\nThis removes the device agent (Guest Shell or IOx app) and only receipt-owned resources. Inband deployments preserve their existing network; router NAT preserves a pre-existing outside marking.') +
                 '\n\nStaged images at the filesystem root are left in place. Running jobs are never interrupted.')) {
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
                              action === 'onboard' ? telemetryFlags()
                                : (forced ? { force: true } : {}));
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
                   'delete-selected', 'apply-cred-selected',
                   'assign-images-selected',
                   'quarantine-selected', 'release-selected'];
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
  // "id — filename", both escaped -- the same two facts the catalog list
  // shows for an image, so a picker/drawer row never makes the operator go
  // find the id in the Images tab to see what it actually is. Falls back to
  // the bare id when the filename is not known (a stale id the catalog no
  // longer has, or imageFilenames not loaded yet).
  function imageLabel(id) {
    var fn = imageFilenames[id];
    return fn ? esc(id) + ' — ' + esc(fn) : esc(id);
  }
  // ---- Image picker: one control shared by the per-row assign button and
  // the bulk "Assign images to N devices…" toolbar action below. Both POST
  // the checked ids, in the order the checked-first render placed them,
  // through the SAME ordered-set body (image_ids) -- there is exactly one
  // way to pick images in this console, whether for one device or many, so
  // the row select and the bulk dropdown that used to do this separately
  // cannot drift apart again.
  var imgPickerOnApply = null;
  // Open the picker for ONE device and apply what comes back. Named, because
  // two callers need it: each row's assign button, and the conflict retry in
  // assignImagesTo -- a lost race must re-open the very control the operator
  // was using, on the set that is really stored now.
  function openRowAssign(id, btn) {
    if (!imageListOk) {
      devStatus.textContent = 'Image list unavailable; not opening the picker. ' +
        'Retry once the Images list loads.';
      return;
    }
    var d = LAST_DEVICES.filter(function (x) { return x.device_id === id; })[0] || {};
    var current = rowAssignedIds(d);
    // Device ids are operator-chosen strings, so the map must not inherit
    // (or assign into) anything from Object.prototype.
    var expect = Object.create(null);
    expect[id] = current;
    openImagePicker(current, function (ids) {
      // An empty pick is a deliberate unassign for a device that already
      // has one; for anything else it is one unchecked box away from
      // wiping the assigned set by accident, so confirm before it posts.
      if (!ids.length && !confirm('Unassign all images from ' + id + '?')) return;
      // ONE row is not a selected-action, so this must never touch the
      // shared bulk lock: releasing it here re-enabled every bulk button
      // mid-batch. The row's own button carries the busy state instead.
      if (btn) btn.disabled = true;
      assignImagesTo([id], ids, { ownsBulkLock: false, expect: expect })
        .then(function () {
          // the refresh may have re-rendered this row out from under us
          if (btn && btn.isConnected) btn.disabled = false;
        });
    });
  }
  function openImagePicker(currentIds, onApply) {
    var overlay = document.getElementById('img-picker');
    var rows = document.getElementById('img-picker-rows');
    var counter = document.getElementById('img-picker-count');
    // Reset any note left over from a previous open (the bulk caller below
    // sets one back on right after this returns, when it applies).
    var note = document.getElementById('img-picker-note');
    if (note) note.hidden = true;
    var checkedSet = {};
    (currentIds || []).forEach(function (id) { checkedSet[id] = true; });
    // checked-first: the current set, in its own order, before every other
    // catalog image -- so what is already assigned is never buried below
    // the fold in a large catalog, and Apply's read order (top to bottom)
    // preserves it.
    // An assigned id the catalog list does not carry used to be filtered out
    // of the picker entirely. Apply posts exactly what is checked, so the id
    // the operator was never shown was removed from the device by the act of
    // looking. It keeps its place in the order instead, checked and disabled,
    // and applying preserves it.
    var ordered = (currentIds || [])
      .concat(imageIds.filter(function (id) { return !checkedSet[id]; }));
    rows.innerHTML = ordered.length ? ordered.map(function (id) {
      var unknown = imageIds.indexOf(id) === -1;
      // Quarantined images are visibly blocked here rather than silently
      // hidden (KGV / Cisco Bulk Hash reconciler, Task 5) -- but only from
      // being NEWLY checked. One already checked (assigned before it was
      // quarantined) stays togglable at RENDER time so the operator can
      // still uncheck it to remove the bad assignment -- but every
      // quarantined row (checked or not) carries data-blocked="1" so that
      // the moment it IS unchecked, updateCount's own disable sweep below
      // catches it and it cannot be re-checked. Without data-blocked on the
      // checked row too, unchecking it produced a plain unchecked-and-
      // enabled box indistinguishable from any other image, and the
      // operator could tick it straight back. The server's own
      // set_policy() refusal (QuarantinedImage -> 400) stays the backstop
      // either way.
      var quarantined = !!imageQuarantined[id];
      var blocked = quarantined && !checkedSet[id];
      return '<label class="img-pick-row"><input type="checkbox" class="img-pick" value="' +
        esc(id) + '"' + (checkedSet[id] ? ' checked' : '') + (unknown ? ' disabled' : '') +
        (blocked && !unknown ? ' disabled' : '') +
        (quarantined ? ' data-blocked="1"' : '') +
        '> ' + imageLabel(id) +
        (quarantined ? ' <span class="badge badge-fail" title="Hash mismatch — ' +
          'quarantined by the Cisco Bulk Hash reconciler">quarantined</span>' : '') +
        (unknown ? ' <span class="muted">— not in the catalog; kept as assigned</span>' : '') +
        (blocked ? ' <span class="muted">— quarantined; cannot be newly assigned</span>' : '') +
        '</label>';
    }).join('') : '<p class="muted">No images in the catalog yet.</p>';
    function updateCount() {
      var n = rows.querySelectorAll('input:checked').length;
      counter.textContent = n + '/10';
      // the 11th box is disabled, not just rejected server-side at Apply;
      // a quarantined row (data-blocked) stays disabled regardless of
      // count, never re-enabled just because the selection dropped -- and
      // this sweep is what catches a quarantined row the MOMENT it is
      // unchecked (see the render-time comment above), since every
      // quarantined row carries data-blocked="1" whether or not it started
      // checked.
      rows.querySelectorAll('input:not(:checked)').forEach(function (cb) {
        cb.disabled = n >= 10 || cb.dataset.blocked === '1';
      });
    }
    rows.querySelectorAll('input').forEach(function (cb) { cb.addEventListener('change', updateCount); });
    updateCount();
    imgPickerOnApply = function () {
      var ids = Array.prototype.map.call(rows.querySelectorAll('input:checked'),
        function (cb) { return cb.value; });
      closeImagePicker();
      onApply(ids);
    };
    overlay.hidden = false;
  }
  function closeImagePicker() {
    document.getElementById('img-picker').hidden = true;
    imgPickerOnApply = null;
  }
  document.getElementById('img-picker-apply').addEventListener('click', function () {
    if (imgPickerOnApply) imgPickerOnApply();
  });
  // Cancel closes without ever POSTing -- picking is a deliberate confirm.
  document.getElementById('img-picker-cancel').addEventListener('click', closeImagePicker);
  document.addEventListener('keydown', function (e) {
    var overlay = document.getElementById('img-picker');
    if (e.key === 'Escape' && overlay && !overlay.hidden) closeImagePicker();
  });
  function delWarning(ids) {
    // Removing inventory does NOT undeploy: an onboarded device keeps running
    // its agent with no Console record of it, so say so before it happens.
    return 'Delete ' + ids.length + ' device(s) from the inventory?\n\n' +
      ids.join(', ') + '\n\nThis removes the Console record only — it does NOT ' +
      'undeploy. An onboarded device keeps its agent and staged image with no ' +
      'inventory entry left to manage it. Undeploy first if that is what you want.' +
      '\n\nAny deployment receipt is abandoned: it is kept as the record of what ' +
      'IRIS built on the box, but it stops authorising a teardown, so re-adding ' +
      'this device id later starts from scratch.' +
      '\n\nThis cannot be undone.';
  }
  // Run *fn* for each selected id, reporting per-device refusals rather than
  // failing the whole batch — same shape as startBatch's error handling.
  //
  // opts.ownsBulkLock (default true) says whether this call is the
  // selected-action holding the shared bulk lock. It is false for the ONE
  // caller that is not a selected-action at all: the per-row assign button,
  // which shares this helper for its status-line reporting. Releasing the
  // lock there re-enabled every bulk button in the middle of someone else's
  // batch — a delete could then fire while an onboard was still starting,
  // which is the exact thing the lock exists to prevent.
  async function forSelected(label, ids, fn, opts) {
    opts = opts || {};
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
      if (opts.ownsBulkLock !== false) setBulkBusy(false);
    }
    devStatus.textContent = label + ' ' + (ids.length - failed.length) + '/' +
      ids.length + ' device(s)' + (failed.length ? '; failed: ' + failed.join(', ') : '');
    refreshDevices();
  }
  // Shared by the per-row assign button and the bulk toolbar action: POST
  // the SAME ordered image_ids body to every device id, sequentially,
  // reporting per-device failures in the status line through forSelected --
  // same shape as every other bulk action. An empty imgIds is a deliberate
  // unassign, not the absence of a choice: the picker's Apply always POSTs
  // whatever is checked, including nothing.
  //
  // opts.expect maps a device id to the set its picker was OPENED on, and the
  // server refuses (409) if the stored set has moved on since. It has to be a
  // snapshot the caller captured: reading the current set here would pick up
  // whatever the 10s poll last wrote, which is precisely the concurrent edit
  // the check exists to catch -- absorbed in silence. Devices with no
  // snapshot post without the field and keep the unconditional write.
  function assignImagesTo(ids, imgIds, opts) {
    opts = opts || {};
    var expect = opts.expect;
    var label = imgIds.length ? ('Assigned ' + imgIds.length + ' image(s) to') : 'Unassigned';
    var conflicts = [];
    return forSelected(label, ids, async function (id) {
      var body = { image_ids: imgIds };
      if (expect && expect[id] !== undefined) body.expect_image_ids = expect[id];
      var r = await jpost('/api/devices/' + encodeURIComponent(id) + '/assign', body);
      if (r.status === 409) conflicts.push(id);
      return r;
    }, opts).then(async function () {
      if (!conflicts.length) return;
      // Nothing was written for these. Re-read first, so what the operator is
      // told (and re-opened on) is what the device actually carries now.
      await refreshDevices().catch(function () { });
      devStatus.textContent = 'Images changed elsewhere on ' + conflicts.join(', ') +
        '; nothing was written there. Review the current set and apply again.';
      if (ids.length === 1 && conflicts.length === 1) openRowAssign(conflicts[0], null);
    });
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
  // ---- Devices: filter wiring ----
  // The Status options are generated from the same list the cell derives from,
  // so a state can never be renderable but unfilterable.
  (function () {
    var sel = document.getElementById('dev-filter-status');
    if (!sel) return;
    sel.innerHTML = '<option value="">Status: any</option>' +
      DEVICE_STATUS_OPTIONS.map(function (o) {
        return '<option value="' + esc(o[0]) + '">' + esc(o[1]) + '</option>';
      }).join('');
  })();
  ['dev-filter-q', 'dev-filter-management-type', 'dev-filter-platform',
   'dev-filter-cred', 'dev-filter-telemetry', 'dev-filter-peer',
   'dev-filter-status'].forEach(function (id) {
    var el = document.getElementById(id);
    if (!el) return;
    el.addEventListener(el.tagName === 'SELECT' ? 'change' : 'input',
                        applyDeviceFilters);
  });
  (function () {
    var clear = document.getElementById('dev-filter-clear');
    if (!clear) return;
    clear.addEventListener('click', function () {
      ['dev-filter-q', 'dev-filter-management-type', 'dev-filter-platform',
       'dev-filter-cred', 'dev-filter-telemetry', 'dev-filter-peer',
       'dev-filter-status'].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.value = '';
      });
      applyDeviceFilters();
    });
  })();

  // Quarantine/release the whole selection. The peer-policy API is one device
  // per call and carries a revision, so these run in sequence and carry the
  // revision forward; a losing race re-reads the policy once rather than
  // stamping a stale revision over someone else's change.
  async function bulkQuarantine(quarantined) {
    var ids = selectedIds();
    if (!ids.length || bulkBusy) return;
    var verb = quarantined ? 'Quarantine' : 'Release';
    if (!confirm(verb + ' ' + ids.length + ' device' + (ids.length === 1 ? '' : 's') +
        '?\n\nThis changes peer discovery and the server seeder across all torrents. ' +
        'It may not terminate existing device-to-device sessions immediately. ' +
        'It never installs or reloads a device.')) return;
    setBulkBusy(true);
    var ok = 0, failed = [];
    try {
      for (var i = 0; i < ids.length; i++) {
        var id = ids[i];
        var done = false;
        for (var attempt = 0; attempt < 2 && !done; attempt++) {
          var r = await fetch('/api/peer-policy/quarantine/' + encodeURIComponent(id), {
            method: 'PUT', headers: csrfHdr({ 'Content-Type': 'application/json' }),
            body: JSON.stringify({ quarantined: quarantined, if_revision: peerPolicy.revision })
          });
          var body = await r.json().catch(function () { return {}; });
          if (r.ok) {
            peerPolicy.revision = body.revision;
            peerPolicy.quarantine_assignments =
              (peerPolicy.quarantine_assignments || []).filter(function (x) { return x !== id; });
            if (body.quarantined) peerPolicy.quarantine_assignments.push(id);
            ok++; done = true;
          } else if (r.status === 409 && attempt === 0) {
            // someone else moved the policy on: re-read and try this one again
            var pr = await fetch('/api/peer-policy');
            if (pr.ok) peerPolicy = await pr.json();
          } else {
            failed.push(id); done = true;
          }
        }
      }
      devStatus.textContent = verb + ' intent saved for ' + ok + ' device' +
        (ok === 1 ? '' : 's') +
        (failed.length ? ('; ' + failed.length + ' failed: ' + failed.join(', ')) : '.');
    } finally {
      setBulkBusy(false);
      refreshDevices().catch(function () {});
    }
  }
  document.getElementById('quarantine-selected').addEventListener('click', function () {
    bulkQuarantine(true);
  });
  document.getElementById('release-selected').addEventListener('click', function () {
    bulkQuarantine(false);
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
  document.getElementById('assign-images-selected').addEventListener('click', function () {
    var ids = selectedIds();
    if (!ids.length) { devStatus.textContent = 'No devices selected.'; return; }
    if (!imageListOk) {
      devStatus.textContent = 'Image list unavailable; not opening the picker. ' +
        'Retry once the Images list loads.';
      return;
    }
    // Pre-check the INTERSECTION of the selection's current sets: pre-
    // checking the UNION would silently ADD an image to a device that does
    // not have it the moment ANY other selected device does; pre-checking
    // just one device's set would silently DROP an image from the rest on
    // Apply. The intersection is the only starting point Apply cannot
    // change anyone's assignment by surprise from.
    var sets = ids.map(function (id) {
      var d = LAST_DEVICES.filter(function (x) { return x.device_id === id; })[0] || {};
      return rowAssignedIds(d);
    });
    var intersection = sets.reduce(function (a, b) {
      return a.filter(function (x) { return b.indexOf(x) !== -1; });
    });
    // Whether the selection's sets are all IDENTICAL, which is the only case
    // Apply cannot surprise anyone in. Apply posts ONE set to every selected
    // device, so every image the picker does not show checked is DROPPED from
    // whichever device had it -- and an intersection can be perfectly
    // non-empty while the sets still disagree ([A,B] + [A] -> [A]). That is
    // exactly the case that used to apply in silence: the pre-check looked
    // complete, so nothing warned and nothing confirmed, and the device with
    // the larger set quietly lost an image. Compared as SEQUENCES, since
    // applying rewrites the order too. The note below and the confirm inside
    // Apply both read this one derivation.
    var firstSet = sets[0].join('\u0000');
    var setsDiffer = sets.some(function (s) { return s.join('\u0000') !== firstSet; });
    // What each selected device was showing when the picker opened, so an
    // assignment written by someone else in between is refused rather than
    // flattened by this Apply.
    var expect = Object.create(null);
    ids.forEach(function (id, i) { expect[id] = sets[i]; });
    openImagePicker(intersection, function (imgIds) {
      var claimed = claimSelection();
      if (!claimed) return;
      // An empty pick from the bulk path is one accidental Apply away from
      // wiping every selected device's assignment (an empty intersection
      // opens the picker with nothing pre-checked) -- confirm before it posts.
      if (!imgIds.length) {
        if (!confirm('Unassign all images from ' + claimed.length + ' device(s)?')) {
          setBulkBusy(false); return;
        }
      } else if (setsDiffer &&
          !confirm('The selected devices have differing image assignments.\n\n' +
                   'Applying replaces every selected device\'s set with the ' +
                   imgIds.length + ' checked image(s). Any image a device has ' +
                   'that is not checked here is dropped from it.\n\nProceed?')) {
        setBulkBusy(false); return;
      }
      assignImagesTo(claimed, imgIds, { expect: expect });
    });
    // Sets that disagree are the trap, whatever their intersection comes to:
    // Apply as-is replaces everyone's set with whatever ends up checked. Say
    // so before the operator picks. Devices that all agree -- including every
    // one of them unassigned -- are not a trap and get no note.
    if (setsDiffer) {
      var note = document.getElementById('img-picker-note');
      if (note) {
        note.textContent = 'Selected devices have differing assignments; '
          + 'applying replaces them all.';
        note.hidden = false;
      }
    }
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
    var attach = document.getElementById('df-management-type').value;
    var router = attach === 'router-routed' || attach === 'router-nat';
    // xr-host runs the appmgr container on the router's own network stack:
    // no VLAN, SVI, VPG, NAT interface, or app IP/mask/gateway. Those last
    // three used to be visible for every management type -- the core bug this
    // hides.
    var xrHost = attach === 'xr-host';
    document.getElementById('df-vlan').hidden = router || xrHost;
    document.getElementById('df-svi').hidden = attach !== 'routed';
    document.getElementById('df-vpg').hidden = !router;
    document.getElementById('df-nat-interface').hidden = attach !== 'router-nat';
    document.getElementById('df-guest').hidden = xrHost;
    document.getElementById('df-mask').hidden = xrHost;
    document.getElementById('df-gateway').hidden = xrHost;
    var platform = document.getElementById('df-platform');
    if (router && !platform.value) platform.value = 'router';
    if (!router && platform.value === 'router') platform.value = '';
    if (xrHost && !platform.value) platform.value = 'xr-appmgr';
    if (!xrHost && platform.value === 'xr-appmgr') platform.value = '';
  }
  document.getElementById('df-management-type').addEventListener('change', updateDeviceFields);
  // xr-host <-> xr-appmgr is mutually required server-side, so picking the
  // agent install directly should carry the operator into xr-host too --
  // the same auto-select the model-driven path below performs, just from
  // the other field. Never fight an operator already on xr-host.
  document.getElementById('df-platform').addEventListener('change', function () {
    if (this.value !== 'xr-appmgr') return;
    var attachSel = document.getElementById('df-management-type');
    if (attachSel.value === 'xr-host') return;
    attachSel.value = 'xr-host';
    updateDeviceFields();
  });
  // Agent-install options depend on the model, so df-model sits ahead of
  // df-platform in the form and this repaints the select as the operator
  // types -- the same model-aware guardrail server-side validation enforces
  // (gui_fleet.validate_record / gui_onboard.install_options_for), surfaced
  // before submit instead of as a rejection after it.
  var INSTALL_OPTION_LABELS = { guestshell: 'Guest Shell', iox: 'IOx',
                                router: 'Router (Guest Shell via VirtualPortGroup)',
                                'xr-appmgr': 'XR appmgr container' };
  // Offered when the model is blank or unrecognized -- i.e. when nobody has
  // established what the hardware is. 'xr-appmgr' is deliberately NOT in
  // that permissive set: validate_record refuses it without an IOS-XR model,
  // so offering it here would only produce a rejection after submit. It
  // appears the moment the model says IOS-XR, from the fetched options below.
  var AUTO_INSTALL_OPTIONS = ['guestshell', 'iox', 'router'];
  var FULL_INSTALL_OPTIONS_HTML = '<option value="">Agent install - auto by model</option>' +
    AUTO_INSTALL_OPTIONS.map(function (k) {
      return '<option value="' + esc(k) + '">' + esc(INSTALL_OPTION_LABELS[k]) + '</option>';
    }).join('');
  var installOptionsGen = 0;
  async function refreshInstallOptions() {
    var model = document.getElementById('df-model').value.trim();
    var platform = document.getElementById('df-platform');
    var attachSel = document.getElementById('df-management-type');
    var gen = ++installOptionsGen;
    // The install-options answer for an IOS-XR-shaped model is exactly
    // ["xr-appmgr"] -- the one thing it can run, and nothing else ever
    // returns just that -- so ANY other repaint of the platform select
    // (blank model, a server/network error, a null or empty answer, or a
    // real answer that isn't that exact singleton) must exit an
    // auto-entered xr-host management type. Left stuck on xr-host, the
    // addressing fields stay hidden for a non-XR device with no visible
    // cause and the platform select no longer even offers xr-appmgr to
    // undo it with. Every one of those paths below calls this helper.
    function exitXrHostIfStale() {
      if (attachSel.value === 'xr-host') {
        attachSel.value = '';
        updateDeviceFields();
      }
    }
    if (!model) {
      platform.disabled = false;
      platform.innerHTML = FULL_INSTALL_OPTIONS_HTML;
      exitXrHostIfStale();
      return;
    }
    try {
      var r = await fetch('/api/install-options?model=' + encodeURIComponent(model));
      if (gen !== installOptionsGen) return;   // a newer keystroke superseded this fetch
      if (!r.ok) {
        // Restore to permissive default on server error: a valid choice must not
        // be locked out by a transient failure. The server-side validate_record
        // guard still refuses impossible platform+model combinations.
        platform.disabled = false;
        platform.innerHTML = FULL_INSTALL_OPTIONS_HTML;
        exitXrHostIfStale();
        return;
      }
      var options = (await r.json()).options;
      if (options === null) {
        platform.disabled = false;
        platform.innerHTML = FULL_INSTALL_OPTIONS_HTML;
        exitXrHostIfStale();
        return;
      }
      if (options.length === 0) {
        // No family answers this today: every model the server has an
        // opinion about can run something (IOS-XR included, since the appmgr
        // container agent shipped). Kept as an honest dead end rather than a
        // silent fall-through to the permissive list.
        platform.innerHTML = '<option value="">No agent install available for this model</option>';
        platform.disabled = true;
        exitXrHostIfStale();
        return;
      }
      var kept = platform.value;
      platform.disabled = false;
      platform.innerHTML = '<option value="">Agent install - auto by model</option>' +
        options.map(function (o) {
          return '<option value="' + esc(o) + '">' + esc(INSTALL_OPTION_LABELS[o] || o) + '</option>';
        }).join('');
      if (options.indexOf(kept) !== -1) platform.value = kept;
      // Drive the management type auto-select off the server answer instead of
      // re-implementing the model regex here.
      if (options.length === 1 && options[0] === 'xr-appmgr') {
        if (attachSel.value !== 'xr-host') {
          attachSel.value = 'xr-host';
          updateDeviceFields();
        }
      } else {
        exitXrHostIfStale();
      }
    } catch (e) {
      // Network failure or JSON parse error: restore permissive defaults so
      // a transient blip never locks out a valid platform choice.
      platform.disabled = false;
      platform.innerHTML = FULL_INSTALL_OPTIONS_HTML;
      exitXrHostIfStale();
    }
  }
  document.getElementById('df-model').addEventListener('input', refreshInstallOptions);
  document.getElementById('add-dev').addEventListener('click', function () {
    // populate the credential dropdown from the latest profiles
    var sel = document.getElementById('df-cred');
    sel.innerHTML = '<option value="">— no credential —</option>' +
      credOpts.map(function (c) { return '<option value="' + esc(c.id) + '">' + esc(c.id) + '</option>'; }).join('');
    devForm.hidden = !devForm.hidden;
    if (!devForm.hidden) { updateDeviceFields(); refreshInstallOptions(); }
  });
  document.getElementById('df-cancel').addEventListener('click', function () { devForm.hidden = true; });
  devForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    var did = document.getElementById('df-id').value.trim();
    var derr = document.getElementById('df-err'); derr.textContent = '';
    if (!did) { derr.textContent = 'Device ID is required.'; return; }
    var attach = document.getElementById('df-management-type').value;
    var vlan = document.getElementById('df-vlan').value.trim();
    var mask = document.getElementById('df-mask').value.trim();
    var body = {
      device_id: did,
      device_ip: document.getElementById('df-ip').value.trim() || did,
      management_type: attach,
      model: document.getElementById('df-model').value.trim(),
      platform: document.getElementById('df-platform').value,
      credential_profile_id: document.getElementById('df-cred').value
    };
    if (attach === 'xr-host') {
      // XR host networking -- the agent shares the router's own network
      // stack, so no app-network fields belong on this wire body.
    } else if (attach === 'inband') {
      body.app_ip = document.getElementById('df-guest').value.trim();
      body.app_mask = mask;
      body.app_gateway = document.getElementById('df-gateway').value.trim();
      body.inband_vlan = vlan;
    } else if (attach === 'router-routed' || attach === 'router-nat') {
      body.app_ip = document.getElementById('df-guest').value.trim();
      body.app_mask = mask;
      body.app_gateway = document.getElementById('df-gateway').value.trim();
      body.vpg_number = document.getElementById('df-vpg').value.trim();
      if (attach === 'router-nat') {
        body.nat_interface = document.getElementById('df-nat-interface').value.trim();
      }
    } else {
      body.app_ip = document.getElementById('df-guest').value.trim();
      body.app_mask = mask;
      body.app_gateway = document.getElementById('df-gateway').value.trim();
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
    // Telemetry export health is dashboard state, so it rides the Overview
    // refresh. Deliberately not awaited with the overview fetch: a slow or
    // unreachable collector must not delay the cards.
    refreshTelemetryHealth();
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
    var legacyPeers = (sw.images || []).reduce(function (n, im) {
      return n + (im.peers || []).filter(function (p) {
        return p && p.tracker && p.tracker.participant_class === 'legacy_unattributed';
      }).length;
    }, 0);
    var legacyWarning = document.getElementById('legacy-peer-warning');
    legacyWarning.hidden = legacyPeers === 0;
    legacyWarning.textContent = legacyPeers ? legacyPeers + ' legacy participant(s) cannot be attributed or individually quarantined until personalized torrent refresh.' : '';
    s.textContent = peers + ' peer(s) in the swarm. Open the full map for the live view.';
  }

  // ---- Settings ----
  // CA bundle source presets (Feature 3): the select is a client-side view
  // over the same stored URL the free-text input always wrote — "cisco"
  // means "no override" (server default), "mozilla" is this curated URL,
  // anything else is "custom" and shows the raw input.
  var CA_MOZILLA_URL = 'https://curl.se/ca/cacert.pem';

  // ---- Settings: post-install setup checklist ----
  // Chip classes reuse the existing badge-* palette (see the telemetry
  // health badge above) rather than the bare ok/warn/muted classes, which
  // don't exist as standalone selectors in styles.css.
  function setupChip(state) {
    var label = {ok: 'done', unset: 'not configured', stale: 'needs rebuild',
                 absent: 'not built', unknown: 'cannot determine'}[state] || state;
    var cls = state === 'ok' ? 'badge-ok'
      : (state === 'unset' || state === 'stale') ? 'badge-cancelled' : 'badge-queued';
    return '<span class="badge ' + cls + '">' + esc(label) + '</span>';
  }

  // packages.reason (present only in some non-ok states) needs its own
  // guidance -- the plain rebuild remedy is actively WRONG for a
  // served-vs-distributed mismatch, since new onboards are broken too and
  // rebuilding packages would not fix it.
  var SETUP_PKG_REASON_TEXT = {
    'served-vs-distributed-mismatch':
      'The certificate this server currently serves does not match the ' +
      'copy handed to devices during onboarding. New onboards are ' +
      'affected as well as existing ones, and rebuilding packages alone ' +
      'will not resolve this.',
    'distributed-cert-unavailable':
      'The copy of the certificate handed to devices could not be read, ' +
      'so package state cannot be confirmed.'
  };

  function setupPkgRemedyText(pkg) {
    if (pkg.state === 'ok') return '';
    var parts = [];
    var reasonText = SETUP_PKG_REASON_TEXT[pkg.reason];
    if (reasonText) parts.push(reasonText);
    // The rebuild remedy only applies once a package is confirmed stale --
    // and never for a served-vs-distributed mismatch, where rebuilding
    // packages would not fix anything.
    if (pkg.state === 'stale' && pkg.reason !== 'served-vs-distributed-mismatch') {
      parts.push('Rebuild on the Docker host, then re-onboard affected devices: '
        + pkg.remedy);
    }
    return parts.join(' ');
  }

  // telemetry.source distinguishes an explicit console override from the
  // deployment default (whatever the compose/env file happens to set) --
  // meaningfully different to an operator, so this note names which one is
  // in effect rather than just showing the chip.
  function setupTelemetryNote(t) {
    var scope = t.source === 'override' ? 'console override' : 'deployment default';
    if (t.state === 'ok') return 'Exporting to ' + t.endpoint + ' (' + scope + ').';
    if (!t.enabled) return 'Export is disabled (' + scope + ').';
    return 'No endpoint is set (' + scope + ').';
  }

  // A failed or thrown fetch must never leave a PREVIOUS render on screen --
  // that would be evidence-free chips still claiming "done" (spec:
  // error handling must show "cannot determine" per card and never silently
  // render a stale/empty checklist as if it were healthy).
  function setupShowUnknown() {
    document.getElementById('setup-admin-chip').innerHTML = setupChip('unknown');
    document.getElementById('setup-td-chip').innerHTML = setupChip('unknown');
    document.getElementById('setup-td-note').textContent = '';
    document.getElementById('setup-sh-chip').innerHTML = setupChip('unknown');
    document.getElementById('setup-pkg-chip').innerHTML = setupChip('unknown');
    document.querySelector('#setup-pkg-table tbody').innerHTML = '';
    document.getElementById('setup-pkg-remedy').textContent = '';
    document.getElementById('setup-iv-chip').innerHTML = setupChip('unknown');
  }

  // ---- First-run setup wizard -------------------------------------------
  // A flow, not a checklist: the operator finishes setup here instead of being
  // sent back and forth to Settings pages. The two form steps mount the SAME
  // templates Settings uses, so there is one implementation of each form.
  //
  // Every step is skippable and the wizard resumes at the first incomplete one.
  // That is forced, not a convenience: the packages step can never complete
  // in-console (the container has no Docker socket), so a wizard that insisted
  // on completion could never be finished.
  var WIZARD_STEPS = [
    { id: 'telemetry', pane: 'wz-step-telemetry', key: 'telemetry',  chip: 'wz-td-chip',  label: 'Telemetry destination' },
    { id: 'stagehost', pane: 'wz-step-stagehost', key: 'stage_host', chip: 'wz-sh-chip',  label: 'Stage host' },
    { id: 'packages',  pane: 'wz-step-packages',  key: 'packages',   chip: 'wz-pkg-chip', label: 'Device packages' }
  ];
  var wizardStep = 0;
  var wizardStatus = null;

  function wizardFirstIncompleteStep(status) {
    if (!status) return 0;
    for (var i = 0; i < WIZARD_STEPS.length; i++) {
      var st = (status[WIZARD_STEPS[i].key] || {}).state;
      if (st !== 'ok') return i;
    }
    return WIZARD_STEPS.length - 1;   // all done: rest on the last step
  }

  // Every step is listed with its current state, whatever that state is, and
  // any of them can be opened directly. Without this the wizard opened on the
  // first INCOMPLETE step and rendered only that one, so a step already
  // satisfied by the deployment environment -- telemetry, when
  // IRIS_OTLP_ENDPOINT is set in the compose env -- was never visible at all
  // and read as missing.
  function renderWizardStepList() {
    var host = document.getElementById('wz-steplist');
    if (!host) return;
    host.innerHTML = WIZARD_STEPS.map(function (st, n) {
      var state = wizardStatus ? ((wizardStatus[st.key] || {}).state || 'unknown')
                               : 'unknown';
      return '<button type="button" role="listitem" class="wz-steplist-item' +
        (n === wizardStep ? ' current' : '') + '" data-step="' + n + '">' +
        '<span class="wz-steplist-n">' + (n + 1) + '</span>' +
        '<span class="wz-steplist-label">' + esc(st.label) + '</span>' +
        setupChip(state) + '</button>';
    }).join('');
    host.querySelectorAll('.wz-steplist-item').forEach(function (b) {
      b.addEventListener('click', function () {
        showWizardStep(parseInt(b.getAttribute('data-step'), 10));
      });
    });
  }

  function showWizardStep(i) {
    wizardStep = Math.max(0, Math.min(WIZARD_STEPS.length - 1, i));
    WIZARD_STEPS.forEach(function (st, n) {
      document.getElementById(st.pane).hidden = n !== wizardStep;
    });
    // Mount the shared form for whichever step is showing. Settings reclaims
    // it on its way back in, so only one clone is ever live.
    if (WIZARD_STEPS[wizardStep].id === 'telemetry') {
      mountSettingsForm('td', 'wz-td-mount');
      refreshSettings();
    } else if (WIZARD_STEPS[wizardStep].id === 'stagehost') {
      mountSettingsForm('sh', 'wz-sh-mount');
      refreshSettings();
    }
    document.getElementById('wz-progress').textContent =
      'Step ' + (wizardStep + 1) + ' of ' + WIZARD_STEPS.length;
    document.getElementById('wz-back').disabled = wizardStep === 0;
    document.getElementById('wz-next').textContent =
      wizardStep === WIZARD_STEPS.length - 1 ? 'Done' : 'Next \u203a';
    renderWizardStepList();
  }

  function renderWizardPackages(pkg) {
    var body = document.querySelector('#wz-pkg-table tbody');
    if (!body) return;
    body.innerHTML = ((pkg && pkg.items) || []).map(function (i) {
      return '<tr><td class="mono">' + esc(i.name || '') + '</td><td>' +
        setupChip(i.state) + '</td><td class="muted">built ' +
        esc(i.built_at || 'unknown') + '</td></tr>';
    }).join('');
    document.getElementById('wz-pkg-remedy').textContent = setupPkgRemedyText(pkg || {});
  }

  async function refreshSetupWizard() {
    var s = null;
    try {
      var r = await fetch('/api/settings/setup-status');
      if (r.ok) s = await r.json();
    } catch (e) { /* leave s null -- never report green on missing evidence */ }
    wizardStatus = s;
    function chip(id, state) {
      var el = document.getElementById(id);
      if (el) el.innerHTML = setupChip(state);
    }
    chip('wz-admin-chip', s ? (s.admin || {}).state : 'unknown');
    WIZARD_STEPS.forEach(function (st) {
      chip(st.chip, s ? (s[st.key] || {}).state : 'unknown');
    });
    renderWizardPackages(s ? s.packages : null);
    renderWizardStepList();
    updateSetupNudge(s);
    return s;
  }

  // The nudge is what brings an operator back to an unfinished setup. It
  // dismisses for the SESSION, not for good: a package that goes stale later
  // is a silent regression, and a permanently dismissed banner would hide
  // exactly the failure this feature exists to catch.
  function setupIncompleteCount(s) {
    if (!s) return 0;
    return WIZARD_STEPS.filter(function (st) {
      return (s[st.key] || {}).state !== 'ok';
    }).length;
  }
  function updateSetupNudge(s) {
    var el = document.getElementById('setup-nudge');
    if (!el) return;
    var n = setupIncompleteCount(s);
    if (!n || window.sessionStorage.getItem('iris_setup_nudge_dismissed')) {
      el.hidden = true; return;
    }
    document.getElementById('setup-nudge-text').textContent =
      n + ' setup step' + (n === 1 ? '' : 's') + ' still ' +
      (n === 1 ? 'needs' : 'need') + ' attention.';
    el.hidden = false;
  }

  async function enterSetupWizard() {
    var s = await refreshSetupWizard();
    showWizardStep(wizardFirstIncompleteStep(s));
  }

  document.getElementById('wz-back').addEventListener('click', function () {
    showWizardStep(wizardStep - 1);
  });
  document.getElementById('wz-skip').addEventListener('click', function () {
    if (wizardStep === WIZARD_STEPS.length - 1) { location.hash = '#overview'; return; }
    showWizardStep(wizardStep + 1);
  });
  document.getElementById('wz-next').addEventListener('click', async function () {
    await refreshSetupWizard();
    if (wizardStep === WIZARD_STEPS.length - 1) { location.hash = '#overview'; return; }
    showWizardStep(wizardStep + 1);
  });
  document.getElementById('wz-pkg-recheck').addEventListener('click', function () {
    var msg = document.getElementById('wz-msg');
    msg.textContent = 'Re-checking\u2026';
    refreshSetupWizard().then(function () { msg.textContent = ''; });
  });
  document.getElementById('setup-nudge-dismiss').addEventListener('click', function () {
    window.sessionStorage.setItem('iris_setup_nudge_dismissed', '1');
    document.getElementById('setup-nudge').hidden = true;
  });

  async function refreshSetup() {
    var s;
    try {
      var r = await fetch('/api/settings/setup-status');
      if (!r.ok) { setupShowUnknown(); return; }
      s = await r.json();
    } catch (e) {
      setupShowUnknown();
      return;
    }
    document.getElementById('setup-admin-chip').innerHTML =
      setupChip(s.admin.state);
    document.getElementById('setup-td-chip').innerHTML =
      setupChip(s.telemetry.state);
    document.getElementById('setup-td-note').textContent =
      setupTelemetryNote(s.telemetry);
    document.getElementById('setup-sh-chip').innerHTML =
      setupChip(s.stage_host.state);
    document.getElementById('setup-pkg-chip').innerHTML =
      setupChip(s.packages.state);
    document.querySelector('#setup-pkg-table tbody').innerHTML =
      s.packages.items.map(function (i) {
        var when = i.built_at
          ? new Date(i.built_at * 1000).toLocaleString() : '—';
        return '<tr><td class="muted">' + esc(i.name) + '</td><td>' +
               setupChip(i.state) + '</td><td class="muted">built ' +
               esc(when) + '</td></tr>';
      }).join('');
    document.getElementById('setup-pkg-remedy').textContent =
      setupPkgRemedyText(s.packages);
    document.getElementById('setup-iv-chip').innerHTML =
      setupChip(s.image_verification.state);
  }

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
    // These live in a template and are only present while mounted, so every
    // write guards -- refreshSettings also runs for surfaces that host neither.
    var shUser = document.getElementById('sh-user');
    if (shUser) shUser.value = sh.username || '';
    var shStatus = document.getElementById('sh-status');
    if (shStatus) shStatus.textContent = sh.configured
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
    var tdStatus = document.getElementById('td-status');
    if (tdStatus) tdStatus.innerHTML =
      (td.source === 'override'
        ? '<span class="badge badge-running">console override</span> '
        : '<span class="badge badge-queued">deployment default</span> ') +
      (td.effective_enabled
        ? ('export on — ' + esc(td.effective_endpoint || '(no endpoint)'))
        : 'export off') +
      (obs.metrics_url
        ? ' · Prometheus scrape ' + esc(obs.metrics_url) : '');
    var tdEndpoint = document.getElementById('td-endpoint');
    if (tdEndpoint) tdEndpoint.value = td.effective_endpoint || '';
    var tdEnabled = document.getElementById('td-enabled');
    if (tdEnabled) tdEnabled.checked = !!td.effective_enabled;
    var tdRevert = document.getElementById('td-revert');
    if (tdRevert) tdRevert.hidden = td.source !== 'override';
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
    // --- Image verification (KGV / Cisco Bulk Hash reconciler, Task 5) ---
    // Its own dedicated GET, unlike the panes above -- not part of the big
    // /api/settings blob (see the endpoint contract in Task 4's report).
    await refreshImageVerificationSettings();
  }
  // ---- Settings: Image verification (KGV / Cisco Bulk Hash reconciler) ----
  // Schedule select + hour, Refresh now, offline .tar upload. Its own
  // dedicated GET/POST at /api/settings/image-verification and
  // /api/image-verification/{refresh,offline} -- see Task 4's endpoint
  // contracts. Factored out of refreshSettings (rather than inlined like the
  // ae-/cert- panes above) because the Refresh now button and the offline
  // upload both need to re-render just the last-run line afterward, without
  // re-fetching the whole /api/settings blob.
  //
  // last_run.outcome is "ok" or "fail: <detail>" -- NEVER compared with
  // equality against "fail" (the detail suffix always differs); this
  // function and its caller only ever test the "fail" PREFIX.
  function bulkhashOutcomeFailed(outcome) {
    return String(outcome || '').slice(0, 4) === 'fail';
  }
  function fmtBulkhashLastRun(lr) {
    if (!lr || !lr.at) return 'Never run.';
    var failed = bulkhashOutcomeFailed(lr.outcome);
    var badge = failed ? '<span class="badge badge-fail">fail</span>'
                       : '<span class="badge badge-ok">ok</span>';
    var counts = lr.matched == null ? ''
      : (' · ' + lr.matched + ' matched, ' + lr.mismatched + ' mismatched, ' +
         lr.not_in_feed + ' not in feed');
    var detail = failed && String(lr.outcome).indexOf(':') > -1
      ? (' · ' + esc(String(lr.outcome).slice(String(lr.outcome).indexOf(':') + 1).trim())) : '';
    return esc(fmtDate(lr.at)) + ' · ' + esc(lr.source || 'unknown') + ' ' + badge + counts + detail;
  }
  async function refreshImageVerificationSettings() {
    // Setup pane's never-render-stale-as-healthy pattern (setupShowUnknown):
    // a failed GET must not silently leave whatever was already in
    // #iv-last-run (the static "Never run." markup on first load, or a
    // stale prior successful render) standing in as if it were current.
    var lastRun = document.getElementById('iv-last-run');
    var r;
    try {
      r = await fetch('/api/settings/image-verification');
    } catch (e) {
      lastRun.textContent = 'Could not load status.';
      return;
    }
    if (!r.ok) { lastRun.textContent = 'Could not load status.'; return; }
    var iv = await r.json();
    document.getElementById('iv-mode').value = iv.mode || 'off';
    document.getElementById('iv-hour').value = String(iv.hour_utc == null ? 0 : iv.hour_utc);
    lastRun.innerHTML = fmtBulkhashLastRun(iv.last_run);
  }
  // Hour select is built once here (00:00-23:00 UTC) rather than spelled out
  // as 24 <option> elements in index.html.
  (function () {
    var sel = document.getElementById('iv-hour');
    if (!sel) return;
    var opts = [];
    for (var h = 0; h < 24; h++) {
      opts.push('<option value="' + h + '">' + (h < 10 ? '0' : '') + h + ':00</option>');
    }
    sel.innerHTML = opts.join('');
  })();
  document.getElementById('iv-schedule-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('iv-schedule-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var mode = document.getElementById('iv-mode').value;
    var hour = parseInt(document.getElementById('iv-hour').value, 10);
    var r = await jpost('/api/settings/image-verification', { mode: mode, hour_utc: hour });
    if (!r.ok) { msg.textContent = ((await r.json()).error || ('Failed (' + r.status + ')')); return; }
    msg.textContent = 'Schedule saved.'; msg.classList.add('ok');
    refreshImageVerificationSettings();
  });
  document.getElementById('iv-refresh').addEventListener('click', async function () {
    var btn = this;
    var msg = document.getElementById('iv-refresh-msg'); msg.textContent = ''; msg.classList.remove('ok');
    btn.disabled = true;
    try {
      var r = await jpost('/api/image-verification/refresh', {});
      var body = {};
      try { body = await r.json(); } catch (e) { }
      if (r.status === 409) {
        msg.textContent = 'A refresh is already in progress.';
      } else if (r.ok) {
        msg.textContent = 'Refresh complete: ' + body.matched + ' matched, ' +
          body.mismatched + ' mismatched, ' + body.not_in_feed + ' not in feed.';
        msg.classList.add('ok');
      } else {
        msg.textContent = 'Refresh failed: ' + (body.detail || ('status ' + r.status));
      }
    } finally {
      btn.disabled = false;
      refreshImageVerificationSettings();
      refreshImages().catch(function () { });
      // Also refreshes imageQuarantined (the picker's block list) -- without
      // this it lagged the run by up to one periodic devices-view poll
      // interval, during which a freshly-quarantined image stayed pickable.
      refreshDevices().catch(function () { });
    }
  });
  // Offline upload: a raw-body POST of the tar bytes (not multipart, not
  // form-encoded -- see Task 4's endpoint contract), streamed via XHR the
  // same way the image-upload PUT route sends a raw File body. Reuses the
  // TLS pane's wireDropzone for the drag-drop mechanics; unlike the TLS
  // dropzones (which read the file as text into a textarea) this one sends
  // the file's raw bytes straight to the server.
  var ivOfflineBusy = false;
  function uploadOfflineTar(file) {
    if (!file || ivOfflineBusy) return;
    ivOfflineBusy = true;
    var msg = document.getElementById('iv-offline-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var prog = document.getElementById('iv-offline-progress');
    var bar = document.getElementById('iv-offline-bar');
    prog.hidden = false; bar.style.width = '0%';
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/image-verification/offline');
    xhr.setRequestHeader('X-CSRF-Token', info.csrf);
    xhr.upload.onprogress = function (e) { if (e.lengthComputable) bar.style.width = (e.loaded / e.total * 100) + '%'; };
    function finish(text, ok) {
      ivOfflineBusy = false;
      prog.hidden = true;
      msg.textContent = text;
      if (ok) msg.classList.add('ok');
      refreshImageVerificationSettings();
      refreshImages().catch(function () { });
      // See the Refresh now handler's comment: keeps imageQuarantined (the
      // picker's block list) from lagging this run by a poll interval.
      refreshDevices().catch(function () { });
    }
    xhr.onload = function () {
      var body = {};
      try { body = JSON.parse(xhr.responseText); } catch (e) { }
      if (xhr.status === 409) {
        finish('A refresh is already in progress.', false);
      } else if (xhr.status === 200) {
        finish('Offline check complete: ' + body.matched + ' matched, ' +
          body.mismatched + ' mismatched, ' + body.not_in_feed + ' not in feed.', true);
      } else {
        finish('Offline check failed: ' + (body.detail || body.error || ('status ' + xhr.status)), false);
      }
    };
    xhr.onerror = function () { finish('Upload error.', false); };
    xhr.send(file);
  }
  wireDropzone(document.getElementById('iv-offline-dropzone'), document.getElementById('iv-offline-dropzone-input'),
    function (files) { uploadOfflineTar(files[0]); });
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
  // ---- Shared settings forms: one markup source, mounted where it is needed
  // The telemetry and stage-host forms live in a <template> in the settings
  // pane and are cloned into whichever surface is showing -- Settings, or a
  // step of the first-run wizard. Cloning rather than duplicating the markup
  // keeps a single source of truth, and only ever ONE clone is mounted, so the
  // ids inside stay unique. Handlers bind per mount, which is why they live in
  // wire*Form() rather than running once at startup.
  var FORM_MOUNTS = {
    td: { tpl: 'tpl-td-form', wire: function () { wireTelemetryForm(); } },
    sh: { tpl: 'tpl-sh-form', wire: function () { wireStageHostForm(); } }
  };
  var formMountedAt = { td: null, sh: null };

  function mountSettingsForm(which, hostId) {
    var spec = FORM_MOUNTS[which];
    var host = document.getElementById(hostId);
    var tpl = document.getElementById(spec.tpl);
    if (!host || !tpl) return false;
    if (formMountedAt[which] === hostId && host.firstChild) return true;
    // tear the previous clone down first -- two live clones would duplicate ids
    if (formMountedAt[which] && formMountedAt[which] !== hostId) {
      var prev = document.getElementById(formMountedAt[which]);
      if (prev) prev.innerHTML = '';
    }
    host.innerHTML = '';
    host.appendChild(tpl.content.cloneNode(true));
    formMountedAt[which] = hostId;
    spec.wire();
    return true;
  }

  function wireStageHostForm() {
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
  }


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
  function wireTelemetryForm() {
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
  }


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
  // The setup pane rides the same pane/nav id pattern; appended for the
  // same reason (keeps the original trio a literal for the source guard).
  SETTINGS_SUBS.push('setup');
  // The Image verification (KGV / Cisco Bulk Hash reconciler) pane rides the
  // same pane/nav id pattern; appended for the same reason.
  SETTINGS_SUBS.push('bulkhash');
  function showSettingsSub(sub) {
    if (SETTINGS_SUBS.indexOf(sub) < 0) sub = 'general';
    SETTINGS_SUBS.forEach(function (t) {
      document.getElementById('settings-pane-' + t).hidden = t !== sub;
      document.getElementById('nav-settings-' + t).classList.toggle('active', t === sub);
    });
    // Claim the shared forms back from the wizard, then repopulate them --
    // a freshly cloned form is empty until refreshSettings writes to it.
    if (sub === 'general') mountSettingsForm('sh', 'sh-mount');
    if (sub === 'telemetry') mountSettingsForm('td', 'td-mount');
    refreshSettings();
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
  // The chip labels the SUBSYSTEM, but it sits immediately before the verb
  // phrase, so it reads as the sentence's subject: one service runs both
  // onboard and undeploy jobs, which rendered as "onboard started undeploying
  // <device>". The stored category stays "onboard" -- it is persisted in
  // audit.jsonl and drives the category filter -- only the label changes.
  var AUDIT_CAT_LABELS = { onboard: 'deployment' };

  function auditRowHtml(e) {
    var category = e.category || AUDIT_LEGACY_CATS[e.event] || 'system';
    var catLabel = AUDIT_CAT_LABELS[category] || category;
    var target = e.target || e.device_id || '';
    var actor = e.actor || (e.device_id ? 'device:' + e.device_id : 'system');
    var detail = e.detail ||
      (e.secret_name ? e.secret_name + ' ' + (e.old_id || '?') + ' -> ' + (e.new_id || '?') : '');
    var msg = '<span class="cat-tag cat-' + esc(category) + '">' + esc(catLabel) + '</span> ' +
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
                       refreshDeployLogsAll()]);
  }

  // ---- Monitoring: persistent deployment logs pane ----
  function deployLogResult(l) {
    return jobBadge(l.state || 'done') +
      (l.rc == null ? '' : ' <span class="muted">rc=' + esc(l.rc) + '</span>');
  }
  // Generation counter (same idiom as imageJobGen / caPollGen): two quick
  // "view" clicks race their fetches, and without this the SLOWER response
  // would paint the shared <pre> after the newer one — only the latest
  // requested file may render.
  var deployLogGen = 0;
  async function showDeployLog(file, pre) {
    var gen = ++deployLogGen;
    pre.hidden = false;
    pre.textContent = 'Loading ' + file + '…';
    var r = null;
    try { r = await fetch('/api/deploy-logs/' + encodeURIComponent(file)); } catch (e) { }
    if (gen !== deployLogGen) return;   // a newer view request superseded this one
    if (!r || !r.ok) {
      pre.textContent = 'Log unavailable' + (r ? ' (' + r.status + ')' : '') + '.';
      return;
    }
    var text = await r.text();
    if (gen !== deployLogGen) return;
    pre.textContent = text;
  }
  // The API returns the newest 200; search, action/result pickers, the graph
  // and paging all work over exactly that set, which is what the pane says it
  // shows. Filtering client-side keeps typing responsive and avoids a refetch
  // per keystroke.
  var DL_PAGE_SIZE = 25;
  var dlAll = [];
  var dlPage = 0;

  function dlFilterState() {
    function val(id) { var el = document.getElementById(id); return el ? el.value : ''; }
    return {
      q: val('dl-search').trim().toLowerCase(),
      action: val('dl-action'),
      result: val('dl-result')
    };
  }
  function deployLogMatches(l, f) {
    if (f.action && (l.action || '') !== f.action) return false;
    if (f.result && (l.state || 'done') !== f.result) return false;
    if (f.q) {
      var hay = [l.device_id, l.action, l.state, l.rc == null ? '' : ('rc=' + l.rc)]
        .filter(Boolean).join(' ').toLowerCase();
      if (hay.indexOf(f.q) === -1) return false;
    }
    return true;
  }

  // ---- Deployment logs: time filter (the audit timeline's feature) --------
  // Chips pick the outer window, the server bins into buckets, and dragging a
  // brush selects a range that is fed back into the LIST query -- the graph
  // filters, it is not decoration.
  //
  // NOTE: this deliberately does NOT share code with the audit timeline yet.
  // That machinery has no behavioural test coverage (only source assertions
  // that ids and function names exist) and cannot be rendered here, so
  // extracting it would be an unverifiable refactor of a working feature.
  // Audit is left untouched; the shared component is a follow-up.
  var DL_RANGES = {
    '24h': { window: 86400,   buckets: 24 },
    '7d':  { window: 604800,  buckets: 28 },
    '30d': { window: 2592000, buckets: 30 },
    '90d': { window: 7776000, buckets: 45 },
    'all': { window: 7776000, buckets: 45 }
  };
  var dlRange = '7d';
  var dlSel = null;            // {start,end} epoch secs, or null
  var dlDomain = null;         // {since,until} the histogram currently displays
  var dlBucketSecs = 0;
  var DL_W = 600, DL_H = 64, DL_HANDLE_VB = 4, DL_HANDLE_HIT_PX = 8;
  var DL_CLICK_SLOP_PX = 3, DL_MIN_SEL_SECONDS = 60;
  var dlSvg = document.getElementById('dl-histogram');
  var dlBarsG = document.getElementById('dl-bars');
  var dlBrushG = document.getElementById('dl-brush');

  function dlEpochToVb(t) {
    return (t - dlDomain.since) / (dlDomain.until - dlDomain.since) * DL_W;
  }
  function dlClientXToEpoch(clientX) {
    var r = dlSvg.getBoundingClientRect();
    return dlDomain.since + ((clientX - r.left) / r.width) *
      (dlDomain.until - dlDomain.since);
  }
  function dlEpochToClientX(t) {
    var r = dlSvg.getBoundingClientRect();
    return r.left + (t - dlDomain.since) / (dlDomain.until - dlDomain.since) * r.width;
  }
  function dlOuterBounds() {
    var cfg = DL_RANGES[dlRange] || DL_RANGES['7d'];
    var now = Date.now() / 1000;
    return { since: now - cfg.window, until: now };
  }
  function dlClampSel(a, b) {
    var ob = dlOuterBounds();
    var st = Math.max(ob.since, Math.min(a, b));
    var en = Math.min(ob.until, Math.max(a, b));
    if (en - st < DL_MIN_SEL_SECONDS) {
      en = Math.min(ob.until, st + DL_MIN_SEL_SECONDS);
      st = en - DL_MIN_SEL_SECONDS;
    }
    return { start: Math.floor(st), end: Math.ceil(en) };
  }
  function dlPickBucketCount(spanSecs) {
    return Math.min(90, Math.max(1, Math.floor(spanSecs / 60)));
  }

  function dlRenderBars(buckets) {
    var maxCount = buckets.reduce(function (m, b) { return Math.max(m, b.count); }, 0);
    var n = buckets.length || 1, barW = DL_W / n;
    var parts = ['<line x1="0" y1="' + (DL_H - 1) + '" x2="' + DL_W +
                 '" y2="' + (DL_H - 1) + '" class="axis"/>'];
    buckets.forEach(function (b, i) {
      var h = b.count > 0
        ? Math.max(1, Math.round((b.count / (maxCount || 1)) * (DL_H - 4))) : 0;
      if (!h) return;
      parts.push('<rect class="bar" x="' + (i * barW + 1) + '" y="' + (DL_H - h) +
        '" width="' + Math.max(1, barW - 2) + '" height="' + h + '"><title>' +
        esc(fmtDate(b.start)) + '–' + esc(fmtDate(b.start + dlBucketSecs)) + ': ' +
        esc(b.count) + ' deployment' + (b.count === 1 ? '' : 's') + '</title></rect>');
    });
    dlBarsG.innerHTML = parts.join('');   // bars layer only; brush layer persists
  }
  function dlRenderBrush(sel) {
    if (!sel || !dlDomain) { dlBrushG.innerHTML = ''; return; }
    var x0 = dlEpochToVb(sel.start), x1 = dlEpochToVb(sel.end);
    var hL = Math.max(0, Math.min(x0 - DL_HANDLE_VB / 2, DL_W - DL_HANDLE_VB));
    var hR = Math.max(0, Math.min(x1 - DL_HANDLE_VB / 2, DL_W - DL_HANDLE_VB));
    dlBrushG.innerHTML =
      '<rect class="brush-sel" x="' + x0 + '" y="0" width="' + Math.max(0, x1 - x0) +
      '" height="' + DL_H + '"/>' +
      '<rect class="brush-handle" x="' + hL + '" y="0" width="' + DL_HANDLE_VB + '" height="' + DL_H + '"/>' +
      '<rect class="brush-handle" x="' + hR + '" y="0" width="' + DL_HANDLE_VB + '" height="' + DL_H + '"/>';
  }
  function dlRenderWindowLabel(startOverride, endOverride) {
    var label = document.getElementById('dl-window-label');
    var clear = document.getElementById('dl-clear-selection');
    if (startOverride != null) {
      label.textContent = fmtDate(startOverride) + ' – ' + fmtDate(endOverride);
      return;
    }
    if (dlSel) {
      label.textContent = fmtDate(dlSel.start) + ' – ' + fmtDate(dlSel.end);
      clear.hidden = false;
    } else {
      var ob = dlOuterBounds();
      label.textContent = fmtDate(ob.since) + ' – now';
      clear.hidden = true;
    }
  }

  async function refreshDeployHistogram() {
    var url, domain;
    if (dlSel) {
      var span = dlSel.end - dlSel.start;
      url = '/api/deploy-logs/histogram?since_ts=' + encodeURIComponent(dlSel.start) +
        '&until_ts=' + encodeURIComponent(dlSel.end) +
        '&buckets=' + dlPickBucketCount(span);
      domain = { since: dlSel.start, until: dlSel.end };
    } else {
      var cfg = DL_RANGES[dlRange] || DL_RANGES['7d'];
      url = '/api/deploy-logs/histogram?window=' + cfg.window + '&buckets=' + cfg.buckets;
      domain = null;
    }
    var r = null;
    try { r = await fetch(url); } catch (e) { }
    if (!r || !r.ok) return;
    var body = await r.json();
    var buckets = body.buckets || [];
    var now = body.now || Math.floor(Date.now() / 1000);
    if (!domain) {
      var w = (DL_RANGES[dlRange] || DL_RANGES['7d']).window;
      domain = { since: now - w, until: now };
    }
    dlDomain = domain;
    dlBucketSecs = (domain.until - domain.since) / (buckets.length || 1);
    dlRenderBars(buckets);
    dlRenderBrush(dlSel);
    dlRenderWindowLabel();
  }

  function dlCommitSelection(a, b) { dlSel = dlClampSel(a, b); refreshDeployLogsAll(); }
  function dlClearSelection() { if (!dlSel) return; dlSel = null; refreshDeployLogsAll(); }

  // -- brush pointer state machine (mirrors the audit one) --
  var dlDrag = null;
  function dlHitTest(clientX) {
    if (dlSel) {
      var pxL = dlEpochToClientX(dlSel.start), pxR = dlEpochToClientX(dlSel.end);
      if (Math.abs(clientX - pxL) <= DL_HANDLE_HIT_PX) return 'left';
      if (Math.abs(clientX - pxR) <= DL_HANDLE_HIT_PX) return 'right';
      if (clientX > pxL && clientX < pxR) return 'pan';
    }
    return 'new';
  }
  if (dlSvg) {
    dlSvg.addEventListener('pointerdown', function (e) {
      if (e.button !== 0 || !e.isPrimary || dlDrag || !dlDomain) return;
      dlDrag = { mode: dlHitTest(e.clientX), downX: e.clientX,
                 anchor: dlClientXToEpoch(e.clientX), orig: dlSel, moved: false,
                 pending: null };
      dlSvg.setPointerCapture(e.pointerId);
      e.preventDefault();
    });
    dlSvg.addEventListener('pointermove', function (e) {
      if (!dlDrag) return;
      if (Math.abs(e.clientX - dlDrag.downX) > DL_CLICK_SLOP_PX) dlDrag.moved = true;
      if (!dlDrag.moved) return;
      var at = dlClientXToEpoch(e.clientX), sel;
      if (dlDrag.mode === 'left')       sel = dlClampSel(at, dlDrag.orig.end);
      else if (dlDrag.mode === 'right') sel = dlClampSel(dlDrag.orig.start, at);
      else if (dlDrag.mode === 'pan') {
        var shift = at - dlDrag.anchor;
        sel = dlClampSel(dlDrag.orig.start + shift, dlDrag.orig.end + shift);
      } else sel = dlClampSel(dlDrag.anchor, at);
      dlDrag.pending = sel;
      dlRenderBrush(sel);
      dlRenderWindowLabel(sel.start, sel.end);
    });
    dlSvg.addEventListener('pointerup', function (e) {
      if (!dlDrag) return;
      var d = dlDrag; dlDrag = null;
      try { dlSvg.releasePointerCapture(e.pointerId); } catch (err) { }
      if (!d.moved) { dlClearSelection(); return; }   // a click clears, as in audit
      if (d.pending) dlCommitSelection(d.pending.start, d.pending.end);
    });
  }
  document.querySelectorAll('#dl-range-chips .chip').forEach(function (c) {
    c.addEventListener('click', function () {
      document.querySelectorAll('#dl-range-chips .chip').forEach(function (o) {
        o.classList.toggle('active', o === c);
      });
      dlRange = c.getAttribute('data-range');
      dlSel = null;                       // a new outer window drops the selection
      refreshDeployLogsAll();
    });
  });
  (function () {
    var b = document.getElementById('dl-clear-selection');
    if (b) b.addEventListener('click', dlClearSelection);
  })();

  function renderDeployLogs() {
    var tbody = document.getElementById('dl-rows');
    var f = dlFilterState();
    var rows = dlAll.filter(function (l) { return deployLogMatches(l, f); });
    var pages = Math.max(1, Math.ceil(rows.length / DL_PAGE_SIZE));
    if (dlPage >= pages) dlPage = pages - 1;
    if (dlPage < 0) dlPage = 0;
    var page = rows.slice(dlPage * DL_PAGE_SIZE, (dlPage + 1) * DL_PAGE_SIZE);
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">No deployment logs match.</td></tr>';
    } else {
      tbody.innerHTML = page.map(function (l) {
        return '<tr data-file="' + esc(l.file) + '"><td>' + esc(fmtDate(l.finished_at)) +
          '</td><td>' + esc(l.device_id || '') + '</td><td>' + esc(l.action || '') +
          '</td><td>' + deployLogResult(l) + '</td><td>' + esc(fmtSize(l.size)) + '</td>' +
          '<td><button class="linkish dlog-view">view</button></td></tr>';
      }).join('');
      document.querySelectorAll('#dl-rows .dlog-view').forEach(function (btn) {
        btn.addEventListener('click', function () {
          openDeployLogDrawer(btn.closest('tr').getAttribute('data-file'));
        });
      });
    }
    document.getElementById('dl-count').textContent =
      rows.length + ' log' + (rows.length === 1 ? '' : 's') +
      (rows.length === dlAll.length ? '' : ' of ' + dlAll.length);
    document.getElementById('dl-page').textContent = 'page ' + (dlPage + 1) + ' of ' + pages;
    document.getElementById('dl-prev').disabled = dlPage === 0;
    document.getElementById('dl-next').disabled = dlPage >= pages - 1;
  }

  function openDeployLogDrawer(file) {
    var drawer = document.getElementById('dl-drawer');
    document.getElementById('dl-drawer-title').textContent = file;
    drawer.hidden = false;
    showDeployLog(file, document.getElementById('dl-text'));
  }
  function closeDeployLogDrawer() {
    document.getElementById('dl-drawer').hidden = true;
  }

  function dlListUrl() {
    // The brush selection narrows the list; with no selection the chip window
    // bounds it, so the table always shows the span the timeline is showing.
    var params = [];
    if (dlSel) {
      params.push('after_ts=' + dlSel.start, 'before_ts=' + dlSel.end);
    } else {
      var ob = dlOuterBounds();
      params.push('after_ts=' + Math.floor(ob.since));
    }
    return '/api/deploy-logs' + (params.length ? '?' + params.join('&') : '');
  }

  // Timeline and table are one view of one query: refresh them together, or a
  // selection would move the bars while the rows below still showed the old
  // range.
  async function refreshDeployLogsAll() {
    await Promise.all([refreshDeployHistogram(), refreshDeployLogs()]);
  }

  async function refreshDeployLogs() {
    var tbody = document.getElementById('dl-rows');
    var r = null;
    try { r = await fetch(dlListUrl()); } catch (e) { }
    if (!r || !r.ok) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">Deployment logs unavailable' +
        (r ? ' (' + r.status + ')' : '') + '.</td></tr>';
      return;
    }
    dlAll = (await r.json()).logs || [];
    if (!dlAll.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">No deployment logs in this range.</td></tr>';
      document.getElementById('dl-count').textContent = '';
      document.getElementById('dl-page').textContent = '';
      return;
    }
    renderDeployLogs();
  }
  document.getElementById('dl-refresh').addEventListener('click', refreshDeployLogsAll);
  ['dl-search', 'dl-action', 'dl-result'].forEach(function (id) {
    var el = document.getElementById(id);
    if (!el) return;
    el.addEventListener(el.tagName === 'SELECT' ? 'change' : 'input', function () {
      dlPage = 0; renderDeployLogs();
    });
  });
  document.getElementById('dl-prev').addEventListener('click', function () {
    if (dlPage > 0) { dlPage--; renderDeployLogs(); }
  });
  document.getElementById('dl-next').addEventListener('click', function () {
    dlPage++; renderDeployLogs();
  });
  document.getElementById('dl-drawer-close').addEventListener('click', closeDeployLogDrawer);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !document.getElementById('dl-drawer').hidden) {
      closeDeployLogDrawer();
    }
  });

  // OTLP export health badge (spec 8.3), via the console's session-gated
  // proxy — never the unauthenticated :9101 directly.
  async function refreshTelemetryHealth() {
    var el = document.getElementById('telemetry-health');
    if (!el) return;
    var state = 'unknown';
    el.title = '';
    try {
      var r = await fetch('/api/telemetry/health');
      var d = await r.json();
      if (d && d.otlp_export && d.otlp_export.signals) {
        var signals = d.otlp_export.signals;
        state = d.otlp_export.state || 'unknown';
        var detail = ['logs', 'metrics'].map(function (name) {
          var signal = signals[name] || {};
          var text = name + ': ' + (signal.state || 'unknown');
          if (name === 'logs') text += ', queued ' + (signal.queued || 0) + ', dropped ' + (signal.dropped_total || 0);
          return text;
        }).join('; ');
        el.title = detail;
      } else if (d && d.otlp_export && d.otlp_export.state) state = d.otlp_export.state;
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
  var VIEWS = ['overview', 'images', 'devices', 'swarm', 'settings', 'monitoring', 'setup'];

  // Periodic refresh of whatever view is on screen. Without this the console
  // only updated on navigation or after an explicit action, so device state
  // that changes server-side -- heartbeats, staging progress, deployment
  // state -- stayed invisible until the operator navigated away and back.
  // refreshDevices() already preserves batch checkbox selections across a
  // re-render, so a poll does not cost the operator their selection.
  var VIEW_POLL_MS = 10000;
  var viewPollTimer = null;
  var viewPollFn = null;
  function stopViewPoll() {
    if (viewPollTimer !== null) { clearInterval(viewPollTimer); viewPollTimer = null; }
  }
  function startViewPoll(fn) {
    stopViewPoll();
    viewPollFn = fn;
    if (!fn) return;
    viewPollTimer = setInterval(function () {
      // A backgrounded tab must not keep hitting the server. The
      // visibilitychange handler restarts the poll when the tab returns.
      if (document.hidden) return;
      try { fn(); } catch (e) { /* a failed refresh must not kill the poll */ }
    }, VIEW_POLL_MS);
  }
  document.addEventListener('visibilitychange', function () {
    // Refresh immediately on return so the operator never reads stale state
    // while waiting out the rest of an interval.
    if (!document.hidden && viewPollFn) {
      try { viewPollFn(); } catch (e) { /* ignore */ }
    }
  });

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
    var swarmFrame = document.getElementById('swarm-frame');
    if (swarmFrame && swarmFrame.contentWindow) {
      swarmFrame.contentWindow.postMessage(view === 'swarm' ? 'MAP_RESUME' : 'MAP_PAUSE', location.origin);
    }
    document.getElementById('settings-submenu').hidden = view !== 'settings';
    if (view === 'settings') showSettingsSub(sub || 'general');
    document.getElementById('monitoring-submenu').hidden = view !== 'monitoring';
    if (view === 'monitoring') showMonitoringSub(sub || 'audit');
    // Each view names the refresh the poll should repeat. Settings is
    // deliberately excluded: it is a set of forms, and re-rendering them
    // under the operator's cursor would discard half-typed input.
    var poll = null;
    if (view === 'overview') { refreshOverview(); poll = refreshOverview; }
    else if (view === 'images') {
      refreshImages(); refreshImportable();
      poll = function () { refreshImages(); refreshImportable(); };
    } else if (view === 'devices') { refreshDevices(); poll = refreshDevices; }
    else if (view === 'swarm') { refreshSwarm(); poll = refreshSwarm; }
    else if (view === 'settings') { refreshSettings(); refreshSetup(); }
    else if (view === 'monitoring') { refreshMonitoring(); poll = refreshMonitoring; }
    else if (view === 'setup') enterSetupWizard();
    startViewPoll(poll);
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
