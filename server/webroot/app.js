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

  // ---- one fetch for the whole console ------------------------------------
  // Shadows window.fetch inside this closure so EVERY request made by this
  // file goes through it (function declarations hoist, so the session check
  // above used it too). Three concerns no individual refresher used to
  // handle:
  //  1. Session loss after the initial check (container restart, "Sign out
  //     other sessions" from another tab, idle expiry): a 401 anywhere stops
  //     the view poll and sends the operator to the login page, instead of
  //     every poll returning silently and a frozen fleet view passing for
  //     live for the rest of the day.
  //  2. A poll that fails (server down, 5xx, network) is announced in the
  //     header as "live data unavailable since <time>" while the last known
  //     state stays on screen; the note clears on the next successful GET.
  //  3. Background polls are marked with "X-IRIS-Poll: 1" (GET only). The
  //     server validates the session for them WITHOUT refreshing its idle
  //     clock, so an unattended console on a polled view reaches the idle
  //     timeout Settings advertises. "Background" = no operator input since
  //     the poll tick began: pointer/keyboard input clears the mark, so a
  //     refresh the operator actually caused still counts as activity.
  // window.fetch is called directly (never cached in a var): the session
  // check above runs before any var here is assigned, and hoisting means
  // it already goes through this wrapper.
  var sessionLost = false;
  var backgroundPoll = false;
  var staleSince = null;
  ['pointerdown', 'keydown'].forEach(function (ev) {
    document.addEventListener(ev, function () { backgroundPoll = false; }, true);
  });
  function markConnection(ok) {
    var el = document.getElementById('conn-state');
    if (!el) return;
    // == null on purpose: the session check above runs before this
    // closure's vars are assigned, so staleSince can still be undefined.
    if (ok) {
      if (staleSince != null) { staleSince = null; el.hidden = true; el.textContent = ''; }
      return;
    }
    if (staleSince == null) staleSince = new Date();
    el.textContent = 'Live data unavailable since ' + staleSince.toLocaleTimeString() +
      ' — showing the last known state, retrying.';
    el.hidden = false;
  }
  function onSessionLost() {
    if (sessionLost) return;
    sessionLost = true;
    try { stopViewPoll(); } catch (e) { /* not wired yet */ }
    window.location.href = '/login.html';
  }
  function fetch(url, opts) {
    opts = opts || {};
    var isGet = !opts.method || String(opts.method).toUpperCase() === 'GET';
    if (isGet && backgroundPoll) {
      var h = new Headers(opts.headers || {});
      h.set('X-IRIS-Poll', '1');
      opts = Object.assign({}, opts, { headers: h });
    }
    return window.fetch(url, opts).then(function (r) {
      if (r.status === 401) onSessionLost();
      else if (isGet && r.status >= 500) markConnection(false);
      else if (isGet && r.ok) markConnection(true);
      return r;
    }, function (err) {
      if (isGet && !(err && err.name === 'AbortError')) markConnection(false);
      throw err;
    });
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function dash(v) { return v ? esc(v) : '—'; }
  // Telemetry posture as the DEVICE last reported it (not what onboarding
  // asked for). Tri-state: an agent that predates the flag reports nothing,
  // which is "unknown" — never shown as "off", since off is a real choice.
  // ---- Devices: column filters -------------------------------------------
  // Every bulk action operates on an explicit id SET (SELECTED, below), and
  // the table renders only what the server just said matches -- filtering
  // then "select all" is how an operator acts on a subset without hand-
  // picking. Filter state lives in the DOM controls, not in the row data,
  // so the periodic re-render never clears it.
  //
  // Issue #112: the six column filters and the status filter now have
  // SERVER-SIDE parity (gui_server.py's _row_matches_extra_filters mirrors
  // deviceMatchesFilters below condition-for-condition) -- a prerequisite
  // for paging the table, because a page filtered only on what the server
  // understood would silently disagree with the filter bar. deviceOffset/
  // devTotal/DEV_PAGE_SIZE (below) are that paging; SELECTED is prerequisite
  // 2, selection keyed by device_id rather than by rendered DOM row, so a
  // bulk action still hits exactly the ids the operator meant after a page
  // turns, a filter changes, or a poll re-renders.
  var LAST_DEVICES = [];
  var LAST_DEV_NOW = 0;
  var DEV_PAGE_SIZE = 200;
  var devOffset = 0;   // start of the CURRENTLY LOADED page, within the filtered set
  var devTotal = 0;    // server's total match count for the current filter (all pages)
  // device_id -> true. Populated by row/header checkboxes and by
  // selectAllMatchingDevices() (the real "every matching device" action);
  // never scraped from '#dev-rows .mark:checked', which -- once the table is
  // paged -- reflects only the page currently in the DOM.
  var SELECTED = Object.create(null);
  // device_id -> the most relevant retained onboard/undeploy job (facelift
  // carried fix #2, step/elapsed in the status cell). Refreshed alongside
  // the devices table from the EXISTING GET /api/onboard/jobs listing
  // (already used by the batch panel) -- the /api/devices merge itself
  // (_device_view()/latest_jobs_by_device() server-side) deliberately trims
  // started_at and last_line off, so this is a client-side-only
  // cross-reference by device_id, never a server change.
  var LAST_JOBS_BY_DEVICE = Object.create(null);

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
  // The SAME filter state as a GET /api/devices query string (q/
  // management_type/platform/cred/telemetry/peer/status) -- the wire names
  // _device_filter_params (gui_server.py) reads. Kept as one function so a
  // filter added to deviceFilterState() above can never be forgotten here.
  function deviceFilterQuery(f) {
    var names = { q: 'q', managementType: 'management_type', platform: 'platform',
                  cred: 'cred', telemetry: 'telemetry', peer: 'peer', status: 'status' };
    var parts = [];
    Object.keys(names).forEach(function (key) {
      if (f[key]) parts.push(names[key] + '=' + encodeURIComponent(f[key]));
    });
    return parts.join('&');
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
  // Labels here are sentence case (Magnetic pill grammar, Task 4) -- they
  // double as statusDisplay()'s default text below, so the dropdown and the
  // rendered pill share one copy of every static label and cannot drift
  // apart. 'deployed' is the one WIRE key that keeps its old spelling while
  // its DISPLAY text becomes "Staged" (spec: derivation in app.js unchanged).
  var DEVICE_STATUS_OPTIONS = [
    ['onboarding', 'Onboarding'],
    ['undeploying', 'Undeploying'],
    ['waiting-heartbeat', 'Waiting for heartbeat'],
    ['onboard-failed', 'Onboard failed'],
    ['undeploy-failed', 'Undeploy failed'],
    ['deployed', 'Staged'],
    ['placement-failed', 'Placement failed'],
    ['image-failed', 'Image(s) failed'],
    ['copying', 'Copying to IOS storage'],
    ['staging', 'Staging (other)'],
    ['unassigned', 'Unassigned'],
    ['enrolled', 'Enrolled'],
    ['not-enrolled', 'Not enrolled'],
    ['offline', 'Offline (no recent heartbeat)']
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
    // A legacy single-image agent reports this literal stage_state (it is
    // absent from catalog.py's _V2_STAGE_STATES, so no current agent sends
    // it). It used to fall through to the catch-all below, which rendered the
    // raw word under the PROGRESS level -- an idle device dressed as one mid
    // transfer, and selectable only via "Staging (other)" along with every
    // other raw state.
    if (d.stage_state === 'unassigned') {
      return { key: 'unassigned', label: 'unassigned', cls: 'muted' };
    }
    if (d.stage_state) {
      return { key: 'staging', label: d.stage_state, cls: 'badge badge-running' };
    }
    // Enrolled with an empty assigned set. This read "enrolled" before, which
    // is true but hides the one thing an operator can act on -- and nothing
    // else in the row distinguishes them, so there was no way to ask the table
    // "which devices have I not assigned an image to yet". Ordered AFTER every
    // staging/error branch (a device mid-stage is not unassigned) and BEFORE
    // 'enrolled', but never ahead of 'not-enrolled': an agent that has never
    // checked in is not yet an assignment problem.
    if (d.last_seen && !assignedIds.length) {
      return { key: 'unassigned', label: 'unassigned', cls: 'muted' };
    }
    if (d.last_seen) {
      return { key: 'enrolled', label: 'enrolled', cls: 'badge badge-queued' };
    }
    return { key: 'not-enrolled', label: 'not enrolled', cls: 'muted' };
  }

  // ---- Status pill grammar (12-level Magnetic mapping, Task 4) ----------
  // One level (and one icon) per status, built next to deviceStatus() so a
  // key can never be renderable under a level this map doesn't cover --
  // same "one derivation feeds both" reasoning as DEVICE_STATUS_OPTIONS
  // above. Positive is BLUE-family per Magnetic, not green: green stays
  // reserved for Allow/policy grammar elsewhere in the console.
  var STATUS_OPTION_LABELS = {};
  DEVICE_STATUS_OPTIONS.forEach(function (o) { STATUS_OPTION_LABELS[o[0]] = o[1]; });
  // copying/staging/image-failed carry PER-DEVICE text deviceStatus() itself
  // already built (target filesystem, the raw stage_state, an N-of-M count)
  // -- the option label above is only their generic dropdown stand-in, never
  // what a row's own pill should show.
  var STATUS_DYNAMIC_KEYS = { copying: 1, staging: 1, 'image-failed': 1 };
  // offline's dropdown text is a full explanation ("no recent heartbeat"),
  // too long beside the status it modifies -- the pill gets the short form.
  var STATUS_PILL_LABEL_OVERRIDES = { offline: 'Offline' };
  var STATUS_LEVELS = {
    onboarding: 'progress', undeploying: 'progress',
    copying: 'progress', staging: 'progress',
    'waiting-heartbeat': 'info',
    'onboard-failed': 'negative', 'undeploy-failed': 'negative',
    'placement-failed': 'negative',
    deployed: 'positive', enrolled: 'positive',
    'image-failed': 'warning',   // overridden to 'severe' by ratio below
    // A resting state that wants an operator, not a transfer in flight --
    // same family as not-enrolled, deliberately not 'progress'.
    unassigned: 'inactive',
    'not-enrolled': 'inactive', offline: 'inactive'
  };
  var STATUS_ICONS = {
    positive: 'i-check-circle', progress: 'i-dash-circle', negative: 'i-octagon-x',
    warning: 'i-triangle-warn', severe: 'i-diamond-severe', info: 'i-square-info',
    inactive: 'i-minus-circle', disabled: 'i-slash-circle'
  };
  function statusSentenceCase(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  // status: the {key, label, ...} object deviceStatus() returns, or a bare
  // key string for the one modifier deviceStatus() never produces itself
  // ('offline', applied by deviceIsOffline() on top of whatever the cell
  // already says). ratio: errored/assigned images, image-failed only --
  // swings the pill between the amber warning and the orange severe diamond
  // (N-of-M by severity, spec status grammar).
  function statusDisplay(status, ratio) {
    var key = typeof status === 'string' ? status : status.key;
    var level = STATUS_LEVELS[key] || 'inactive';
    var label;
    if (key === 'image-failed') {
      level = (ratio || 0) >= 0.5 ? 'severe' : 'warning';
      label = (status && status.label) || STATUS_OPTION_LABELS[key] || key;
    } else if (STATUS_DYNAMIC_KEYS[key]) {
      label = statusSentenceCase((status && status.label) || STATUS_OPTION_LABELS[key] || key);
    } else {
      label = STATUS_PILL_LABEL_OVERRIDES[key] || STATUS_OPTION_LABELS[key] || key;
    }
    return { label: label, level: level };
  }

  // Icon + sentence-case label, tinted background, never color alone. <use>
  // only ever references the sprite vendored in index.html; the label text
  // (not the icon) carries the accessible name, so the sprite stays
  // aria-hidden and the icon itself needs none.
  //
  // levelPillHTML is the raw renderer (level chosen directly by the
  // caller); statusPillHTML derives the level from a deviceStatus() key via
  // statusDisplay() first, then hands off to it. Splitting them out (Task
  // 7) lets non-deviceStatus() domains -- the Cisco Bulk Hash verdict pill,
  // the Overview "Needs attention" rollup cards, a Staging Boundary
  // step's failed-step pill -- share the exact same markup/CSS without
  // borrowing deviceStatus()'s key space, which the spec keeps separate
  // ("device pill vs image verdict pill share only the same 8-level
  // PALETTE, not one key space").
  function levelPillHTML(level, label, opts) {
    opts = opts || {};
    var icon = STATUS_ICONS[level] || STATUS_ICONS.inactive;
    var titleAttr = opts.title ? ' title="' + esc(opts.title) + '"' : '';
    return '<span class="status-pill is-' + level + '"' + titleAttr + '>' +
      '<svg aria-hidden="true"><use href="#' + icon + '"></use></svg>' +
      esc(label) + '</span>';
  }
  function statusPillHTML(status, opts) {
    opts = opts || {};
    var d = statusDisplay(status, opts.ratio);
    return levelPillHTML(d.level, d.label, opts);
  }

  // ---- Staging Boundary (spec §4 "Signature: Staging Boundary") ----------
  // The one intentional IRIS signature: Catalogued -> Source checked ->
  // Assigned -> Transferring -> Verified -> Staged, then a hatched
  // "Operator control" terminus -- installation, activation and reload
  // stay outside IRIS. stagingBoundaryHTML(steps) is the ONE renderer,
  // shared verbatim by every device/image detail context that shows it
  // (Task 8; Overview's own fleet-wide instance was removed per operator
  // decision, Wave C) -- callers derive `steps` from whatever data THEIR
  // view actually has and must never guess: an unknown or not-applicable
  // step stays the explicit 'na' state, not an inferred 'done'.
  //
  // `steps` is an array of six entries, one per BOUNDARY_STEPS below, each
  // either a bare state string -- 'done' | 'current' | 'upcoming' | 'na' --
  // or, only for a failed step, `{ state: 'failed', pillHtml: '<pre-
  // rendered pill>' }` (built with levelPillHTML, so it matches every other
  // pill in the console). A missing/unrecognized entry renders as
  // 'upcoming' (a plain outline), never as progress that was not reported.
  var BOUNDARY_STEPS = [
    { label: "Catalogued" }, { label: "Source checked" }, { label: "Assigned" },
    { label: "Transferring" }, { label: "Verified" }, { label: "Staged" }
  ];
  function boundaryMarkerHTML(state, pillHtml) {
    if (state === 'failed' && pillHtml) {
      return '<span class="boundary-marker">' + pillHtml + '</span>';
    }
    if (state === 'done') {
      return '<span class="boundary-circle is-done">' +
        '<svg aria-hidden="true"><use href="#i-check"></use></svg></span>';
    }
    if (state === 'current') {
      return '<span class="boundary-circle is-current"><span class="boundary-dot"></span></span>';
    }
    if (state === 'na') {
      return '<span class="boundary-circle is-na"></span>';
    }
    // upcoming, and the safe default for anything unrecognized -- a plain
    // outline claims no progress at all, so an unknown value never reads
    // as more complete than it is.
    return '<span class="boundary-circle is-upcoming"></span>';
  }
  function stagingBoundaryHTML(steps) {
    steps = steps || [];
    var stepsHtml = BOUNDARY_STEPS.map(function (step, i) {
      var entry = steps[i];
      var state = typeof entry === 'string' ? entry : (entry && entry.state) || 'upcoming';
      var pillHtml = (entry && typeof entry === 'object') ? entry.pillHtml : null;
      var connector = i > 0 ? '<span class="boundary-connector" aria-hidden="true"></span>' : '';
      return connector + '<span class="boundary-step is-' + esc(state) + '">' +
        boundaryMarkerHTML(state, pillHtml) +
        '<span class="boundary-label">' + esc(step.label) + '</span></span>';
    }).join('');
    return '<div class="staging-boundary">' + stepsHtml +
      '<span class="boundary-connector" aria-hidden="true"></span>' +
      '<span class="boundary-terminus"><span class="boundary-terminus-label">' +
      'Operator control</span></span></div>';
  }

  // Shared by deviceStatusHtml and Overview's "Needs attention" tally
  // (overviewDeviceAttention): image-failed's severity (warning vs severe)
  // depends on THIS device's own errored/assigned ratio -- one derivation,
  // so a fleet rollup can never grade a device's severity differently than
  // its own row does.
  function imageFailedRatio(d) {
    var assigned = rowAssignedIds(d);
    var errored = rowErroredIds(d).filter(function (iid) {
      return assigned.indexOf(iid) !== -1;
    });
    return assigned.length ? errored.length / assigned.length : 0;
  }
  // key deviceStatus() can return while an onboard/undeploy job is active ->
  // the job action that must match it, so a stale/superseded job for this
  // device (a different action, or one that already finished) can never be
  // mistaken for the one the cell is describing right now.
  var JOB_ACTION_FOR_STATUS_KEY = { onboarding: 'onboard', undeploying: 'undeploy' };
  function deviceStatusHtml(d, devNow) {
    var st = deviceStatus(d, devNow);
    var ratio = st.key === 'image-failed' ? imageFailedRatio(d) : undefined;
    var job = LAST_JOBS_BY_DEVICE[d.device_id];
    var activeJob = (job && (job.state === 'queued' || job.state === 'running') &&
      job.action === JOB_ACTION_FOR_STATUS_KEY[st.key]) ? job : null;
    var html;
    if (activeJob) {
      // carried fix #2: append " [n/m] · Xm" to the in-progress label
      // itself, rather than going through statusPillHTML/STATUS_DYNAMIC_KEYS
      // (which would sentence-case a label deviceStatus() never set for
      // onboarding/undeploying) -- every other status key's rendering below
      // is byte-identical to before.
      var disp = statusDisplay(st, ratio);
      html = levelPillHTML(disp.level, disp.label + jobPhaseSuffix(activeJob), { title: st.detail });
    } else {
      html = statusPillHTML(st, { title: st.detail, ratio: ratio });
    }
    if (st.detail) {
      html += ' <span class="muted" title="' + esc(st.detail) + '">' + esc(st.detail) + '</span>';
    }
    if (deviceIsOffline(d, devNow)) {
      // carried fix #3: a device already offline/stale WHILE its own
      // undeploy job is actually RUNNING is the expected shape of a
      // healthy teardown -- undeploy step [1/5] deactivates the agent (EEM
      // applets removed, or the appmgr app stopped on XR) well before the
      // rest of the job finishes, so no heartbeat is exactly what should
      // happen. deviceStatus() sets st.key 'undeploying' for BOTH a queued
      // AND a running job (it only reads d.onboard_state, not the job's own
      // record), so gating on st.key alone would label a device stuck
      // behind the onboard concurrency cap as "expected offline" before its
      // job has even started -- a false claim (review finding: a batch
      // undeploy beyond max_concurrent showed step [1/5] deactivated on
      // devices whose job never touched them). Gate on the CROSS-REFERENCED
      // job's own state === 'running' instead; a queued job's offline
      // device keeps the normal, honest "no recent heartbeat" treatment.
      if (activeJob && activeJob.state === 'running' && st.key === 'undeploying') {
        html += ' ' + levelPillHTML('inactive', 'Offline (expected during undeploy)',
          { title: 'The agent is deactivated at undeploy step [1/5]; no heartbeat is expected again until it re-enrolls.' });
      } else {
        html += ' ' + statusPillHTML('offline');
      }
    }
    return html;
  }
  function deviceIsOffline(d, devNow) {
    return !!(d.last_seen && (devNow - d.last_seen) >= 600);
  }
  // device_id -> job for every RETAINED onboard/undeploy job (from GET
  // /api/onboard/jobs, already fetched by refreshDevices) -> the one job
  // deviceStatusHtml should read for that device: mirrors gui_onboard.py's
  // own latest_jobs_by_device() tie-break exactly (an ACTIVE queued/running
  // job wins outright, else the most recently queued one), just kept on the
  // client so started_at and last_line survive the trip -- the server's own
  // merge into /api/devices deliberately strips both (the raw data already
  // exists in the job listing; it is simply not in the trimmed
  // latest_jobs_by_device() dict). Device ids are operator-chosen, so the
  // map must not inherit anything from Object.prototype.
  function bestJobForDevice(jobs) {
    var best = Object.create(null);
    (jobs || []).forEach(function (j) {
      var did = j.device_id, cur = best[did];
      var active = j.state === 'queued' || j.state === 'running';
      if (!cur) { best[did] = j; return; }
      var curActive = cur.state === 'queued' || cur.state === 'running';
      if ((active && !curActive) ||
          (active === curActive && j.queued_at > cur.queued_at)) {
        best[did] = j;
      }
    });
    return best;
  }
  // A job's freshest log line (last_line) carries a "[n/m]" step marker only
  // on the tick its install/uninstall script actually echoes one
  // (device-install.sh etc. echo "[n/m] ..." per step) -- most ticks in
  // between (e.g. the guestshell-enable step, which can take several
  // minutes on a cold IOx start) show plain progress text with no bracket.
  // Remembering the newest step seen PER JOB keeps the status cell's step
  // count steady between brackets instead of flickering in and out every
  // ~10s poll; pruned back in refreshDevices() as jobs age out.
  var lastJobStep = {};
  function jobPhaseSuffix(job) {
    if (!job || !job.started_at) return '';
    var m = /\[(\d+\/\d+)\]/.exec(job.last_line || '');
    if (m) lastJobStep[job.id] = m[1];
    var step = lastJobStep[job.id];
    // Elapsed is SERVER clock minus SERVER clock (job.started_at is the
    // job's own started_at timestamp; LAST_DEV_NOW is the same server "now"
    // refreshDevices() already reads for offline-freshness math) -- never a
    // client-clock delta, so a page refresh (or a skewed lab VM) never
    // resets or distorts what looks like elapsed progress.
    var now = LAST_DEV_NOW || (Date.now() / 1000);
    var elapsedMin = Math.max(0, Math.round((now - job.started_at) / 60));
    var elapsed = elapsedMin >= 60
      ? Math.floor(elapsedMin / 60) + ' h ' + (elapsedMin % 60) + ' min'
      : elapsedMin + ' min';
    return (step ? ' [' + step + ']' : '') + ' · ' + elapsed;
  }

  function deviceMatchesFilters(d, f, devNow) {
    if (f.q) {
      var hay = [d.device_id, d.device_ip, d.model, d.heartbeat_model]
        .filter(Boolean).join(' ').toLowerCase();
      if (hay.indexOf(f.q) === -1) return false;
    }
    // Mirrors managementTypeLabel's own legacy_routed/legacy equivalence
    // (below, in the row renderer) without touching that pinned line: the
    // wire value for an unclassified device is always the truthy
    // "legacy_routed" (gui_fleet.py's _legacy_record/_legacy_like), so the
    // naive `d.management_type || 'legacy'` fallback here never actually
    // fires and the value="legacy" filter option matched zero rows every
    // time an operator picked it (facelift M2, ADJUDICATED repair-not-
    // remove: the option itself stays exactly as it is).
    if (f.managementType && (d.management_type === 'legacy_routed' ? 'legacy' : (d.management_type || 'legacy')) !== f.managementType) return false;
    if (f.platform) {
      var plat = d.platform || '';
      if (f.platform === '__none' ? plat !== '' : plat !== f.platform) return false;
    }
    if (f.cred) {
      var cred = d.credential_profile_id || '';
      if (f.cred === '__none' ? cred !== '' : cred !== f.cred) return false;
    }
    if (f.telemetry) {
      // Same tri-state as telemetryCell: "on" only when the device has
      // actually reported telemetry (never-heartbeated devices are
      // "unknown", not silently bucketed with "on").
      var tel = d.telemetry_enabled === false ? 'off'
        : (d.telemetry_enabled === true || typeof d.telemetry_stream_enabled === 'boolean') ? 'on'
        : 'unknown';
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
      // '__attention': Overview's "Needs attention" rollup card routes here
      // (goToDevicesFiltered below) -- any level the Magnetic grammar marks
      // negative/severe/warning, spanning BOTH IRIS lifecycles (agent
      // deployment AND target-software staging). A general "what needs me"
      // filter, unlike the Staging Boundary's own failed-step derivation
      // (deviceBoundarySteps, the device drawer's per-device instance),
      // which stays scoped to the staging lifecycle only -- see that
      // function's comment.
      else if (f.status === '__attention') {
        var lvl = statusDisplay(deviceStatus(d, devNow)).level;
        if (lvl !== 'negative' && lvl !== 'severe' && lvl !== 'warning') return false;
      }
      else if (deviceStatus(d, devNow).key !== f.status) return false;
    }
    return true;
  }
  // Set once by an Overview "Needs attention" devices card just before
  // routing here; consumed the next time the devices list is (re)fetched.
  var PENDING_DEV_FILTER = null;
  function goToDevicesFiltered(status) {
    PENDING_DEV_FILTER = status;
    location.hash = '#devices';
  }

  // A filter or search change now means the match set itself changed
  // server-side (issue #112 prerequisite 1 made that possible), so this
  // returns to page one and re-fetches rather than re-rendering the page
  // already in hand -- the OLD behavior, back when every filter ran
  // client-side over the whole fleet already in memory. Debounced: the q
  // box fires on every keystroke ('input', not 'change'), and a fetch per
  // keystroke would hammer the server on a fast typist.
  var applyDeviceFiltersTimer = null;
  function applyDeviceFilters() {
    if (applyDeviceFiltersTimer) clearTimeout(applyDeviceFiltersTimer);
    applyDeviceFiltersTimer = setTimeout(function () {
      applyDeviceFiltersTimer = null;
      devOffset = 0;
      refreshDevices();
    }, 250);
  }

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

  // Focus trap for a modal/drawer overlay (Task 6): Tab/Shift+Tab cycle
  // within the container's own focusable elements instead of escaping to
  // the page behind it. Modeled on server/swarmmap.html's #drawer keydown
  // handler, ported to this file's ES5 style. Attaching the listener
  // directly on the container (rather than document) is what makes this
  // safe to call once at setup time for every dialog: while the container
  // carries [hidden] nothing inside it is focusable, so no keydown ever
  // bubbles out of it and the trap is inert until the dialog is actually
  // open.
  function trapDialogFocus(container) {
    container.addEventListener('keydown', function (e) {
      if (e.key !== 'Tab') return;
      var focusable = Array.prototype.filter.call(
        container.querySelectorAll(
          'button:not([disabled]), [href], input:not([disabled]), ' +
          'select:not([disabled]), textarea:not([disabled]), ' +
          '[tabindex]:not([tabindex="-1"])'),
        function (el) { return el.offsetWidth > 0 || el.offsetHeight > 0; });
      if (!focusable.length) return;
      var first = focusable[0], last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault(); last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault(); first.focus();
      }
    });
  }

  // ---- Images (unchanged behavior) ----
  var statusEl = document.getElementById('status');
  var imageJobGen = 0;
  // The full last-fetched /api/images rows, kept for the image-detail drawer
  // (KGV / Cisco Bulk Hash reconciler, Task 5) -- refreshImages() only ever
  // wrote row HTML before, with nowhere to read a single image's verdict
  // back out of once the drawer needed one.
  var LAST_IMAGES = [];
  // Verdict PILL (Task 7: was a plain .badge, now the Magnetic status-pill
  // grammar) shared by the Images catalog, the image-detail drawer and the
  // image picker: null state (never checked) reads as neutral, a mismatch
  // reads as quarantined only while quarantined is actually still true (an
  // override-released mismatch stays a mismatch verdict forever --
  // release_quarantine() deliberately never rewrites hash_verification.state
  // -- but it is no longer BLOCKING anything, so it must not keep claiming
  // "quarantined"). Deferral is an orthogonal warning that can accompany any
  // state, per the spec. A standalone derivation (not routed through
  // statusDisplay()'s deviceStatus() key space) -- see levelPillHTML's own
  // comment for why the two domains stay separate.
  function bulkhashVerdictPillHTML(hv, quarantined) {
    var state = hv && hv.state;
    var html;
    if (!state) {
      html = levelPillHTML('inactive', 'Not checked');
    } else if (state === 'verified') {
      html = levelPillHTML('positive', 'Verified');
    } else if (state === 'mismatch') {
      html = quarantined
        ? levelPillHTML('negative', 'Mismatch — quarantined')
        : levelPillHTML('negative', 'Mismatch — released');
    } else if (state === 'not_in_feed') {
      html = levelPillHTML('inactive', 'Not in Cisco\'s feed');
    } else {
      // Defensive: bulkhash.py only ever writes verified/mismatch/
      // not_in_feed, but a catch-all that silently relabeled anything else
      // as "Not in Cisco's feed" would misreport a genuinely unrecognized
      // state as a specific, wrong verdict instead of admitting it doesn't
      // know.
      html = levelPillHTML('inactive', 'Unknown verification state');
    }
    if (hv && hv.deferral) {
      html += ' ' + levelPillHTML('warning', 'Deferred by Cisco', { title: 'Deferred by Cisco' });
    }
    return html;
  }
  // Set once by an Overview "Needs attention" image card (goToImagesFiltered
  // below) just before routing here; consumed the next time the catalog's
  // data is (re)fetched, so the toggle below reflects it even though the
  // fetch and the navigation race each other.
  var PENDING_IMG_ATTENTION = false;
  async function refreshImages() {
    var r = await fetch('/api/images'); if (!r.ok) return;
    var imgs = (await r.json()).images || [];
    imgs.sort(function (a, b) { return (b.published_at || 0) - (a.published_at || 0); });
    LAST_IMAGES = imgs;
    if (PENDING_IMG_ATTENTION) {
      var attnBox = document.getElementById('images-filter-attention');
      if (attnBox) attnBox.checked = true;
      PENDING_IMG_ATTENTION = false;
    }
    renderImageRows();
  }
  // Pure client-side render from LAST_IMAGES -- no fetch -- so the "Needs
  // attention only" toggle can re-render instantly, the same pattern
  // applyDeviceFilters() uses for the Devices table.
  function renderImageRows() {
    var attnBox = document.getElementById('images-filter-attention');
    var attnOnly = !!(attnBox && attnBox.checked);
    var imgs = attnOnly
      ? LAST_IMAGES.filter(function (i) { return !!i.quarantined; })
      : LAST_IMAGES;
    // Catalog rows lead with the exact filename + verdict pill; image id
    // stays adjacent (spec Task 7 Step 5).
    document.getElementById('rows').innerHTML = imgs.length ? imgs.map(function (i) {
      return '<tr data-id="' + esc(i.id) + '"><td class="machine">' + dash(i.filename) + '</td><td>' +
        bulkhashVerdictPillHTML(i.hash_verification, i.quarantined) + '</td><td class="machine">' + esc(i.id) +
        '</td><td class="machine">' + esc(fmtSize(i.size)) + '</td><td class="machine">' +
        esc((i.sha256 || '').slice(0, 16)) + '…</td><td class="machine">' + esc(fmtDate(i.published_at)) +
        '</td><td><button class="linkish img-info" title="Image details" aria-label="' +
        'Image details for ' + esc(i.id) + '">ⓘ</button> ' +
        '<button class="linkish danger-link del-img">delete</button></td></tr>';
    }).join('') : '<tr><td colspan="7" class="muted">No images match.</td></tr>';
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
    var countEl = document.getElementById('images-count');
    if (countEl) {
      countEl.textContent = attnOnly
        ? imgs.length + ' of ' + LAST_IMAGES.length + ' image' + (LAST_IMAGES.length === 1 ? '' : 's')
        : LAST_IMAGES.length + ' image' + (LAST_IMAGES.length === 1 ? '' : 's');
    }
  }
  document.getElementById('images-filter-attention').addEventListener('change', renderImageRows);
  // Overview's quarantined-images attention card routes here.
  function goToImagesFiltered() {
    PENDING_IMG_ATTENTION = true;
    location.hash = '#images';
  }
  // ---- Image detail drawer: verdict + release-from-quarantine, with the
  // typed-confirm override path (KGV / Cisco Bulk Hash reconciler, Task 5).
  // Mirrors openDeployInfo/closeDeployInfo's drawer pattern below.
  var imgInfoId = null;
  var imgInfoOpener = null;
  function imageVerdictDetailText(hv) {
    if (!hv || !hv.checked_at) return 'Never checked against the Cisco Bulk Hash feed.';
    var text = 'Checked ' + fmtDate(hv.checked_at) + ' (source: ' + (hv.source || 'unknown') + ')';
    if (hv.feed_published_at) text += '; feed published ' + fmtDate(hv.feed_published_at);
    return text + '.';
  }
  function openImageInfo(id) {
    imgInfoId = id;
    imgInfoOpener = document.activeElement;
    var img = LAST_IMAGES.filter(function (x) { return x.id === id; })[0] || {};
    document.getElementById('ii-id').textContent = id;
    document.getElementById('ii-file').textContent = img.filename || '';
    document.getElementById('ii-verdict').innerHTML = bulkhashVerdictPillHTML(img.hash_verification, img.quarantined);
    document.getElementById('ii-verdict-detail').textContent = imageVerdictDetailText(img.hash_verification);
    // The operator's own `iris-publish --signature-verified` attestation
    // (operator_attested_signature) is a separate fact from the reconciler's
    // verdict above (cisco_signature_verified) -- #88, so it never disappears
    // when the reconciler runs. Shown plainly, never as a pill, so it never
    // reads as a second automated verdict.
    document.getElementById('ii-operator-attestation').textContent =
      img.operator_attested_signature
        ? 'Operator attested at publish time that the Cisco signature was verified elsewhere.'
        : 'Not attested by the publishing operator.';
    // The release action only makes sense while an image is ACTUALLY
    // quarantined -- an override-released mismatch keeps its "mismatch"
    // verdict (see bulkhashVerdictPillHTML) but is not blocking anything, so
    // there is nothing left here to release.
    document.getElementById('ii-release-block').hidden = !img.quarantined;
    document.getElementById('ii-override-block').hidden = true;
    document.getElementById('ii-override-note').textContent = '';
    document.getElementById('ii-confirm-text').value = '';
    document.getElementById('ii-release-msg').textContent = '';
    document.getElementById('img-info-panel').hidden = false;
    document.getElementById('ii-close').focus();
  }
  function closeImageInfo() {
    imgInfoId = null;
    document.getElementById('img-info-panel').hidden = true;
    if (imgInfoOpener) { imgInfoOpener.focus(); imgInfoOpener = null; }
  }
  document.getElementById('ii-close').addEventListener('click', closeImageInfo);
  document.addEventListener('keydown', function (e) {
    var panel = document.getElementById('img-info-panel');
    if (e.key === 'Escape' && panel && !panel.hidden) closeImageInfo();
  });
  // No trapDialogFocus here (Task 6, fix wave): this drawer is non-modal --
  // no backdrop, openImageInfo can be called again for another row while
  // this is open -- so Tab must be free to leave it for the rest of the
  // page. Focus still moves in on open and is restored to the opener above.
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
        if (j.state === 'done') { statusEl.textContent = 'Published ' + (j.image_id || '') + ' ✓'; refreshImages().catch(function () {}); refreshImportable().catch(function () {}); }
        else if (j.state === 'error') { statusEl.textContent = 'Publish failed: ' + j.message; refreshImportable().catch(function () {}); }
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
      return '<tr><td class="machine">' + esc(c.filename) + '</td><td class="machine">' + esc(fmtSize(c.size)) +
        '</td><td class="muted machine">' + esc(c.path) +
        '</td><td><button class="linkish do-import" data-path="' + esc(c.path) +
        '">import</button></td></tr>';
    }).concat(skipped.map(function (c) {
      return '<tr class="muted"><td class="machine">' + esc(c.filename) + '</td><td class="machine">' +
        esc(fmtSize(c.size)) + '</td><td class="muted machine">' + esc(c.path) +
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
  // uploads never fight over shared elements. The legacy #status singleton
  // above now serves only the import-from-disk flow (its own #prog/#bar
  // progress bar was dead -- never unhidden -- and was removed).
  var uploadsEl = document.getElementById('uploads');
  function uploadRowUi(name) {
    var row = document.createElement('div');
    row.className = 'upload-row';
    var label = document.createElement('span');
    label.className = 'up-name'; label.textContent = name; label.title = name;
    var rowProg = document.createElement('div'); rowProg.className = 'progress';
    rowProg.setAttribute('role', 'progressbar');
    rowProg.setAttribute('aria-valuemin', '0');
    rowProg.setAttribute('aria-valuemax', '100');
    rowProg.setAttribute('aria-valuenow', '0');
    rowProg.setAttribute('aria-label', name + ' upload progress');
    var rowBar = document.createElement('div'); rowBar.className = 'bar';
    rowProg.appendChild(rowBar);
    var state = document.createElement('span'); state.className = 'up-state muted';
    state.setAttribute('role', 'status'); state.setAttribute('aria-live', 'polite');
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
        rowProg.setAttribute('aria-valuenow', String(Math.round(pct)));
        state.textContent = Math.round(pct) + '%';
      },
      publishing: function () {
        rowBar.style.width = '100%'; rowProg.setAttribute('aria-valuenow', '100');
        state.textContent = 'publishing…';
      },
      done: function (text) {
        rowBar.style.width = '100%'; rowProg.setAttribute('aria-valuenow', '100');
        state.textContent = text;
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
  var imageFilenames = Object.create(null);
  // id -> quarantined bool, refreshed alongside imageIds (KGV / Cisco Bulk
  // Hash reconciler, Task 5) -- so the picker can visibly block a
  // quarantined image instead of only relying on the server's own
  // set_policy() refusal, which the operator would only discover at Apply.
  var imageQuarantined = Object.create(null);
  var credOpts = [];
  // Whether the LAST /api/credentials read succeeded. Mirrors imageListOk:
  // on failure credOpts keeps its previous value and every credential
  // picker is disabled and says so, instead of rendering the whole fleet
  // as "no credential" (an empty option list matches nothing).
  var credListOk = false;
  var peerPolicy = { revision: null, quarantine_assignments: [], enforcement: {} };
  // Image and device ids are operator-chosen strings (the server accepts
  // "constructor", "toString", ...), so every id-keyed map is
  // prototype-free; a plain {} made a device called "constructor" render
  // pre-checked and its Quarantine button permanently disabled.
  var peerPolicyBusy = Object.create(null);
  function peerPolicyAssigned(deviceId) {
    return (peerPolicy.quarantine_assignments || []).indexOf(deviceId) !== -1;
  }
  function peerPolicyStatus() {
    var e = peerPolicy.enforcement || {};
    var state = ['pending', 'enforced', 'degraded', 'rpc_unavailable', 'fail_closed'].indexOf(e.state) !== -1
      ? e.state : 'pending';
    // IRIS-99: the tracker reconciler can freeze (its own degraded-pass
    // write failing, or the process dying) with peer-enforcement.json's
    // last recorded state left at "enforced" forever -- the API's `stale`
    // flag (server-computed from last_reconciled_at, since "now" belongs
    // there) is what tells this apart from a genuinely current pass. A
    // stale claim is shown as stale REGARDLESS of the frozen state: an old
    // "enforced" must not read as healthy just because nothing rewrote it.
    var stale = !!e.stale;
    var label = stale ? state + ' (stale)' : state;
    var details = 'Last tracker enforcement: ' + state + '; desired peers: ' +
      (typeof e.desired_ip_count === 'number' ? e.desired_ip_count : 0);
    details += '; last reconciled: ' +
      (e.last_reconciled_at ? fmtDate(e.last_reconciled_at) : 'never');
    if (stale) {
      details += ' (STALE -- enforcement may not reflect current policy; ' +
        'check the tracker process)';
    }
    if (e.last_error) details += '; last error: ' + e.last_error;
    if (e.conflict_count) details += '; conflicts: ' + (e.conflict_types || []).join(', ');
    var badgeClass = stale ? 'badge-fail' : (state === 'enforced' ? 'badge-ok' :
      (state === 'degraded' || state === 'fail_closed' ? 'badge-fail' : 'badge-queued'));
    return '<span class="badge ' + badgeClass +
      '" title="' + esc(details) + '">' + esc(label) + '</span>';
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
  // Live status: the devices table previously refreshed via TWO independent
  // 10s loops -- this function's own unconditional setTimeout chain
  // (formerly named scheduleDevices, which ran for the page's lifetime
  // regardless of which hash-routed view was visible) AND the hash
  // router's view-scoped startViewPoll(). Both called refreshDevices()
  // every ~10s while Devices was on screen -- redundant, unsynchronized
  // /api/devices traffic. The hash router (below) is now the SOLE owner of
  // visible-view polling, Devices included; this is the guarded function it
  // polls Devices with. Never redraw while the operator is interacting
  // with a row control (redrawing innerHTML would yank an open dropdown
  // out from under them) -- the hidden-tab suspension, immediate refresh on
  // tab return, and 10s cadence are all the router's startViewPoll now.
  function pollDevices() {
    var a = document.activeElement;
    if (a && a.closest && a.closest('#dev-rows')) return;
    return refreshDevices().catch(function () {
      devStatus.textContent = 'Device refresh unavailable; retrying…';
    });
  }
  // A pending status filter (Overview's "Needs attention" routing) must land
  // on the control before devicesPageQuery() builds the query from it --
  // filtering is server-side now (issue #112), so there is no client-side
  // "rows already in hand" left to re-filter the old way, after the fetch.
  function applyPendingDevFilter() {
    if (PENDING_DEV_FILTER === null) return;
    var sel = document.getElementById('dev-filter-status');
    if (sel) sel.value = PENDING_DEV_FILTER;
    PENDING_DEV_FILTER = null;
    devOffset = 0;
  }
  function devicesPageQuery() {
    var q = deviceFilterQuery(deviceFilterState());
    return (q ? q + '&' : '') + 'limit=' + DEV_PAGE_SIZE + '&offset=' + devOffset;
  }
  // The page came back empty while matches exist elsewhere -- the fleet
  // shrank, or a filter/refresh moved this page's devices off the end.
  // Snap back to page one rather than stranding the operator on a dead page;
  // devTotal>0 with a non-empty offset=0 page always holds (a page is at
  // least one row), so a caller retrying on `true` recurses at most once.
  function devicesPageWentEmpty(devs) {
    if (devs.length || devOffset <= 0 || devTotal <= 0) return false;
    devOffset = 0;
    return true;
  }
  async function refreshDevices() {
    var mine = ++devicesRefreshGeneration;
    if (devicesRefreshController) devicesRefreshController.abort();
    devicesRefreshController = new AbortController();
    var signal = devicesRefreshController.signal;
    applyPendingDevFilter();
    var devicesQuery = devicesPageQuery();
    // Optional job listing -- decoupled from the other four fetches below
    // via its own .then/.catch (Task 7's refreshOverview pattern); see the
    // full rationale where its result is consumed, past credOpts below.
    var jobsPromise = fetch('/api/onboard/jobs', { signal: signal }).then(function (r) {
      return r.ok ? r.json() : null;
    }).catch(function () { return null; });
    var results;
    try {
      results = await Promise.all([fetch('/api/devices?' + devicesQuery, { signal: signal }), fetch('/api/images', { signal: signal }), fetch('/api/credentials', { signal: signal }), fetch('/api/peer-policy', { signal: signal }), jobsPromise]);
    } catch (e) {
      // Superseding a refresh is expected; callers must not see an unhandled
      // AbortError. Other failures still reach their caller/status handling.
      if (e && e.name === 'AbortError') return;
      throw e;
    }
    var dr = results[0], ir = results[1], cr = results[2], pr = results[3], jobsBody = results[4];
    if (!dr.ok || mine !== devicesRefreshGeneration) return;
    var nextPolicy = pr.ok ? await pr.json() : peerPolicy;
    var dbody = await dr.json();
    if (mine !== devicesRefreshGeneration) return;
    peerPolicy = nextPolicy;
    var devs = dbody.devices || [];
    var devNow = dbody.now || Date.now() / 1000;   // server clock for last_seen freshness
    devTotal = dbody.total || 0;
    devOffset = dbody.offset || 0;
    if (devicesPageWentEmpty(devs)) return refreshDevices();
    var imgs = ir.ok ? ((await ir.json()).images || []) : [];
    imageListOk = ir.ok;
    imageIds = imgs.map(function (i) { return i.id; });
    imageFilenames = Object.create(null);
    imageQuarantined = Object.create(null);
    imgs.forEach(function (i) {
      imageFilenames[i.id] = i.filename || '';
      imageQuarantined[i.id] = !!i.quarantined;
    });
    if (cr.ok) credOpts = (await cr.json()).profiles || [];
    if (cr.ok !== credListOk) {
      credListOk = cr.ok;
      if (!credListOk) {
        devStatus.textContent = 'Credential list unavailable (' + cr.status +
          '); credential pickers are disabled until it loads.';
      }
    }
    // Fix wave 1 (reviewer finding): the job listing is OPTIONAL polish on
    // top of the device rows /api/devices already returned above -- a
    // network-level rejection on it must never take the other four fetches
    // down with it, so jobsPromise (above) resolves to null on EITHER a
    // rejection or a non-2xx response rather than rejecting the shared
    // Promise.all; the other four keep their pre-existing coupling
    // (a real failure on any of THEM still aborts this refresh via the
    // outer catch, unchanged -- out of scope for this fix). jobsBody null
    // here just leaves the previous status-cell step/elapsed suffixes in
    // place for this tick rather than blanking them; the plain
    // onboarding…/undeploying… pill underneath (from /api/devices, which
    // DID gate this refresh above) is never affected.
    if (jobsBody) {
      var jobs = jobsBody.jobs || [];
      LAST_JOBS_BY_DEVICE = bestJobForDevice(jobs);
      var liveJobIds = {};
      jobs.forEach(function (j) { liveJobIds[j.id] = true; });
      Object.keys(lastJobStep).forEach(function (id) {
        if (!liveJobIds[id]) delete lastJobStep[id];
      });
    }
    if (mine !== devicesRefreshGeneration) return;
    syncCredSelected();
    LAST_DEVICES = devs;
    LAST_DEV_NOW = devNow;
    syncDeviceFilterOptions();
    renderDevices(devs, devNow, devTotal);
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

  // The four filter fields living inside the <details id="more-filters">
  // disclosure panel (density pass, Task 8) -- Search/Agent
  // install/Status stay above the fold and are not counted here.
  var MORE_FILTER_IDS = ['dev-filter-management-type', 'dev-filter-cred',
                          'dev-filter-telemetry', 'dev-filter-peer'];
  function updateMoreFiltersSummary() {
    // Magnetic Filter bar > Anatomy fixes the overflow button's format as
    // "<icon> + Filters", so the label lives in its own span and the icon
    // beside it survives the write -- textContent on the <summary> itself
    // would delete the svg. The applied-filter count stays appended: the
    // panel is closed most of the time and the operator has to be able to
    // see that something inside it is narrowing the table.
    var el = document.getElementById('more-filters-label');
    if (!el) return;
    var n = MORE_FILTER_IDS.filter(function (id) {
      var f = document.getElementById(id);
      return f && f.value !== '';
    }).length;
    el.textContent = 'Filters' + (n ? ' (' + n + ')' : '');
  }
  // Reset is "displayed when at least one filter has been selected or a
  // search term has been entered" (Magnetic Filter bar > Anatomy) -- it used
  // to sit there permanently, offering to clear nothing.
  var ALL_FILTER_IDS = ['dev-filter-q', 'dev-filter-platform', 'dev-filter-status']
    .concat(MORE_FILTER_IDS);
  function updateFilterBarState() {
    var reset = document.getElementById('dev-filter-clear');
    if (!reset) return;
    reset.hidden = !ALL_FILTER_IDS.some(function (id) {
      var f = document.getElementById(id);
      return f && f.value !== '';
    });
  }
  function renderDevices(devs, devNow, total) {
    var filters = deviceFilterState();
    // devs is already the server's own page for this exact filter (issue
    // #112 prerequisite 1 -- gui_server.py's _row_matches_extra_filters
    // mirrors deviceMatchesFilters condition-for-condition), so this is a
    // defensive RE-check, not the primary filter any more: it can only ever
    // narrow an already-matching page, never explain away a row the
    // server's own `total` already counted as a match.
    devs = devs.filter(function (d) { return deviceMatchesFilters(d, filters, devNow); });
    document.getElementById('dev-rows').innerHTML = devs.length ? devs.map(function (d) {
      var rowIds = rowAssignedIds(d);
      var assignLabel = rowIds.length ? (rowIds.length + ' image(s)') : '— assign —';
      var credSel = credListOk
        ? ['<option value="">— no credential —</option>'].concat(credOpts.map(function (c) {
            return '<option value="' + esc(c.id) + '"' + (c.id === d.credential_profile_id ? ' selected' : '') + '>' + esc(c.id) + '</option>';
          })).join('')
        // profile list unavailable: show what the inventory says, read-only
        : '<option value="' + esc(d.credential_profile_id || '') + '" selected>' +
          (d.credential_profile_id ? esc(d.credential_profile_id) : '— no credential —') + '</option>';
      var credAttrs = credListOk ? '' :
        ' disabled title="Credential list unavailable; showing the assignment as recorded in the inventory"';
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
        '<td><input type="checkbox" class="mark" data-id="' + esc(d.device_id) + '" aria-label="Select ' + esc(d.device_id) + '"' +
        (SELECTED[d.device_id] ? ' checked' : '') + '></td>' +
        '<td class="dev-id">' + esc(d.device_id) + '</td><td class="machine">' + dash(d.device_ip) + '</td>' +
        '<td class="machine">' + dash(d.model || d.heartbeat_model) + '</td>' +
        '<td>' + esc(managementTypeLabel) + '</td>' +
        '<td><select class="platform">' + platSel + '</select></td>' +
        '<td><select class="cred"' + credAttrs + '>' + credSel + '</select></td>' +
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
    }).join('') : '<tr><td colspan="11" class="muted">' +
      (total ? 'No devices match the current filters.' : 'No devices yet.') + '</td></tr>';
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
    // The header checkbox can only ever speak for the page in the DOM right
    // now (issue #112 prerequisite 2 -- a paged table cannot let "select
    // all" silently mean "select everything" when only a page is loaded):
    // checked when every rendered row is in SELECTED, indeterminate when
    // some but not all are, unchecked otherwise. #sel-scope-all (wired in
    // updateSelBar) is the one control that means "every matching device".
    var markAll = document.getElementById('mark-all');
    var selectedOnPage = devs.filter(function (d) { return !!SELECTED[d.device_id]; }).length;
    markAll.checked = devs.length > 0 && selectedOnPage === devs.length;
    markAll.indeterminate = selectedOnPage > 0 && selectedOnPage < devs.length;
    // The filter bar's Total (Magnetic Filter bar > Anatomy, "<number> +
    // results"). One readout, in the bar the filters live in: the page used
    // to carry two, "N devices" up in the table-level toolbar and "showing X
    // of N" down in the filter row, which said the same thing twice in two
    // different vocabularies and left the reader checking both.
    // Plural agreement follows `total` in BOTH branches: in the "X of N"
    // form the noun belongs to N, so filtering twelve devices down to one
    // reads "1 of 12 results", not "1 of 12 result". Agreeing with the
    // matched count instead put a grammar error on screen for the single
    // most common thing the search box does.
    document.getElementById('dev-count').textContent =
      (devs.length === total ? String(total) : devs.length + ' of ' + total) +
      ' result' + (total === 1 ? '' : 's');
    updateDevPager(total);
    updateMoreFiltersSummary();
    updateFilterBarState();
    updateSelBar();
  }
  // Prev/Next paging over the CURRENT filter's match set (issue #112 step
  // 3 -- the table only pages once prerequisites 1 and 2 above hold). Hidden
  // entirely when everything fits on one page, so an unpaged fleet reads
  // exactly as it always did.
  function updateDevPager(total) {
    var pager = document.getElementById('dev-pager');
    if (!pager) return;
    pager.hidden = total <= DEV_PAGE_SIZE;
    var pages = Math.max(1, Math.ceil(total / DEV_PAGE_SIZE));
    var page = Math.floor(devOffset / DEV_PAGE_SIZE) + 1;
    var pos = document.getElementById('dev-page-pos');
    if (pos) pos.textContent = 'Page ' + page + ' of ' + pages;
    var prev = document.getElementById('dev-page-prev');
    if (prev) prev.disabled = devOffset <= 0;
    var next = document.getElementById('dev-page-next');
    if (next) next.disabled = devOffset + DEV_PAGE_SIZE >= total;
  }
  // ---- Device deployment details (per-row ⓘ) ----
  // The panel lives OUTSIDE #dev-rows so the 10s table re-render never
  // touches it. deployInfoDev guards against a slow fetch for one device
  // painting over the panel after another row was opened.
  var deployInfoDev = null;
  var deployInfoOpener = null;
  var DEPLOY_STATE_BADGE = { active: 'badge-ok', removed: 'badge-queued',
                             superseded: 'badge-cancelled', 'needs-reconcile': 'badge-fail' };
  function deployRecordRows(rec, total) {
    var res = rec.resolved || {};
    var ts = rec.timestamps || {};
    var pf = rec.preflight || {};
    var managementType = res.management_type || '';
    // xr-host carries none of the four addressing rows below -- the
    // appmgr container runs on the router's own network stack -- so they
    // are dropped from the table entirely rather than shown as dashes,
    // which would read as "unknown" instead of "not applicable".
    var xrHost = managementType === 'xr-host';
    var managementTypeLabel = xrHost ? 'XR host' : managementType;
    var mgmt = managementType.indexOf('router-') === 0
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
      ['Record', '<span class="machine">' + esc(rec.record_id || '') + '</span>' +
        ' <span class="muted">(' + esc(total) + ' stored for this device)</span>'],
      ['Planned', '<span class="machine">' + esc(fmtDate(ts.planned_at) || '—') + '</span>'],
      ['Finished', '<span class="machine">' + esc(fmtDate(ts.finished_at) || '—') + '</span>'],
      ['Preflight', esc(pf.status || '—')],
      ['Management type', esc(managementTypeLabel || '—')]
    ];
    if (!xrHost) {
      pairs.push(
        ['Management VLAN / VPG', esc(mgmt || '—')],
        ['SVI', '<span class="machine">' + esc(svi || '—') + '</span>'],
        ['App IP', '<span class="machine">' + esc(app || '—') + '</span>'],
        ['NAT interface', '<span class="machine">' + esc(res.nat_interface || '—') + '</span>']
      );
    }
    pairs.push(
      ['Swarm port', '<span class="machine">' + esc(res.swarm_port || '—') + '</span>'],
      ['Model', esc(res.model || '—')],
      ['Agent install', esc(res.platform || '—')],
      ['Device identity', '<span class="machine">' + esc(res.device_identity || '—') + '</span>']
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
      return '<tr><td class="machine">' + imageLabel(iid) + '</td><td>' + esc(state) + '</td></tr>';
    }).join('');
    if (perImage && d.stage_error) {
      rows += '<tr><td class="muted">Last reported error</td><td>' +
        esc(d.stage_error) + '</td></tr>';
    }
    return rows;
  }
  // Per-device instance of the Staging Boundary (Task 7's
  // stagingBoundaryHTML, spec: "device and image detail contexts in Task
  // 8" -- reused verbatim, never re-implemented). Uses the same six-step,
  // same-deviceStatus()-keys reasoning Overview's own fleet-wide instance
  // used before it was removed (Wave C, operator decision) -- "unknown
  // stays na, never a guessed done" -- but scoped to this one device's
  // assigned set, and derives ONLY from data
  // the drawer already has in hand when it opens: the device row `d`
  // (already fetched by refreshDevices) and the imageQuarantined map that
  // same fetch already populated. No per-image hash_verification state
  // reaches this view (only the quarantined flag does), so "Source
  // checked" can say FAILED for a quarantined assigned image but never
  // claims a "done" it cannot back up; "Verified" admits it has no
  // on-device signal here either, same as it never did.
  function deviceBoundarySteps(d, devNow) {
    var ids = rowAssignedIds(d);
    if (!ids.length) return ['na', 'na', 'upcoming', 'na', 'na', 'na'];
    var catalogued = 'done';
    var assigned = 'done';

    var quarantined = ids.filter(function (iid) { return imageQuarantined[iid]; });
    var sourceChecked = quarantined.length
      ? { state: 'failed', pillHtml: levelPillHTML('negative',
          quarantined.length + (quarantined.length === 1 ? ' image quarantined' : ' images quarantined')) }
      : 'na';

    var st = deviceStatus(d, devNow);
    var transferring, staged;
    if (st.key === 'placement-failed') {
      transferring = { state: 'failed', pillHtml: levelPillHTML('negative', 'placement failed') };
      staged = 'na';
    } else if (st.key === 'image-failed') {
      var ratio = imageFailedRatio(d);
      transferring = { state: 'failed', pillHtml: levelPillHTML(ratio >= 0.5 ? 'severe' : 'warning', st.label) };
      staged = 'na';
    } else if (st.key === 'deployed') {
      transferring = 'done'; staged = 'done';
    } else if (st.key === 'copying' || st.key === 'staging') {
      transferring = 'current'; staged = 'upcoming';
    } else {
      transferring = 'na'; staged = 'na';
    }
    var verified = 'na';
    return [catalogued, sourceChecked, assigned, transferring, verified, staged];
  }
  async function openDeployInfo(id) {
    deployInfoDev = id;
    deployInfoOpener = document.activeElement;
    var note = document.getElementById('di-note');
    document.getElementById('di-dev').textContent = id;
    document.getElementById('di-rows').innerHTML = '';
    document.getElementById('di-log-rows').innerHTML = '';
    var d = LAST_DEVICES.filter(function (x) { return x.device_id === id; })[0] || {};
    document.getElementById('di-img-rows').innerHTML = deployImageRows(d);
    document.getElementById('di-boundary').innerHTML =
      stagingBoundaryHTML(deviceBoundarySteps(d, LAST_DEV_NOW));
    var lt = document.getElementById('di-log-text');
    lt.hidden = true; lt.textContent = '';
    note.textContent = 'Loading…';
    document.getElementById('deploy-info-panel').hidden = false;
    document.getElementById('di-close').focus();
    var r = null;
    try { r = await fetch('/api/devices/' + encodeURIComponent(id) + '/deployment'); } catch (e) { }
    if (deployInfoDev !== id) return;      // another row was opened meanwhile
    if (!r) {
      note.textContent = 'Deployment details unavailable.';
    } else if (r.status === 404) {
      note.textContent = 'Deployment records are unavailable on this server.';
    } else if (!r.ok) {
      note.textContent = 'Deployment details unavailable (' + r.status + ').';
    } else {
      var body = await r.json();
      if (deployInfoDev !== id) return;
      if (!body.record) {
        note.textContent = 'No deployment record — onboarded before records ' +
          'existed, or added manually; adopt or re-onboard to create one.';
      } else {
        note.textContent = '';
        document.getElementById('di-rows').innerHTML =
          deployRecordRows(body.record, body.total || 0);
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
      return '<tr data-file="' + esc(l.file) + '"><td class="machine">' + esc(fmtDate(l.finished_at)) +
        prev + '</td><td>' + esc(l.action || '') + '</td><td>' + deployLogResult(l) +
        '</td><td class="machine">' + esc(fmtSize(l.size)) + '</td>' +
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
    if (deployInfoOpener) { deployInfoOpener.focus(); deployInfoOpener = null; }
  }
  document.getElementById('di-close').addEventListener('click', closeDeployInfo);
  // Escape closes it, the same as the deployment-log drawer: a drawer that
  // covers part of the table needs a way out that is not aiming for the ✕.
  document.addEventListener('keydown', function (e) {
    var panel = document.getElementById('deploy-info-panel');
    if (e.key === 'Escape' && panel && !panel.hidden) closeDeployInfo();
  });
  // No trapDialogFocus here (Task 6, fix wave): this drawer is non-modal --
  // no backdrop, deployInfoDev's own guard above expects a second row's
  // drawer to open while the first is still loading -- so Tab must be free
  // to leave it for the rest of the page. Focus still moves in on open and
  // is restored to the opener above.
  // "Forget host key" (issue #84): a re-imaged/replaced device presents a
  // new SSH host key and accept-new mode then refuses every session with a
  // changed-key error. This clears the stale entry from the persistent
  // known_hosts so the NEXT session re-verifies and re-pins the new key --
  // it does not disable verification. State-changing, so it goes through
  // jpost (session + CSRF) and is audited server-side.
  document.getElementById('di-forget-host-key').addEventListener('click', async function () {
    var id = deployInfoDev;
    if (!id) return;
    if (!confirm('Forget the recorded SSH host key for ' + id + '?\n\n' +
                 'Only do this if the device was legitimately re-imaged or ' +
                 'replaced. The next session will trust and record whatever ' +
                 'key that device presents.')) return;
    var status = document.getElementById('di-forget-host-key-status');
    status.textContent = 'Forgetting…';
    var r = await jpost('/api/devices/' + encodeURIComponent(id) + '/forget-host-key', {});
    if (deployInfoDev !== id) return;   // the drawer moved to another device meanwhile
    if (r.ok) {
      var body = await r.json();
      status.textContent = 'Host key forgotten for ' + (body.peer || id) +
        '. The next session will re-pin its new key.';
    } else {
      var err = null;
      try { err = (await r.json()).error; } catch (e) { }
      status.textContent = 'Forget host key failed: ' + (err || r.status);
    }
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
      // "idle": the server closed a stream with no progress for its idle
      // budget; the job itself may still be running -- reopen to continue.
      append(e.data === 'idle'
        ? '— stream closed: no progress for a while; the job may still be running, reopen the log to continue —'
        : '— ' + e.data + ' —'); flush();
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
  // The header checkbox can only ever mean "every row on THIS page" -- once
  // the table pages (issue #112 step 3), a page is a fraction of what the
  // filter matches, and silently treating "select all" as "select the
  // fleet" is exactly the ambiguity prerequisite 2 rules out. Selecting
  // every device the filter matches, not just what is loaded, is
  // selectAllMatchingDevices() below, offered explicitly via #sel-scope-all.
  document.getElementById('mark-all').addEventListener('change', function (e) {
    document.querySelectorAll('#dev-rows .mark').forEach(function (cb) {
      var id = cb.getAttribute('data-id');
      if (e.target.checked) SELECTED[id] = true; else delete SELECTED[id];
      cb.checked = e.target.checked;
    });
    updateSelBar();
  });
  // Bulk bar's "Select all N matching devices" (spec §5 scope copy, below in
  // updateSelBar): walks every page of the CURRENT filter server-side and
  // adds every id it returns to SELECTED. This is a REAL fetch, not a
  // shortcut into the header checkbox -- the header checkbox only ever sees
  // the page in the DOM, so replaying its change handler here would have
  // silently selected "this page" while the button claims "every matching
  // device" (the exact defect issue #112 flags).
  document.getElementById('sel-scope-all').addEventListener('click', function () {
    selectAllMatchingDevices();
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
    // The Settings/Monitoring flyout triggers live directly in the rail,
    // not inside a .menu-wrap (their panel is positioned off .nav-rail
    // itself, not off the trigger) -- reset their aria-expanded here too,
    // or a flyout closed by an outside click / Escape leaves a stale
    // aria-expanded="true" on an already-collapsed trigger.
    var settingsTrigger = document.getElementById('nav-settings');
    var monitoringTrigger = document.getElementById('nav-monitoring');
    if (settingsTrigger) settingsTrigger.setAttribute('aria-expanded', 'false');
    if (monitoringTrigger) monitoringTrigger.setAttribute('aria-expanded', 'false');
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
  // Bulk-bar action cap (Magnetic Table > Bulk action bar allows up to four
  // actions): Adopt/Quarantine/Release/Set-credential/Delete live inside this
  // overflow dropdown -- same generic menu machinery as every other menu-wrap
  // on the page, no action-specific wiring here.
  wireMenu('more-menu-btn', 'more-pop');
  // ---- bulk-action modals -------------------------------------------------
  // Onboard / Undeploy / Set credential used to be .menu popovers hanging off
  // caret buttons in the bulk bar, each carrying form controls and its own
  // nested submit button. Magnetic Dropdown rules that shape out -- "Selecting
  // an item from the menu starts an action without requiring the use of
  // another button to submit or apply" -- and names the replacement in the
  // same breath: "provide features in bulk action bar that open modals".
  // Magnetic Modal > Usage agrees ("Use modals for simple tasks that inform,
  // confirm, or complete a simple action"). Every control id inside moved
  // unchanged, so telemetryFlags(), startBatch() and the credential handler
  // read exactly what they read before.
  var modalOpener = null;
  function openModal(id) {
    var overlay = document.getElementById(id);
    if (!overlay) return;
    // Remember what to hand focus back to on close. An opener that lives
    // INSIDE a .menu popover -- "Set credential…" in the bulk bar's overflow
    // -- carries .menu-close, so wireMenu's own panel handler runs closeMenus()
    // a moment after this line and hides it. focus() on a display:none element
    // is a spec'd no-op, so restoring to it would silently drop the operator
    // at the top of the document instead of back in the bulk bar. Fall back to
    // the popover's trigger, which stays on screen.
    var opener = document.activeElement;
    var menu = opener && opener.closest ? opener.closest('.menu') : null;
    if (menu) {
      var wrap = menu.closest('.menu-wrap');
      opener = (wrap && wrap.querySelector('[aria-expanded]')) || opener;
    }
    modalOpener = opener;
    overlay.hidden = false;
    var first = overlay.querySelector('.modal-body input, .modal-body select') ||
                overlay.querySelector('.modal-foot .btn');
    if (first) first.focus();
  }
  function closeModal(id) {
    var overlay = document.getElementById(id);
    if (!overlay || overlay.hidden) return;
    overlay.hidden = true;
    // Return focus to whatever opened it -- if that button has since been
    // hidden with the bulk bar (the batch cleared the selection), focus()
    // on it is simply a no-op and the browser falls back to the document.
    if (modalOpener && modalOpener.focus) modalOpener.focus();
    modalOpener = null;
  }
  function wireModal(id, closerIds) {
    var overlay = document.getElementById(id);
    if (!overlay) return;
    closerIds.forEach(function (cid) {
      var el = document.getElementById(cid);
      if (el) el.addEventListener('click', function () { closeModal(id); });
    });
    // Deliberately NO backdrop click-to-close. The head's ✕, the foot's Cancel
    // and Escape are the ways out, which is what Magnetic Modal asks for ("Do
    // include a button to close the modal in all cases") -- and it is what the
    // image picker below, this page's pre-existing modal, already does.
    // A bare `e.target === overlay` closer misfires twice: the second click of
    // a double-click on the opener lands on the backdrop that the first click
    // just raised over it, so the dialog flashes open and shut and the button
    // reads as dead; and a click is dispatched at the common ancestor of its
    // mousedown and mouseup, so drag-selecting the undeploy modal's force
    // help text and releasing past the dialog edge targets the overlay and
    // closes it mid-read.
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && !overlay.hidden) closeModal(id);
    });
    trapDialogFocus(overlay);
  }
  var BULK_MODALS = ['onboard-modal', 'undeploy-modal', 'cred-modal'];
  wireModal('onboard-modal', ['onboard-cancel', 'onboard-modal-x']);
  wireModal('undeploy-modal', ['undeploy-cancel', 'undeploy-modal-x']);
  wireModal('cred-modal', ['cred-modal-cancel', 'cred-modal-x']);
  document.getElementById('onboard-selected').addEventListener('click', function () {
    openModal('onboard-modal');
  });
  document.getElementById('undeploy-selected').addEventListener('click', function () {
    openModal('undeploy-modal');
  });
  document.getElementById('set-cred-selected').addEventListener('click', function () {
    if (!credListOk) {
      devStatus.textContent = 'Credential list unavailable; not opening the picker. ' +
        'Retry once the profile list loads.';
      return;
    }
    var msg = document.getElementById('cred-modal-msg');
    if (msg) msg.textContent = '';
    syncCredSelected();
    openModal('cred-modal');
  });
  wireMenu('help-btn', 'help-pop');
  wireMenu('status-legend-btn', 'status-legend-pop');
  // Settings/Monitoring flyouts (Wave D fix 2, operator: "does not
  // disappear when I click the site"): Wave B made these floating panels
  // but left their visibility tied to the active route, so a flyout stayed
  // open the entire time the operator was anywhere on Settings/Monitoring,
  // never closing on an outside click the way every other .menu popover
  // does. The rail item is both a real navigation link (href, unchanged)
  // AND now this popover's trigger -- same wireMenu machinery as every
  // other menu-wrap pair: open on trigger click, close on outside click or
  // Escape (already wired above, generically, for every open .menu), or on
  // choosing a sub-item (each carries .menu-close, so wireMenu's own panel
  // click handler closes it the instant a destination is picked).
  wireMenu('nav-settings', 'settings-submenu');
  wireMenu('nav-monitoring', 'monitoring-submenu');
  // Status column legend (density pass, Task 8): one row per
  // DEVICE_STATUS_OPTIONS entry (the SAME 12-level Magnetic mapping the
  // Status filter and the cell itself already derive from -- STATUS_LEVELS,
  // Task 4), so the legend can never list a level a real pill cannot show.
  // image-failed's own ratio-driven warning/severe split is per-row, not
  // meaningful for a static legend, so it renders at its base 'warning'
  // level here.
  (function () {
    var pop = document.getElementById('status-legend-pop');
    if (!pop) return;
    pop.innerHTML = '<div class="legend-title">Status legend</div>' +
      DEVICE_STATUS_OPTIONS.map(function (o) {
        return '<div class="legend-row">' +
          levelPillHTML(STATUS_LEVELS[o[0]] || 'inactive', o[1]) + '</div>';
      }).join('');
  })();
  function updateSelBar() {
    // n is the REAL selection size -- every device_id in SELECTED, which
    // survives paging, filtering and a poll's re-render (issue #112
    // prerequisite 2). m is the server's own total for the CURRENT filter,
    // never the rendered row count: under paging those two only agree once
    // the filter fits on one page, and using the DOM count here is exactly
    // how "select all" used to come to silently mean "select this page".
    var n = Object.keys(SELECTED).length;
    var m = devTotal;
    document.getElementById('sel-bar').hidden = n === 0;
    document.getElementById('sel-count').textContent = n + ' selected';
    // Scope copy (spec §5, revised for paging): names whether the selection
    // IS every device the filter matches or only part of it, and -- when
    // it's only part -- offers a one-click way to the rest. Unlike before
    // paging existed, that click can no longer be a shortcut into the
    // header checkbox (#mark-all only ever reaches the page in the DOM) --
    // it runs selectAllMatchingDevices(), a real walk of every page.
    var scopeText = document.getElementById('sel-scope-text');
    var scopeAll = document.getElementById('sel-scope-all');
    var allSelected = n > 0 && n === m;
    scopeText.hidden = !allSelected;
    if (allSelected) scopeText.textContent = '· All ' + m + ' matching devices selected';
    scopeAll.hidden = allSelected || n === 0 || m <= n;
    if (!scopeAll.hidden) scopeAll.textContent = '· Select all ' + m + ' matching devices';
    // The count lives in the bar's own indicator (Magnetic Table > Bulk
    // action bar: "An indicator displays the number of selected rows"), so
    // the buttons stop restating it. They used to read "Start onboard (3)"
    // and "Assign images to 3 devices…", which re-measured and reflowed the
    // whole bar on every checkbox click -- Magnetic Button > Wrapping and
    // truncation wants button text brief and settled. Each modal repeats the
    // count in its own title instead, where it is the thing being confirmed.
    ['onboard', 'undeploy', 'cred'].forEach(function (k) {
      var el = document.getElementById(k + '-modal-count');
      if (el) el.textContent = n + ' selected';
    });
    document.querySelectorAll('#dev-rows tr').forEach(function (tr) {
      var cb = tr.querySelector('.mark');
      tr.classList.toggle('sel', !!(cb && cb.checked));
    });
    // An empty selection closes the selection-scoped popovers — but never
    // the header help popover, or the Status legend (density pass, Task 8):
    // the 10s devices poll re-renders the (empty) table and lands here with
    // n === 0, and yanking an open informational panel out from under the
    // operator reads as a broken control.
    if (n === 0 && openMenuPanel && openMenuPanel.id !== 'help-pop' &&
        openMenuPanel.id !== 'status-legend-pop') closeMenus();
    // The bulk modals are scoped to the selection exactly the way those
    // popovers were: with the last row deselected they are asking the
    // operator to confirm an action on nothing, so they close with the bar.
    if (n === 0) BULK_MODALS.forEach(closeModal);
  }
  document.getElementById('dev-rows').addEventListener('change', function (e) {
    if (!e.target.classList.contains('mark')) return;
    var id = e.target.getAttribute('data-id');
    if (e.target.checked) SELECTED[id] = true; else delete SELECTED[id];
    updateSelBar();
  });
  document.getElementById('sel-clear').addEventListener('click', function () {
    SELECTED = Object.create(null);
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
      backgroundPoll = true;   // timer-driven, not operator activity
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
        ? '<div class="job-action-undeploy">undeploy</div>' : '';
      return '<tr data-job="' + esc(j.id) + '" data-dev="' + esc(j.device_id) + '"' +
        ' data-state="' + esc(j.state) + '" data-action="' + esc(j.action || 'onboard') + '">' +
        '<td class="machine">' + esc(j.device_id) + act + '</td>' +
        '<td>' + jobBadge(j.state) + '</td>' +
        '<td class="muted">' + queuePos + '</td>' +
        '<td class="out machine">' + esc(j.last_line || '') + '</td>' +
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
          ? '\n\nFORCE is on. For any device with no deployment record this removes the IRIS agent footprint only — EEM applets, Guest Shell and the IRIS guest-share files. The VirtualPortGroup and NAT are NOT removed, because without a record there is no proof IRIS created them; clean those up yourself if IRIS did. On an IOS-XR device, force removes the same IRIS-named footprint a normal undeploy would — the appmgr application iris, its iris-xr package source, the RPM, iris-work/, and the IRIS sidecar files at harddisk: root — but a staged image file there is never removed by IRIS teardown, and the agent deletes an adopted file only when the catalog republishes new content under that same image id — never otherwise.'
          : '\n\nThis removes the device agent (Guest Shell or IOx app) and only record-owned resources. Inband deployments preserve their existing network; router NAT preserves a pre-existing outside marking.') +
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
  // The bulk-bar buttons open their modal (wired above); the modal's own
  // primary is what actually starts the batch.
  document.getElementById('onboard-confirm').addEventListener('click', function () {
    closeModal('onboard-modal');
    startBatch('onboard');
  });
  document.getElementById('undeploy-confirm').addEventListener('click', function () {
    closeModal('undeploy-modal');
    startBatch('undeploy');
  });

  // ---- bulk row actions (adopt / delete / assign credential) ----
  // Every bulk action reads the SELECTED id set, never the checked DOM rows
  // (issue #112 prerequisite 2): '#dev-rows .mark:checked' only ever holds
  // the page currently rendered, so once the table pages that scrape would
  // silently mean "this page" instead of whatever the operator actually
  // checked across however many pages they visited.
  function selectedIds() {
    return Object.keys(SELECTED);
  }
  // The one way to select every device the CURRENT FILTER matches, not just
  // what happens to be loaded (issue #112 prerequisite 2's other half): a
  // real walk of every server page for the active filter, adding each id it
  // returns to SELECTED. Wired to #sel-scope-all's click, above.
  var selectAllMatchingBusy = false;
  async function selectAllMatchingDevices() {
    if (selectAllMatchingBusy) return;
    selectAllMatchingBusy = true;
    var scopeAll = document.getElementById('sel-scope-all');
    var savedLabel = scopeAll.textContent;
    scopeAll.disabled = true;
    scopeAll.textContent = '· Selecting…';
    try {
      var base = deviceFilterQuery(deviceFilterState());
      // The server's own page cap (gui_server.MAX_PAGE_LIMIT) -- the widest
      // page it will ever hand back, so this walks the fewest requests a
      // filtered set of any size can be collected in.
      var batch = 1000;
      var offset = 0, total = null;
      while (total === null || offset < total) {
        var qs = (base ? base + '&' : '') + 'limit=' + batch + '&offset=' + offset;
        var r;
        try { r = await fetch('/api/devices?' + qs); } catch (e) { break; }
        if (!r.ok) break;
        var body = await r.json();
        total = typeof body.total === 'number' ? body.total : 0;
        var got = body.devices || [];
        got.forEach(function (d) { SELECTED[d.device_id] = true; });
        if (!got.length) break;   // never spin forever on an unexpected reply
        offset += got.length;
      }
    } finally {
      selectAllMatchingBusy = false;
      scopeAll.disabled = false;
      scopeAll.textContent = savedLabel;
      renderDevices(LAST_DEVICES, LAST_DEV_NOW, devTotal);
    }
  }
  // Every selected-action shares one lock. Without it a delete could fire while
  // an onboard batch is still starting, removing inventory out from under a
  // running job — onboard/undeploy previously guarded only each other.
  // The controls that actually FIRE a bulk action and claim the lock. Onboard
  // and undeploy now fire from inside their modal, so the ids here are the
  // modal primaries; the bulk bar's own Onboard…/Undeploy… buttons only open
  // those modals and are listed as openers below.
  var BULK_BTNS = ['onboard-confirm', 'undeploy-confirm', 'adopt-selected',
                   'delete-selected', 'apply-cred-selected',
                   'assign-images-selected',
                   'quarantine-selected', 'release-selected'];
  // Openers claim no lock of their own -- there is nothing to claim until the
  // modal's primary is pressed -- but they must not hand out a second modal
  // while a batch is still starting.
  var BULK_OPENERS = ['onboard-selected', 'undeploy-selected', 'set-cred-selected'];
  var bulkBusy = false;
  function setBulkBusy(busy) {
    bulkBusy = busy;
    BULK_BTNS.concat(BULK_OPENERS).forEach(function (id) {
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
    // The resting placeholder is disabled so an untouched Apply is a no-op;
    // clearing is an explicit, distinct choice (CRED_CLEAR) that Apply then
    // confirms -- never the value the modal happens to open on.
    sel.innerHTML = '<option value="" disabled>— choose a credential profile —</option>' +
      '<option value="' + CRED_CLEAR + '">— no credential (clear the assignment) —</option>' +
      credOpts.map(function (c) {
        return '<option value="' + esc(c.id) + '">' + esc(c.id) + '</option>';
      }).join('');
    sel.value = keep;
    if (sel.value !== keep) sel.selectedIndex = 0;
  }
  // Sentinel for the bulk picker's explicit "clear" choice; posted as "".
  var CRED_CLEAR = '__none';
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
  var imgPickerOpener = null;
  function openImagePicker(currentIds, onApply) {
    var overlay = document.getElementById('img-picker');
    imgPickerOpener = document.activeElement;
    var rows = document.getElementById('img-picker-rows');
    var counter = document.getElementById('img-picker-count');
    // Reset any note left over from a previous open (the bulk caller below
    // sets one back on right after this returns, when it applies).
    var note = document.getElementById('img-picker-note');
    if (note) note.hidden = true;
    var checkedSet = Object.create(null);   // image ids are operator-chosen
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
    document.getElementById('img-picker-cancel').focus();
  }
  function closeImagePicker() {
    document.getElementById('img-picker').hidden = true;
    imgPickerOnApply = null;
    if (imgPickerOpener) { imgPickerOpener.focus(); imgPickerOpener = null; }
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
  trapDialogFocus(document.getElementById('img-picker'));
  function delWarning(ids) {
    // Removing inventory does NOT undeploy: an onboarded device keeps running
    // its agent with no Console inventory entry for it, so say so before it
    // happens.
    return 'Delete ' + ids.length + ' device(s) from the inventory?\n\n' +
      ids.join(', ') + '\n\nThis removes the device from the Console inventory only — it does NOT ' +
      'undeploy. An onboarded device keeps its agent and staged image with no ' +
      'inventory entry left to manage it. Undeploy first if that is what you want.' +
      '\n\nAny deployment record is abandoned: it is kept as the account of what ' +
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
    var failed = [], failedIds = [];
    try {
      await Promise.all(ids.map(async function (id) {
        try {
          var r = await fn(id);
          if (!r.ok) {
            var reason = '';
            try { reason = (await r.json()).error || ''; } catch (e2) { }
            failed.push(reason ? id + ' (' + reason + ')' : id);
            failedIds.push(id);
          }
        } catch (e) { failed.push(id); failedIds.push(id); }
      }));
    } finally {
      if (opts.ownsBulkLock !== false) setBulkBusy(false);
    }
    devStatus.textContent = label + ' ' + (ids.length - failed.length) + '/' +
      ids.length + ' device(s)' + (failed.length ? '; failed: ' + failed.join(', ') : '');
    refreshDevices();
    // Bare ids that did NOT succeed -- callers that need to know which of
    // `ids` actually went through (delete-selected, so a removed device
    // does not linger in SELECTED forever) diff `ids` against this.
    return failedIds;
  }
  // issue #125: the bulk-endpoint counterpart of forSelected -- ONE POST
  // carrying every selected id, instead of one request per id. Reports the
  // same status-line shape forSelected does (label N/M device(s); failed:
  // id (reason), ...), from the single response's {applied, failed} rather
  // than from N settled promises. Always releases the shared bulk lock
  // (unlike forSelected, nothing here shares it with a non-selected-action
  // caller).
  async function bulkApply(label, ids, fn) {
    var failedIds = [];
    try {
      var r = await fn(ids);
      var body = null;
      try { body = await r.json(); } catch (e) { }
      if (r.ok && body) {
        var failedMap = body.failed || {};
        failedIds = Object.keys(failedMap);
        var reasons = failedIds.map(function (id) {
          return id + ' (' + failedMap[id] + ')';
        });
        devStatus.textContent = label + ' ' + body.applied + '/' + ids.length +
          ' device(s)' + (reasons.length ? '; failed: ' + reasons.join(', ') : '');
      } else {
        // The request itself failed (bad input, session/CSRF, network) --
        // nothing in this batch applied, so every id counts as failed.
        failedIds = ids.slice();
        var reason = (body && body.error) || '';
        devStatus.textContent = label + ' failed for all ' + ids.length +
          ' device(s)' + (reason ? ': ' + reason : '');
      }
    } catch (e) {
      failedIds = ids.slice();
      devStatus.textContent = label + ' failed for all ' + ids.length +
        ' device(s): network error';
    } finally {
      setBulkBusy(false);
    }
    refreshDevices();
    return failedIds;
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
    var failedIds = await forSelected('Deleted', ids, function (id) {
      return fetch('/api/devices/' + encodeURIComponent(id),
                   { method: 'DELETE', headers: csrfHdr() });
    });
    // A deleted device cannot stay "selected" forever -- SELECTED is keyed
    // by device_id and outlives paging/filtering/refresh (issue #112
    // prerequisite 2), so nothing else would ever clear it. Ids that failed
    // to delete stay selected; the operator can see them in the status line
    // and retry.
    ids.forEach(function (id) {
      if (failedIds.indexOf(id) === -1) delete SELECTED[id];
    });
    updateSelBar();
  });
  // ---- Devices: filter wiring ----
  // The Status options are generated from the same list the cell derives from,
  // so a state can never be renderable but unfilterable.
  (function () {
    var sel = document.getElementById('dev-filter-status');
    if (!sel) return;
    // '__attention' is appended here, NOT added to DEVICE_STATUS_OPTIONS
    // itself -- that array is specifically "every key deviceStatus() can
    // produce" (test_every_status_the_cell_can_show_is_filterable enforces
    // it), and '__attention' is a rollup over several of those keys, not a
    // producible status of its own.
    // Alphabetical by LABEL, which is what an operator scans. The array itself
    // stays in derivation order next to deviceStatus() (that order documents
    // the precedence, and the status legend reads it), so this sorts a COPY.
    // "Status: any" stays pinned first and the '__attention' rollup stays
    // pinned last: neither is a status, so neither belongs in the alphabet.
    sel.innerHTML = '<option value="">Status: any</option>' +
      DEVICE_STATUS_OPTIONS.slice().sort(function (a, b) {
        return a[1].localeCompare(b[1]);
      }).map(function (o) {
        return '<option value="' + esc(o[0]) + '">' + esc(o[1]) + '</option>';
      }).join('') +
      '<option value="__attention">Needs attention (any)</option>';
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
  (function () {
    var prev = document.getElementById('dev-page-prev');
    var next = document.getElementById('dev-page-next');
    if (prev) prev.addEventListener('click', function () {
      devOffset = Math.max(0, devOffset - DEV_PAGE_SIZE);
      refreshDevices();
    });
    if (next) next.addEventListener('click', function () {
      devOffset += DEV_PAGE_SIZE;
      refreshDevices();
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
      '\n\nAdoption creates an ownership record for a device IRIS did not onboard, ' +
      'so undeploy may later remove resources IRIS did not create. Only adopt ' +
      'devices whose inventory matches what is really on the box; re-onboarding ' +
      '(idempotent) is the safer option. Router deployments cannot be adopted.' +
      '\n\nProceed with adopt?')) { setBulkBusy(false); return; }
    await forSelected('Adopted', ids, function (id) {
      return jpost('/api/devices/' + encodeURIComponent(id) + '/adopt',
                   { acknowledge_adopt: true });
    });
  });
  // Selection is id-keyed and outlives paging/filtering (issue #112), so a
  // selected device is very often NOT in LAST_DEVICES, which holds only the
  // currently rendered page. Issue #121: the picker used to fall back to []
  // for any such device, feeding a fabricated "assigned: []" into both the
  // pre-check preview and the expect_image_ids compare-and-set below -- the
  // server correctly refused (409) the resulting write, but for the wrong
  // reason, and every off-page device in the selection spuriously conflicted.
  //
  // There is no "fetch by id list" route (only q=, a substring search), so
  // this walks /api/devices at the server's own page cap
  // (gui_server.MAX_PAGE_LIMIT), matching by device_id, and stops the moment
  // every id missing from LAST_DEVICES has been found. Unfiltered, since
  // SELECTED persists across filter changes and a selected device may no
  // longer match whatever the filter bar shows now. For the common case --
  // the whole selection already on the rendered page -- this makes no
  // request at all. Returns a device_id -> row map; an id that still cannot
  // be found (deleted since being selected, or the walk failed) is simply
  // absent from it, same as it always was for a genuinely unknown device.
  async function fetchDeviceRows(ids) {
    var byId = Object.create(null);
    LAST_DEVICES.forEach(function (d) { byId[d.device_id] = d; });
    var missing = ids.filter(function (id) { return !byId[id]; });
    if (!missing.length) return byId;
    var need = Object.create(null);
    missing.forEach(function (id) { need[id] = true; });
    var remaining = missing.length;
    var batch = 1000, offset = 0, total = null;
    while (remaining > 0 && (total === null || offset < total)) {
      var qs = 'limit=' + batch + '&offset=' + offset;
      var r;
      try { r = await fetch('/api/devices?' + qs); } catch (e) { break; }
      if (!r.ok) break;
      var body = await r.json();
      total = typeof body.total === 'number' ? body.total : 0;
      var got = body.devices || [];
      got.forEach(function (d) {
        if (need[d.device_id]) { byId[d.device_id] = d; delete need[d.device_id]; remaining--; }
      });
      if (!got.length) break;   // never spin forever on an unexpected reply
      offset += got.length;
    }
    return byId;
  }
  document.getElementById('assign-images-selected').addEventListener('click', async function () {
    var ids = selectedIds();
    if (!ids.length) { devStatus.textContent = 'No devices selected.'; return; }
    if (!imageListOk) {
      devStatus.textContent = 'Image list unavailable; not opening the picker. ' +
        'Retry once the Images list loads.';
      return;
    }
    this.disabled = true;
    var byId;
    try { byId = await fetchDeviceRows(ids); } finally { this.disabled = false; }
    // Pre-check the INTERSECTION of the selection's current sets: pre-
    // checking the UNION would silently ADD an image to a device that does
    // not have it the moment ANY other selected device does; pre-checking
    // just one device's set would silently DROP an image from the rest on
    // Apply. The intersection is the only starting point Apply cannot
    // change anyone's assignment by surprise from.
    // Off-page ids resolve via fetchDeviceRows (issue #121), not [].
    var sets = ids.map(function (id) { return rowAssignedIds(byId[id] || {}); });
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
    var raw = document.getElementById('cred-selected').value;
    var msg = document.getElementById('cred-modal-msg');
    if (!raw) {
      // untouched picker: nothing is applied, the modal stays open
      if (msg) msg.textContent = 'Choose a credential profile, or "no credential" to clear.';
      return;
    }
    var pid = raw === CRED_CLEAR ? '' : raw;
    // The confirm text and the action it confirms must count the SAME set --
    // selectedIds() (SELECTED), not the checked rows in the DOM, which under
    // paging can be only a fraction of the real selection the claim below
    // actually fires against (issue #112 prerequisite 2).
    var count = selectedIds().length;
    if (!pid && !confirm('Clear the credential on ' + count + ' selected device(s)?\n\n' +
        'Onboard and undeploy are refused for a device without a credential ' +
        'until one is assigned again. Profiles themselves are not deleted.')) return;
    var ids = claimSelection();
    if (!ids) return;
    closeModal('cred-modal');
    // issue #125: one request for the whole selection (ids can run into the
    // thousands via "Select all N matching devices"), not one per device --
    // see bulkApply and gui_server.py's /api/devices/bulk-credential.
    await bulkApply(pid ? 'Assigned ' + pid + ' to' : 'Cleared credential on', ids,
      function (allIds) {
        return jpost('/api/devices/bulk-credential',
                     { device_ids: allIds, credential_profile_id: pid });
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
    var managementType = document.getElementById('df-management-type').value;
    var router = managementType === 'router-routed' || managementType === 'router-nat';
    // xr-host runs the appmgr container on the router's own network stack:
    // no VLAN, SVI, VPG, NAT interface, or app IP/mask/gateway. Those last
    // three used to be visible for every management type -- the core bug this
    // hides.
    var xrHost = managementType === 'xr-host';
    document.getElementById('df-vlan').hidden = router || xrHost;
    document.getElementById('df-svi').hidden = managementType !== 'routed';
    document.getElementById('df-vpg').hidden = !router;
    document.getElementById('df-nat-interface').hidden = managementType !== 'router-nat';
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
    var mgmtTypeSel = document.getElementById('df-management-type');
    if (mgmtTypeSel.value === 'xr-host') return;
    mgmtTypeSel.value = 'xr-host';
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
  var FULL_INSTALL_OPTIONS_HTML = '<option value="" disabled selected>Choose an agent install</option>' +
    AUTO_INSTALL_OPTIONS.map(function (k) {
      return '<option value="' + esc(k) + '">' + esc(INSTALL_OPTION_LABELS[k]) + '</option>';
    }).join('');
  var installOptionsGen = 0;
  async function refreshInstallOptions() {
    var model = document.getElementById('df-model').value.trim();
    var platform = document.getElementById('df-platform');
    var mgmtTypeSel = document.getElementById('df-management-type');
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
      if (mgmtTypeSel.value === 'xr-host') {
        mgmtTypeSel.value = '';
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
      platform.innerHTML = '<option value="" disabled selected>Choose an agent install</option>' +
        options.map(function (o) {
          return '<option value="' + esc(o) + '">' + esc(INSTALL_OPTION_LABELS[o] || o) + '</option>';
        }).join('');
      if (options.indexOf(kept) !== -1) platform.value = kept;
      // Drive the management type auto-select off the server answer instead of
      // re-implementing the model regex here.
      if (options.length === 1 && options[0] === 'xr-appmgr') {
        if (mgmtTypeSel.value !== 'xr-host') {
          mgmtTypeSel.value = 'xr-host';
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
    sel.innerHTML = credListOk
      ? '<option value="">— no credential —</option>' +
        credOpts.map(function (c) { return '<option value="' + esc(c.id) + '">' + esc(c.id) + '</option>'; }).join('')
      : '<option value="">— credential list unavailable; assign later —</option>';
    devForm.hidden = !devForm.hidden;
    if (!devForm.hidden) { updateDeviceFields(); refreshInstallOptions(); }
  });
  document.getElementById('df-cancel').addEventListener('click', function () { devForm.hidden = true; });
  devForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    var did = document.getElementById('df-id').value.trim();
    var derr = document.getElementById('df-err'); derr.textContent = '';
    if (!did) { derr.textContent = 'Device ID is required.'; return; }
    // No automatic answer: the agent install is always chosen explicitly.
    // Letting this through blank handed the decision to a model guess, which
    // is how an IOS-XR router was sent down an install its hardware cannot run.
    var platformSel = document.getElementById('df-platform');
    if (!platformSel.value) {
      derr.textContent = platformSel.disabled
        ? 'No agent install is available for this model.'
        : 'Choose an agent install for this device.';
      return;
    }
    var managementType = document.getElementById('df-management-type').value;
    var vlan = document.getElementById('df-vlan').value.trim();
    var mask = document.getElementById('df-mask').value.trim();
    var body = {
      device_id: did,
      device_ip: document.getElementById('df-ip').value.trim() || did,
      management_type: managementType,
      model: document.getElementById('df-model').value.trim(),
      platform: document.getElementById('df-platform').value,
      credential_profile_id: document.getElementById('df-cred').value
    };
    if (managementType === 'xr-host') {
      // XR host networking -- the agent shares the router's own network
      // stack, so no app-network fields belong on this wire body.
    } else if (managementType === 'inband') {
      body.app_ip = document.getElementById('df-guest').value.trim();
      body.app_mask = mask;
      body.app_gateway = document.getElementById('df-gateway').value.trim();
      body.inband_vlan = vlan;
    } else if (managementType === 'router-routed' || managementType === 'router-nat') {
      body.app_ip = document.getElementById('df-guest').value.trim();
      body.app_mask = mask;
      body.app_gateway = document.getElementById('df-gateway').value.trim();
      body.vpg_number = document.getElementById('df-vpg').value.trim();
      if (managementType === 'router-nat') {
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
          return '<tr data-id="' + esc(p.id) + '"><td class="machine"><b>' + esc(p.id) + '</b></td><td>' +
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

  // ---- Overview: "Needs attention" band (worst-of-group rollups) --------
  // Combined worst-of-group, per the Magnetic status-indicator guidance
  // ("COMBINED status = worst-of-group (Overview fleet rollups)"): reuses
  // the SAME deviceStatus()/statusDisplay() derivation the Devices table
  // already renders from, and the SAME quarantine flag the Images catalog
  // and image picker already read -- nothing new is computed here, only
  // tallied. Offline (Inactive, a freshness modifier per spec) is
  // deliberately not counted -- this band is real negative/severe/warning
  // problems, not staleness.
  var ATTENTION_LEVEL_RANK = { negative: 3, severe: 2, warning: 1 };
  function overviewDeviceAttention(devs, devNow) {
    var worst = null, count = 0;
    devs.forEach(function (d) {
      var st = deviceStatus(d, devNow);
      var ratio = st.key === 'image-failed' ? imageFailedRatio(d) : undefined;
      var lvl = statusDisplay(st, ratio).level;
      if (!ATTENTION_LEVEL_RANK[lvl]) return;
      count++;
      if (!worst || ATTENTION_LEVEL_RANK[lvl] > ATTENTION_LEVEL_RANK[worst]) worst = lvl;
    });
    return { count: count, level: worst };
  }
  function overviewImageAttention(imgs) {
    var count = imgs.filter(function (i) { return !!i.quarantined; }).length;
    return { count: count, level: count ? 'negative' : null };
  }
  function attentionCardHTML(kind, level, count, label, hint) {
    var icon = STATUS_ICONS[level] || STATUS_ICONS.inactive;
    // level/kind are both closed sets (ATTENTION_LEVEL_RANK's values,
    // 'devices'/'images') -- esc() here is belt-and-suspenders consistency
    // with every other interpolation, not a guard against untrusted input.
    return '<button type="button" class="attention-card is-' + esc(level) + '" data-attn="' + esc(kind) + '">' +
      '<svg aria-hidden="true"><use href="#' + icon + '"></use></svg>' +
      '<span class="attention-text"><span class="attention-count">' + esc(count) +
      '</span><span class="attention-label">' + esc(label) + '</span>' +
      '<span class="attention-hint">' + esc(hint) + '</span></span></button>';
  }
  function renderOverviewAttention(devs, devNow, imgs, fleetDataUnavailable) {
    var devAttn = overviewDeviceAttention(devs, devNow);
    var imgAttn = overviewImageAttention(imgs);
    var cards = [];
    if (devAttn.count) {
      cards.push(attentionCardHTML('devices', devAttn.level, devAttn.count,
        devAttn.count === 1 ? 'device needs attention' : 'devices need attention',
        'View filtered devices'));
    }
    if (imgAttn.count) {
      cards.push(attentionCardHTML('images', imgAttn.level, imgAttn.count,
        imgAttn.count === 1 ? 'image quarantined' : 'images quarantined',
        'View filtered images'));
    }
    // "No data to report a problem from" and "confirmed no problem" are
    // different claims -- rendering the same green all-clear card either
    // way would silently lie about which one happened. A real attention
    // card from whichever fetch DID succeed (above) still renders
    // alongside this: only the OTHER half degrades.
    if (fleetDataUnavailable) {
      cards.push('<div class="attention-card is-inactive">' +
        '<svg aria-hidden="true"><use href="#i-minus-circle"></use></svg>' +
        '<span class="attention-text"><span class="attention-label">Fleet status unavailable</span>' +
        '<span class="attention-hint">Device or image data could not be loaded; retrying.</span></span></div>');
    } else if (!cards.length) {
      cards.push('<div class="attention-card is-positive">' +
        '<svg aria-hidden="true"><use href="#i-check-circle"></use></svg>' +
        '<span class="attention-text"><span class="attention-label">All clear</span>' +
        '<span class="attention-hint">No devices or images need attention.</span></span></div>');
    }
    document.getElementById('ov-attention').innerHTML = cards.join('');
    var devBtn = document.querySelector('#ov-attention [data-attn="devices"]');
    if (devBtn) devBtn.addEventListener('click', function () { goToDevicesFiltered('__attention'); });
    var imgBtn = document.querySelector('#ov-attention [data-attn="images"]');
    if (imgBtn) imgBtn.addEventListener('click', goToImagesFiltered);
  }

  // ---- Overview ----
  // Same stale-response hazard refreshDevices() already guards against
  // (generation counter + AbortController, above): once the hash router
  // owns ALL visible-view polling (Task 10), an overlapping refreshOverview()
  // call -- a visibilitychange-triggered immediate refresh racing the
  // interval tick, or a rapid nav-away-and-back -- is a real possibility, so
  // a superseded call must not clobber a newer one's render.
  var overviewRefreshGeneration = 0, overviewRefreshController = null;
  async function refreshOverview() {
    var mine = ++overviewRefreshGeneration;
    if (overviewRefreshController) overviewRefreshController.abort();
    overviewRefreshController = new AbortController();
    var signal = overviewRefreshController.signal;
    // Telemetry export health is dashboard state, so it rides the Overview
    // refresh. Deliberately not awaited with the overview fetch: a slow or
    // unreachable collector must not delay the cards.
    refreshTelemetryHealth();
    // /api/overview is the PRIMARY fetch -- Fleet Totals and Rollout need
    // nothing else, so its own failure is still a hard bail (matches the
    // pre-existing behavior: no data, nothing to render).
    var or_;
    try {
      or_ = await fetch('/api/overview', { signal: signal });
    } catch (e) {
      // Superseding a refresh is expected (a newer refreshOverview() call
      // already owns the render) and must not be treated as a real
      // failure; any other failure keeps the pre-existing hard bail: no
      // data, nothing to render.
      if (e && e.name === 'AbortError') return;
      return;
    }
    if (!or_.ok || mine !== overviewRefreshGeneration) return;
    var ov = await or_.json();
    if (mine !== overviewRefreshGeneration) return;

    // /api/devices and /api/images are SECONDARY -- only the attention band
    // and the aggregate boundary need them (Overview reads the same two
    // existing endpoints Devices/Images already fetch; nothing server-side
    // is new). Each gets its OWN .catch(), so a network-level rejection on
    // either one resolves to an empty fallback instead of rejecting the
    // Promise.all below -- a coupled try/catch around all three fetches
    // would have let one flaky secondary request kill Fleet Totals and
    // Rollout too, which never needed it. Both still fire concurrently.
    // failed:true marks BOTH degraded shapes -- a network-level rejection
    // (.catch) and a resolved-but-non-2xx response (the r.ok ? ... : ...
    // branch) -- so the renderer can tell "no data to report a problem
    // from" apart from "confirmed no problem", which look identical if all
    // you have is an empty array. (A superseded/aborted secondary fetch
    // also resolves to this same failed:true fallback, but that is never
    // rendered either -- the generation check right below discards it.)
    var devsPromise = fetch('/api/devices', { signal: signal }).then(function (r) {
      return r.ok ? r.json() : { devices: [], now: null, failed: true };
    }).catch(function () { return { devices: [], now: null, failed: true }; });
    var imgsPromise = fetch('/api/images', { signal: signal }).then(function (r) {
      return r.ok ? r.json() : { images: [], failed: true };
    }).catch(function () { return { images: [], failed: true }; });
    var results = await Promise.all([devsPromise, imgsPromise]);
    if (mine !== overviewRefreshGeneration) return;
    var dbody = results[0];
    var devs = dbody.devices || [];
    var devNow = dbody.now || Date.now() / 1000;
    var imgsBody = results[1];
    var imgs = imgsBody.images || [];
    var fleetDataUnavailable = !!(dbody.failed || imgsBody.failed);

    renderOverviewAttention(devs, devNow, imgs, fleetDataUnavailable);

    var devicesWord = ov.devices === 1 ? 'device' : 'devices';
    var cards = [
      { lbl: 'Images', num: ov.images },
      { lbl: 'Devices', num: ov.devices },
      { lbl: 'Assigned', num: ov.assigned, sub: 'of ' + ov.devices + ' ' + devicesWord },
      { lbl: 'Staged', num: ov.staged, sub: 'of ' + ov.assigned + ' assigned' },
      { lbl: 'Staging now', num: ov.staging_now, sub: 'of ' + ov.assigned + ' assigned' },
      { lbl: 'Waiting for heartbeat', num: ov.awaiting_heartbeat || 0, sub: 'of ' + ov.devices + ' ' + devicesWord }
    ];
    document.getElementById('ov-cards').innerHTML = cards.map(function (c) {
      return '<div class="card"><div class="lbl">' + esc(c.lbl) +
        '</div><div class="num">' + esc(c.num) + '</div>' +
        (c.sub ? '<div class="sub">' + esc(c.sub) + '</div>' : '') + '</div>';
    }).join('');
    document.getElementById('ov-rows').innerHTML = (ov.rollout || []).map(function (x) {
      var pct = x.assigned ? Math.round(x.staged / x.assigned * 100) : 0;
      return '<tr><td class="machine">' + esc(x.image_id) + '</td><td>' + esc(x.assigned) + '</td><td>' +
        esc(x.staged) + '</td><td><div class="pbar" role="progressbar" aria-valuemin="0" ' +
        'aria-valuemax="100" aria-valuenow="' + pct + '" aria-label="' + esc(x.image_id) +
        ' staged"><span data-pct="' + pct +
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
  // Chips render through the real Magnetic status-pill system (levelPillHTML)
  // rather than the ad-hoc badge-* palette this used before Task 9 --
  // "everything should match Magnetic" applies to the Setup pane's pills too.
  // The level is state-driven by default (SETUP_CHIP_LEVELS); a caller may
  // override it (setupItemChipHTML below) for items that are recommended
  // rather than required, which the state alone cannot express.
  var SETUP_CHIP_LEVELS = {
    ok: 'positive',
    unset: 'warning', stale: 'warning',
    configured_unrun: 'warning',
    // "cannot determine" is an honest unknown, not a claimed problem -- it
    // reads closer to Magnetic's Inactive ("unknown ... indefinite holds")
    // than to a Warning this module has no evidence to justify.
    //
    // 'absent' (fix wave, reviewer Critical): a package for an architecture
    // this deployment does not use -- console.md's own words, "needs no
    // action" -- not a gap the operator failed to fill. The server ranks
    // absent above ok in packages.state's worst-of roll-up
    // (setup_status._RANK), so any single-architecture deployment (the
    // common case: one of iris-amd64.tar/iris-arm64.tar never gets built on
    // purpose) rolled up to 'absent' and painted a PERSISTENT false amber
    // Warning here, in both Settings > Setup and wizard step 3, with
    // nothing an operator could do to clear it. Not-applicable, same as
    // 'unknown'.
    unknown: 'inactive', absent: 'inactive'
  };
  var SETUP_CHIP_LABELS = {
    ok: 'Done', unset: 'Not configured', stale: 'Needs rebuild',
    absent: 'Not built', unknown: 'Cannot determine',
    // M37 fold-in (carried from the KGV close-out): distinct wording for "a
    // schedule exists but has not yet produced a successful run", never
    // conflated with "never configured at all".
    configured_unrun: 'Configured — no successful run yet'
  };
  function setupChip(state, levelOverride) {
    var level = levelOverride || SETUP_CHIP_LEVELS[state] || 'inactive';
    var label = SETUP_CHIP_LABELS[state] || state;
    return levelPillHTML(level, label);
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
    // The rebuild remedy is per stale ITEM, never a single card-wide
    // command -- the IOx tars and the IOS-XR RPM (iris-xr.rpm, Wave C) are
    // rebuilt by two DIFFERENT scripts, so a cert rotation that stales both
    // families needs BOTH commands named, not just whichever one
    // pkg.remedy used to hardcode. Never fires for a served-vs-distributed
    // mismatch, where rebuilding would not fix anything regardless of
    // which item looks stale.
    if (pkg.reason !== 'served-vs-distributed-mismatch') {
      var remedies = [];
      (pkg.items || []).forEach(function (i) {
        if (i.state === 'stale' && i.remedy && remedies.indexOf(i.remedy) === -1) {
          remedies.push(i.remedy);
        }
      });
      if (remedies.length) {
        parts.push('Rebuild on the Docker host, then re-onboard affected devices: '
          + remedies.join('; '));
      }
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
    document.getElementById('setup-pkg-chip').innerHTML = setupChip('unknown');
    document.querySelector('#setup-pkg-table tbody').innerHTML = '';
    document.getElementById('setup-pkg-remedy').textContent = '';
    document.getElementById('setup-iv-chip').innerHTML = setupChip('unknown');
  }

  // Items that are recommended rather than required to finish onboarding a
  // server: IRIS runs without a telemetry destination or image verification,
  // it just cannot prove either is happening. This is a per-ITEM judgment
  // call the setup-status payload does not itself encode (it only ever
  // reports each card's own ok/unset), so it lives here rather than in the
  // API -- widening that response is out of scope for this task.
  var SETUP_ITEM_OPTIONAL = { telemetry: true, image_verification: true };

  // M37 fold-in (carried from the KGV close-out): setup_status.py's
  // image_verification card reports ok only once a run has actually
  // SUCCEEDED (see its docstring) -- a scheduled-but-never-run config and a
  // truly unconfigured one both resolve to "unset" from that field alone.
  // The schedule's own mode -- the same data Settings > Image verification
  // already reads via /api/settings/image-verification -- is what tells
  // them apart. A failed/thrown fetch here must never invent "configured"
  // without evidence, so it resolves to null (treated as "don't know",
  // never as configured).
  // Fix wave (reviewer Minor): the wizard's own showWizardStep needs this
  // same payload again the instant it lands on step 4 (to populate #iv-mode/
  // #iv-hour/#iv-last-run) -- entering the wizard and clicking Next both call
  // this via refreshSetupWizard immediately before showing the resulting
  // step, so without this cache that step 4 landing fetched the identical
  // endpoint twice in a row. wizardIvStatus is consumed (read, then cleared)
  // only by that one call site, landing on step 4 straight out of
  // refreshSetupWizard -- Back and a direct steplist click both call
  // showWizardStep directly, with no refresh first, so neither one clears
  // or renews this cache. Landing on step 4 that way renders whatever this
  // variable last held, however old: fresh if refreshSetupWizard only just
  // set it, stale if the operator lingered on another step or edited image
  // verification via Settings in between. The setup view is not polled, so
  // nothing else invalidates the cache in the meantime.
  var wizardIvStatus = null;
  async function fetchIvScheduleConfigured() {
    try {
      var r = await fetch('/api/settings/image-verification');
      if (!r.ok) { wizardIvStatus = null; return null; }
      var iv = await r.json();
      wizardIvStatus = iv;
      return (iv.mode || 'off') !== 'off';
    } catch (e) {
      wizardIvStatus = null;
      return null;
    }
  }

  // One place that combines: the state a card reports, the M37 distinction
  // (image_verification only), and the required-vs-recommended pill level --
  // shared verbatim by the Settings > Setup status pane and the wizard's own
  // step list/chips, so the two surfaces can never disagree about how a step
  // reads (spec: "Step titles carry status indicators, reuse pill levels").
  function setupItemChipHTML(key, state, ivScheduleConfigured) {
    var effectiveState = state;
    if (key === 'image_verification' && state !== 'ok' && ivScheduleConfigured) {
      effectiveState = 'configured_unrun';
    }
    var override;
    if (effectiveState !== 'ok' && effectiveState !== 'configured_unrun' &&
        SETUP_ITEM_OPTIONAL[key]) {
      override = 'info';
    }
    return setupChip(effectiveState, override);
  }

  // ---- First-run setup wizard -------------------------------------------
  // A flow, not a checklist: the operator finishes setup here instead of being
  // sent back and forth to Settings pages. The telemetry step mounts the SAME
  // template Settings uses, so there is one implementation of that form.
  //
  // Every step is skippable and the wizard resumes at the first incomplete one.
  // That is forced, not a convenience: the packages step can never complete
  // in-console (the container has no Docker socket), so a wizard that insisted
  // on completion could never be finished.
  //
  // Step 3, Image verification (Task 9, USER DIRECTIVE): supersedes the
  // earlier decision that this card stays outside the wizard -- it now
  // mounts the SAME Settings > Image verification controls (schedule,
  // Refresh now, offline import) via mountImageVerification, the same
  // one-implementation precedent as the telemetry form mount.
  var WIZARD_STEPS = [
    { id: 'telemetry', pane: 'wz-step-telemetry', key: 'telemetry',  chip: 'wz-td-chip',  label: 'Telemetry destination' },
    { id: 'packages',  pane: 'wz-step-packages',  key: 'packages',   chip: 'wz-pkg-chip', label: 'Device packages' },
    { id: 'imageverification', pane: 'wz-step-imageverification', key: 'image_verification',
      chip: 'wz-iv-chip', label: 'Image verification' }
  ];
  var wizardStep = 0;
  var wizardStatus = null;
  // M37 fold-in for the wizard's own step list/chip -- fetched alongside
  // wizardStatus in refreshSetupWizard, same shared helper the Settings >
  // Setup status pane uses.
  var wizardIvConfigured = null;

  function wizardFirstIncompleteStep(status) {
    if (!status) return 0;
    for (var i = 0; i < WIZARD_STEPS.length; i++) {
      var item = status[WIZARD_STEPS[i].key] || {};
      // An optional step (the server says required: false, or the client
      // knows it is recommended-only) never counts as outstanding.
      if (item.required === false || SETUP_ITEM_OPTIONAL[WIZARD_STEPS[i].key]) continue;
      if (item.state !== 'ok') return i;
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
      var isCurrent = n === wizardStep;
      // Marker anatomy (captured Magnetic Stepper): completed = blue-outline
      // check, current = blue filled with the step number, upcoming = plain
      // number -- current always wins the marker even on an already-'ok'
      // step, since the operator is standing on it right now.
      var isDone = !isCurrent && state === 'ok';
      var markerCls = isCurrent ? 'is-current' : (isDone ? 'is-done' : 'is-upcoming');
      var marker = isDone
        ? '<svg aria-hidden="true"><use href="#i-check"></use></svg>'
        : String(n + 1);
      var pill = wizardStatus
        ? setupItemChipHTML(st.key, state, st.id === 'imageverification' ? wizardIvConfigured : null)
        : setupChip('unknown');
      return '<button type="button" role="listitem" class="wz-steplist-item' +
        (isCurrent ? ' current' : '') + '" data-step="' + n + '">' +
        '<span class="wz-steplist-n ' + markerCls + '">' + marker + '</span>' +
        '<span class="wz-steplist-label">' + esc(st.label) + '</span>' +
        pill + '</button>';
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
    } else if (WIZARD_STEPS[wizardStep].id === 'imageverification') {
      // Moved, not cloned (see mountImageVerification) -- Settings reclaims
      // the same live nodes back on its own way in.
      mountImageVerification('wz-iv-mount');
      if (wizardIvStatus) {
        // fetchIvScheduleConfigured (called via refreshSetupWizard, just
        // before this) already fetched this exact payload -- reuse it
        // instead of a second GET. See wizardIvStatus's own comment.
        renderIvStatusFields(wizardIvStatus);
        wizardIvStatus = null;
      } else {
        refreshImageVerificationSettings();
      }
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
      // i.detail (iris-xr.rpm, Wave C): this module cannot pin the RPM's
      // baked certificate the way it pins the IOx tars' (see
      // setup_status._xr_package_item), so its row says plainly what was
      // and was not verified rather than showing a bare ok/stale chip that
      // would look like the same guarantee. Empty for the tar rows, which
      // need no such caveat.
      return '<tr><td class="machine">' + esc(i.name || '') + '</td><td>' +
        setupChip(i.state) + '</td><td class="muted">built ' +
        esc(i.built_at || 'unknown') + '</td><td class="muted">' +
        esc(i.detail || '') + '</td></tr>';
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
    wizardIvConfigured = await fetchIvScheduleConfigured();
    function chip(id, state) {
      var el = document.getElementById(id);
      if (el) el.innerHTML = setupChip(state);
    }
    chip('wz-admin-chip', s ? (s.admin || {}).state : 'unknown');
    WIZARD_STEPS.forEach(function (st) {
      var el = document.getElementById(st.chip);
      if (!el) return;
      var state = s ? (s[st.key] || {}).state : 'unknown';
      el.innerHTML = s
        ? setupItemChipHTML(st.key, state, st.id === 'imageverification' ? wizardIvConfigured : null)
        : setupChip('unknown');
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
    var ivConfigured = await fetchIvScheduleConfigured();
    document.getElementById('setup-admin-chip').innerHTML =
      setupChip(s.admin.state);
    document.getElementById('setup-td-chip').innerHTML =
      setupItemChipHTML('telemetry', s.telemetry.state, null);
    document.getElementById('setup-td-note').textContent =
      setupTelemetryNote(s.telemetry);
    document.getElementById('setup-pkg-chip').innerHTML =
      setupChip(s.packages.state);
    document.querySelector('#setup-pkg-table tbody').innerHTML =
      s.packages.items.map(function (i) {
        var when = i.built_at
          ? new Date(i.built_at * 1000).toLocaleString() : '—';
        // i.detail: see the matching comment in renderWizardPackages.
        return '<tr><td class="muted machine">' + esc(i.name) + '</td><td>' +
               setupChip(i.state) + '</td><td class="muted">built ' +
               esc(when) + '</td><td class="muted">' + esc(i.detail || '') +
               '</td></tr>';
      }).join('');
    document.getElementById('setup-pkg-remedy').textContent =
      setupPkgRemedyText(s.packages);
    document.getElementById('setup-iv-chip').innerHTML =
      setupItemChipHTML('image_verification', s.image_verification.state, ivConfigured);
  }

  async function refreshSettings() {
    var r = await fetch('/api/settings'); if (!r.ok) return;
    var s = await r.json();
    var rows = [
      ['Version', s.version],
      ['Admin', s.admin_username],
      ['Host IP', s.host_ip || '(unset)', 'machine'],
      ['Ports', 'tracker ' + s.ports.tracker + ' · catalog ' + s.ports.catalog +
                ' · artifacts ' + s.ports.artifacts + ' · swarm ' + s.ports.swarm +
                ' · console ' + s.ports.console]
    ];
    document.querySelector('#settings-info tbody').innerHTML = rows.map(function (kv) {
      return '<tr><td class="muted">' + esc(kv[0]) + '</td><td' +
        (kv[2] ? ' class="' + kv[2] + '"' : '') + '>' + esc(kv[1]) + '</td></tr>';
    }).join('');
    document.getElementById('sessions-info').textContent =
      s.sessions.active + ' active session(s); idle timeout ' +
      s.sessions.idle_ttl_minutes + ' min.';
    // --- Certificate (metadata only — key material never reaches this page) ---
    var gc = s.gui_cert || {};
    var certStatus = document.getElementById('cert-status');
    if (gc.source === 'custom' || gc.source === 'built-in') {
      certStatus.innerHTML = (gc.source === 'custom'
          ? '<span class="badge badge-running">custom</span> '
          : '<span class="badge badge-queued">built-in</span> ') +
        esc(gc.subject || 'unknown') +
        ' — expires ' + esc(gc.not_after || 'unknown') +
        ' — sha256 <span class="machine">' + esc((gc.fingerprint_sha256 || '').slice(0, 16)) + '…</span>' +
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
            '</td><td class="machine">' + esc(t.not_after || 'unknown') +
            '</td><td class="machine">' + esc((t.fingerprint_sha256 || '').slice(0, 16)) + '…</td><td>' +
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
  // Pure DOM write, factored out so a caller already holding a freshly
  // fetched payload (the wizard's own showWizardStep, fix wave below) can
  // populate these fields without a second, redundant GET to the same
  // endpoint refreshImageVerificationSettings already just made.
  function renderIvStatusFields(iv) {
    document.getElementById('iv-mode').value = iv.mode || 'off';
    document.getElementById('iv-hour').value = String(iv.hour_utc == null ? 0 : iv.hour_utc);
    document.getElementById('iv-last-run').innerHTML = fmtBulkhashLastRun(iv.last_run);
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
    renderIvStatusFields(iv);
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
    prog.hidden = false; bar.style.width = '0%'; prog.setAttribute('aria-valuenow', '0');
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/image-verification/offline');
    xhr.setRequestHeader('X-CSRF-Token', info.csrf);
    xhr.upload.onprogress = function (e) {
      if (!e.lengthComputable) return;
      var pct = e.loaded / e.total * 100;
      bar.style.width = pct + '%';
      prog.setAttribute('aria-valuenow', String(Math.round(pct)));
    };
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
  // The telemetry form lives in a <template> in the settings pane and is
  // cloned into whichever surface is showing -- Settings, or a step of the
  // first-run wizard. Cloning rather than duplicating the markup keeps a
  // single source of truth, and only ever ONE clone is mounted, so the ids
  // inside stay unique. Handlers bind per mount, which is why they live in
  // wire*Form() rather than running once at startup.
  var FORM_MOUNTS = {
    td: { tpl: 'tpl-td-form', wire: function () { wireTelemetryForm(); } }
  };
  var formMountedAt = { td: null };

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

  // The Image verification content (schedule form, Refresh now, offline
  // import) is relocated the same way -- Settings and the wizard's step 3
  // share one implementation -- but by MOVING the live nodes rather than
  // cloning a <template>: unlike wireTelemetryForm above, its handlers
  // (the schedule-form submit listener, the iv-refresh click
  // handler, wireDropzone on the offline dropzone, the once-only hour-select
  // IIFE) are bound ONCE at load, not re-wired per mount. Moving the same
  // DOM node keeps every listener intact and needs no rewire step, and since
  // there is only ever the one instance, its ids can never duplicate.
  var ivMountedAt = 'settings-pane-bulkhash';
  function mountImageVerification(hostId) {
    if (ivMountedAt === hostId) return;
    var host = document.getElementById(hostId);
    var content = document.getElementById('iv-content');
    if (!host || !content) return;
    host.appendChild(content);
    ivMountedAt = hostId;
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
    var certRes = await r.json().catch(function () { return {}; });
    document.getElementById('cert-form').reset();   // never leave the key in the DOM
    msg.textContent = certRes.applied === false
      ? 'Certificate ' + (certRes.note || 'saved; takes effect at the next restart') + '.'
      : 'Certificate replaced. New connections use it now; reload to see it on this one.';
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
    // Claim the shared form back from the wizard, then repopulate it --
    // a freshly cloned form is empty until refreshSettings writes to it.
    if (sub === 'telemetry') mountSettingsForm('td', 'td-mount');
    // Same reclaim, but a move rather than a re-mount -- see
    // mountImageVerification's own comment for why.
    if (sub === 'bulkhash') mountImageVerification('settings-pane-bulkhash');
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
    updateMonitoringScopeTags();
  }
  // The active time scope, as a small tag next to each pane's own title --
  // read from the SAME range variables the histogram/table already use, so
  // the tag can never say something the data below it disagrees with.
  var MONITORING_RANGE_TAG_LABELS = {
    '24h': 'Last 24 h', '7d': 'Last 7 d', '30d': 'Last 30 d',
    '90d': 'Last 90 d', 'all': 'All time'
  };
  function updateMonitoringScopeTags() {
    var auditTag = document.getElementById('audit-scope-tag');
    if (auditTag) auditTag.textContent = MONITORING_RANGE_TAG_LABELS[auditRange] || auditRange;
    var dlTag = document.getElementById('dl-scope-tag');
    if (dlTag) dlTag.textContent = MONITORING_RANGE_TAG_LABELS[dlRange] || dlRange;
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
      return '<span class="machine" title="device">' + esc(actor.slice(7)) + '</span>';
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
    return '<tr><td class="nowrap machine" title="' + esc(fmtAgo(e.ts)) + '">' + esc(fmtDate(e.ts)) + '</td>' +
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
    auditExtraPages = append ? auditExtraPages + 1 : 0;
  }
  // Pages appended by "Load older" since the table was last rebuilt. While
  // any are on screen the periodic poll leaves the table alone (the deploy-
  // logs pane likewise keeps its page across a poll); a range/category/
  // brush change rebuilds it and resets the count.
  var auditExtraPages = 0;

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
    // a drag in progress owns the overlay; repainting the committed
    // selection under it would briefly undo the pending one
    if (!brushDrag) renderBrush(auditSel);
    renderWindowLabel();
  }

  async function refreshAuditTable(fromPoll) {
    if (fromPoll && auditExtraPages > 0) return;   // operator is reading older pages
    var r = await fetch(auditTableUrl());
    if (!r.ok) return;
    var events = (await r.json()).events || [];
    renderAuditRows(events, false);
  }

  async function refreshMonitoring(fromPoll) {
    await Promise.all([refreshHistogram(), refreshAuditTable(!!fromPoll),
                       refreshDeployLogsAll()]);
  }
  // The periodic refresh: only the visible sub-pane, and never the audit
  // table while "Load older" pages are on screen.
  function pollMonitoring() {
    var auditPane = document.getElementById('monitoring-pane-audit');
    if (auditPane && !auditPane.hidden) {
      return Promise.all([refreshHistogram(), refreshAuditTable(true)]);
    }
    return refreshDeployLogsAll();
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
      updateMonitoringScopeTags();
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
        return '<tr data-file="' + esc(l.file) + '"><td class="machine">' + esc(fmtDate(l.finished_at)) +
          '</td><td class="machine">' + esc(l.device_id || '') + '</td><td>' + esc(l.action || '') +
          '</td><td>' + deployLogResult(l) + '</td><td class="machine">' + esc(fmtSize(l.size)) + '</td>' +
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

  var dlDrawerOpener = null;
  function openDeployLogDrawer(file) {
    var drawer = document.getElementById('dl-drawer');
    dlDrawerOpener = document.activeElement;
    document.getElementById('dl-drawer-title').textContent = file;
    drawer.hidden = false;
    document.getElementById('dl-drawer-close').focus();
    showDeployLog(file, document.getElementById('dl-text'));
  }
  function closeDeployLogDrawer() {
    document.getElementById('dl-drawer').hidden = true;
    if (dlDrawerOpener) { dlDrawerOpener.focus(); dlDrawerOpener = null; }
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
  // No trapDialogFocus here (Task 6, fix wave): this drawer is non-modal --
  // no backdrop, the deployment-logs table behind stays fully interactive
  // while it is open -- so Tab must be free to leave it for the rest of the
  // page. Focus still moves in on open and is restored to the opener above.

  // OTLP export health badge (spec 8.3), via the console's session-gated
  // proxy — never the unauthenticated :9101 directly.
  async function refreshTelemetryHealth() {
    var el = document.getElementById('telemetry-health');
    if (!el) return;
    var state = 'unknown';
    el.title = '';
    try {
      var r = await fetch('/api/telemetry/health');
      if (!r.ok) throw new Error('health proxy ' + r.status);   // unknown, never "off"
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
      updateMonitoringScopeTags();
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

  // ---- off-canvas nav (mobile, <=768px; Task 6) ----
  // The nav rail slides in from the left below the 768px breakpoint (CSS);
  // this just flips the open state and keeps aria-expanded honest for
  // assistive tech. show() below closes it on every navigation, so picking
  // a page never leaves the rail covering the content it just opened.
  var navToggle = document.getElementById('nav-toggle');
  var navRail = document.querySelector('.nav-rail');
  function setNavOpen(open) {
    navRail.classList.toggle('open', !!open);
    navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
  navToggle.addEventListener('click', function () { setNavOpen(!navRail.classList.contains('open')); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && navRail.classList.contains('open')) setNavOpen(false);
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
      backgroundPoll = true;   // see the fetch wrapper: not operator activity
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
    // A navigation is exactly when the mobile off-canvas nav should close --
    // the operator picked a page, so the rail covering it has done its job.
    setNavOpen(false);
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
    // Wave D fix 2: the flyouts are now trigger-driven popovers (wireMenu,
    // above) rather than tied to the active route -- but navigating to a
    // DIFFERENT view still has to close one left open over a page it no
    // longer applies to. A click-driven navigation already closes it via
    // wireMenu's own outside-click handler; this covers the paths that
    // never dispatch a click on the page at all -- the browser back/
    // forward buttons, or a hashchange from code elsewhere in the app
    // (e.g. the Overview attention cards' router jump).
    if (view !== 'settings' && view !== 'monitoring') closeMenus();
    if (view === 'settings') showSettingsSub(sub || 'general');
    if (view === 'monitoring') showMonitoringSub(sub || 'audit');
    // Each view names the refresh the poll should repeat. Settings is
    // deliberately excluded: it is a set of forms, and re-rendering them
    // under the operator's cursor would discard half-typed input.
    var poll = null;
    if (view === 'overview') { refreshOverview(); poll = refreshOverview; }
    else if (view === 'images') {
      refreshImages(); refreshImportable();
      poll = function () { refreshImages(); refreshImportable(); };
    } else if (view === 'devices') { refreshDevices(); poll = pollDevices; }
    else if (view === 'swarm') { refreshSwarm(); poll = refreshSwarm; }
    else if (view === 'settings') { refreshSettings(); refreshSetup(); }
    else if (view === 'monitoring') { refreshMonitoring(); poll = pollMonitoring; }
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
